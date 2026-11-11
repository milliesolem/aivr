# FrpMimic — frp OIDC missing audience (client ID) validation → authentication bypass

| | |
|---|---|
| **Product + version** | fatedier/frp v0.72.0 (HEAD `a2c975e`), `pkg/auth/oidc.go` |
| **CVSS** | 4.8 MEDIUM — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **CWE** | CWE-345 — Insufficient Verification of Data Authenticity (token/audience confusion) |

## Summary

frp is a fast reverse proxy (~110k stars) used to expose internal services. When its
server (`frps`) is configured to authenticate clients with **OIDC**, the token verifier
(`pkg/auth/oidc.go::NewTokenVerifier`) is built like this:

```go
verifierConf := oidc.Config{
    ClientID:          cfg.Audience,        // "" unless the admin sets it
    SkipClientIDCheck: cfg.Audience == "",  // true by default
    SkipExpiryCheck:   cfg.SkipExpiryCheck,
    SkipIssuerCheck:   cfg.SkipIssuerCheck,
}
return provider.Verifier(&verifierConf)
```

`Audience` is an **optional** config field. The code comment in
`pkg/config/v1/server.go` states: *"If this value is empty, audience ("client ID")
verification will be skipped."* That skip is implemented by setting the go-oidc
`SkipClientIDCheck` flag, which disables validation of the OIDC `aud` claim.

The `aud` claim is what binds an ID token to a specific relying party / resource. With it
unvalidated, **any** valid ID token issued by the configured issuer is accepted — including
one minted for an attacker's own OAuth client. frp also keeps no subject allowlist
(`VerifyLogin` just records `token.Subject`), so the attacker's identity is fully trusted
and they gain the same access as a legitimate frp client (i.e. they can register proxies on
the shared `frps` server).

## Exploit chain

1. Admin enables OIDC auth on `frps`, configuring `issuer` but (commonly) not `audience`.
2. Attacker obtains a valid ID token from that issuer for *their own* client/app. frp's OIDC
   path uses the **client-credentials grant**, so the realistic self-service case is a
   multi-tenant/self-service IdP (**Auth0-class** — register a free machine-to-machine app) or
   a tenant IdP (Keycloak / Entra ID) where the attacker can register a client. The token has
   `aud = <attacker's resource/client>`, `iss = <configured issuer>`.
3. Attacker presents that token to frp's login (`PrivilegeKey`).
4. `NewTokenVerifier` runs with `SkipClientIDCheck=true`, so `aud` is never checked; the
   signature and `iss` match, and the token is accepted.
5. `VerifyLogin` records the attacker's `sub`; subsequent work-connections use the same
   subject and succeed. Attacker now controls a frp client session → they can register
   proxies on the shared `frps`.

> Note on framing: in frp's client-credentials flow, `aud` is a *resource* identifier rather
> than strictly a "client ID". The audience check pins tokens to the intended resource; a
> complete fix additionally needs a subject/client allowlist, because the audience check alone
> does not restrict *which* clients at that issuer are permitted.

## Vulnerable vs fixed behaviour (demonstrated)

| config | legit token (`aud=legit-frp-client`) | attacker token (`aud=attacker-other-app`) |
|---|---|---|
| `audience` **unset** (frp default) | ACCEPT | **ACCEPT (bypass)** |
| `audience = legit-frp-client` (secure) | ACCEPT | REJECT (audience mismatch) |

## Run

```bash
bash run.sh
```

Requires Go (the build fetches go1.25 + `github.com/coreos/go-oidc/v3@v3.21.0`, the exact
library and version frp vendors). The PoC starts a local mock IdP, mints two RS256 ID
tokens differing only in `aud`, and runs frp's verbatim verifier config both ways.

## Threat model / honesty

- **Precondition 1:** `frps` must use OIDC auth (`auth.method = "oidc"`). frp's default is
  a shared token; OIDC is an opt-in method.
- **Precondition 2:** `audience` must be unset. It is optional and empty by default, and
  nothing warns the admin that omitting it silently disables the core OIDC guarantee.
- **Precondition 3:** the attacker must obtain a valid token from the same issuer. For
  self-service/multi-tenant IdPs (Auth0-class) this is trivial (self-service
  machine-to-machine client registration); for a locked-down private IdP the attacker
  needs some account/tenant presence.
- **This is NOT a memory-safety bug** — it is a logic/config weakness (CWE-345) in a
  prominent Go codebase, and it is the *default* behaviour of the OIDC auth path rather
  than an exotic edge case.
- **Why it is a finding, not "intended behaviour":** the code documents *what* happens
  (audience verification skipped) but not the *security consequence* (any client of the
  issuer is accepted). OIDC Core §3.1.3.7 and RFC 6749 require `aud` validation, and the
  go-oidc library itself warns `SkipClientIDCheck` should only be used when the client ID
  is unknown. Disabling it by default undermines the primary purpose of enabling OIDC.

## Self-critique (3 ways this trigger might not fire)

1. **OIDC not enabled / audience set.** If the admin uses token auth, or explicitly sets
   `audience`, the bypass does not apply. Checked: `Audience` is optional with no default
   and no validation; `SkipClientIDCheck` is `cfg.Audience == ""`.
2. **Private IdP with no attacker presence.** If the issuer issues tokens only to a fixed,
   well-guarded set of clients the attacker cannot reach, the attacker can't obtain a
   token. Checked: for self-service/multi-tenant IdPs this is not a barrier (self-service
   client registration).
3. **A subject allowlist might exist elsewhere.** Checked: `OidcAuthConsumer` keeps only
   `subjectsFromLogin` (a login→ping subject-consistency set), no allowlist of permitted
   subjects — any subject is accepted.

## References

- Vulnerable code: `pkg/auth/oidc.go:276-287` and `pkg/config/v1/server.go:143-156`
  (commit `a2c975efb5e55102068065d61cfc17ffe34e939d`, v0.72.0).
- Dependency: `github.com/coreos/go-oidc/v3 v3.21.0` (go.mod) — `SkipClientIDCheck`
  disables `aud` validation in `IDTokenVerifier.Verify`.
