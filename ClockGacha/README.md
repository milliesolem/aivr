# ClockGacha — BEpusdt admin credentials & payment API token derived from `time.Now()`

| Field | Value |
| --- | --- |
| Product | [BEpusdt](https://github.com/v03413/bepusdt) — self-hosted USDT/USDT-TRC20 payment gateway (2,299★) |
| Version | `main` @ `78db081b3527c7c6a4763e853255dd9141b3bcae` (2026-11-01); `go 1.26` |
| CVSS 3.1 | **6.5 MEDIUM** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N` |
| CWE | CWE-338 (Use of Cryptographically Weak PRNG) / CWE-330 (Insufficiently Random Values) |
| Status | **0-day** — live at HEAD, no fix commit |
| Severity claim | medium |

## Summary

BEpusdt generates **every one of its initial administrative secrets** — the admin
login username, the admin login password, the "secure entry" URL path, and the
payment-integration API token — from a **single call to `time.Now().String()`**.
There is no `crypto/rand`, no `os.urandom`, no CSPRNG anywhere in the chain.

`time.Now().String()` yields `"2006-01-02 15:04:05.999999999 +0000 UTC m=+0.123456789"`:
a wall-clock timestamp with 9-digit nanosecond precision plus a monotonic offset.
That is the *entire* entropy source for credentials that gate the admin panel and
— critically — the payment-notification signature (`EpusdtSign`/`epay` sign), i.e.
the check that decides whether an incoming USDT payment is marked paid.

## Vulnerability details

### File: `app/model/conf.go` (lines 147–160) — `ConfInit()`, first-run credential bootstrap

```go
func ConfInit() {
	var hash = utils.StrSha256(utils.Md5String(time.Now().String())) // (1) only entropy = clock
	var secure = "/" + hash[:10]
	var token = strings.ToUpper(utils.Md5String(hash[18:28]))
	var username = hash[10:20]
	var password = hash[20:30]
	var encrypt, _ = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	...
		ApiAuthToken:  token,          // payment integration token
		AdminSecret:   utils.StrSha256(hash),
		AdminSecure:   secure,         // "/" + 10 hex chars  (40 bits)
		AdminUsername: username,       // 10 hex chars        (40 bits)
		AdminPassword: string(encrypt), // bcrypt of 10 hex   (40 bits)
}
```

### File: `app/cmd/reset.go` (line 34) — the "forgot password" reset path is worse

```go
hash := utils.Md5String(time.Now().String()) // (1) only entropy = clock
username := hash[8:16]
password := hash[0:8]        // 8 hex chars = 32 bits
entrance := fmt.Sprintf("/%s", hash[10:20])
```

### File: `app/handler/admin/conf.go` (line 181) — API token reset

```go
model.SetK(model.ApiAuthToken, strings.ToUpper(utils.Md5String(utils.StrSha256(time.Now().String()))))
```

### The boundary the token guards (payment money path)

```go
// app/handler/epusdt/epusdt.go:100  (also epay.go:65, order.go:219)
if utils.EpusdtSign(m, model.AuthToken()) != sign {
    ctx.String(200, "fail"); return   // rejects forged payment notifications
}
ctx.String(200, "ok")                  // else marks the order PAID
```

`EpusdtSign(data, token) = MD5(sorted("k=v&...") + token)`. An attacker who can
recover `AuthToken()` (a pure function of a timestamp) can sign arbitrary
payment confirmations for their own orders.

## Exploit chain

```
attacker learns / bounds the credential-generation time  (wall-clock second
        + nanosecond + monotonic offset)
            │
            ▼
   hash = SHA256( MD5( time.Now().String() ) )      ← deterministic, no CSPRNG
            │
            ├─ password  = hash[20:30]  (40 bits)  → admin panel login
            ├─ secure    = "/" + hash[:10]          → admin entry URL
            └─ token     = MD5(hash[18:28])         → EpusdtSign / epay sign
                                                        → forge "payment received"
```

## Fix

Replace `time.Now().String()` with `crypto/rand` (e.g. 32 random bytes hex-encoded)
and stop deriving four independent secrets from a single low-entropy value. The
PoC's `[4]` section shows that a `crypto/rand`-based derivation is *not* a function
of the clock and cannot be reconstructed by enumerating the nanosecond window.

## Exploitability assessment (honest)

| Criterion | Assessment |
| --- | --- |
| Entropy source | `time.Now().String()` only — nanosecond wall clock + monotonic offset |
| Effective entropy | ~50–60 bits for the full timestamp; **admin password = 40 bits (32 bits after `reset`)**; secure path = 40 bits |
| Precondition | Attacker must determine or brute-force the generation time to nanosecond precision (or, for the `reset` password, crack a bcrypt hash of a 32-bit value). Uncommon but bounded — far below the 128–256-bit CSPRNG bar. |
| Impact if reached | Forged payment confirmations (integrity) + admin panel takeover (confidentiality/control) |
| Severity | **medium** — real boundary violation (weak, time-derived credentials) with an uncommon precondition. A conservative CVSS of 6.5 is claimed; the high-impact consequences are gated behind the AC:H time-brute-force. |

The PoC is a **faithful port** of the two one-line hash helpers and the exact
`ConfInit`/`reset`/`ResetApiAuthToken` derivations (reproduced from the pinned
commit). It does **not** need a database or the Gin server: the vulnerable logic
is pure and is exercised directly.

## Run

```bash
bash run.sh     # requires go (Go 1.24 toolchain is available in the sandbox)
```

Expected output ends with:

```
RESULT: CONFIRMED — BEpusdt derives the admin password, secure entry and
        payment API token from time.Now().String() (CWE-338). ...
```

## Self-critique (3 ways this might not be a finding — and how each was checked)

1. **"The monotonic clock adds real entropy, so brute-force is infeasible."**
   Checked: `time.Now().String()` was run under Go 1.24 to confirm it emits
   `m=+0.000033161`. The monotonic offset is *process uptime*, which for the
   `reset` CLI command (a short-lived process) and first-run `ConfInit` is a
   small, bounded value — not attacker-unpredictable randomness. Regardless, the
   password itself is only 40 bits (32 after reset), an inherent weakness.
2. **"It's a self-hosted tool; the attacker must already have access."**
   Checked: the API token authenticates *incoming payment notifications* over the
   network (`epusdt.go:100`, `epay.go:65`) — an unauthenticated remote boundary
   that an attacker reaches by submitting forged callbacks.
3. **"bcrypt protects the stored password."**
   Checked: bcrypt only slows an offline crack of a *40-bit* value (or *32-bit*
   after reset); it does not protect the API token (`ApiAuthToken`), which is
   stored in the clear in `Conf` and used directly in the signature check.

## References

- Vulnerable code: <https://github.com/v03413/bepusdt/blob/78db081b3527c7c6a4763e853255dd9141b3bcae/app/model/conf.go#L147-L160>
- Reset path: <https://github.com/v03413/bepusdt/blob/78db081b3527c7c6a4763e853255dd9141b3bcae/app/cmd/reset.go#L33-L43>
- API token reset: <https://github.com/v03413/bepusdt/blob/78db081b3527c7c6a4763e853255dd9141b3bcae/app/handler/admin/conf.go#L180-L182>
- Signature check: <https://github.com/v03413/bepusdt/blob/78db081b3527c7c6a4763e853255dd9141b3bcae/app/handler/epusdt/epusdt.go#L100>
