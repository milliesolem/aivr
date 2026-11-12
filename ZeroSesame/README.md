# ZeroSesame — go-zero zrpc fail-open authentication bypass (0-day)

## Summary

**Product:** [go-zero](https://github.com/zeromicro/go-zero) (33k+ stars, Go)
**Component:** `zrpc` authentication (`zrpc/internal/auth/auth.go`)
**Class:** CWE-287/306 — authentication bypass ("fails open")
**Severity:** Critical — CVSS:3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8**
**Status:** 0-day — the fix (`f56630376b819f56d1f71247af05fdf0c7f9e0ce`, PR #5848,
2026-11-01) is unreleased; the latest release **v1.9.4** is still vulnerable.

## The bug

`zrpc` authenticates RPC requests by looking up the caller's `app` name in a Redis
hash to fetch the expected token, then comparing it to the supplied `token`:

```go
func (a *Authenticator) validate(app, token string) error {
    expect, err := a.cache.Take(app, func() (any, error) {
        return a.store.Hget(a.key, app)     // redis hash: app -> expected token
    })
    if err != nil {
        if a.strict {
            return status.Error(codes.Internal, err.Error())
        }
        return nil                          // <-- FAILS OPEN
    }
    if token != expect {
        return status.Error(codes.Unauthenticated, accessDenied)
    }
    return nil
}
```

`StrictControl` is a JSON `optional` bool, so it defaults to **false**. With
`strict=false`, *any* error from the Redis lookup is treated as success:

1. **Unknown app** — an unregistered `app` name makes `Hget` return `redis.Nil`,
   so `validate` returns `nil` → the caller is **authenticated**. The token is
   never even checked (that branch is only reached for a *registered* app).
2. **Redis outage** — any backend error (down, timeout, `ERR`, wrong type) also
   returns `nil` → **every** request authenticates while Redis is broken.

Because `UnaryAuthorizeInterceptor` / `StreamAuthorizeInterceptor` simply forward
the `Authenticate()` result to the gRPC handler, a `nil` from this path executes
the protected RPC. An unauthenticated attacker who can reach a zrpc endpoint
(with `Auth` enabled) simply sends `app=<anything-unregistered>, token=<anything>`
and is granted access.

The fix removes the fail-open entirely — any lookup error now returns
`codes.Unauthenticated` (fail closed), and `StrictControl` is deprecated.

## Exploit

`driver/main.go` compiles and drives the **real** go-zero v1.9.4
`internal/auth.Authenticator` against a faithful RESP Redis (miniredis — the same
backend go-zero's own auth tests use). It demonstrates four cases:

| case                    | result                          |
|-------------------------|---------------------------------|
| valid (registered) app  | GRANTED  (control)              |
| wrong token, known app  | DENIED   (`Unauthenticated`)    |
| **unknown app**         | **GRANTED — bypass**            |
| **Redis outage**        | **GRANTED — fail-open**         |

```
RESULT: AUTH BYPASS CONFIRMED — unknown app and Redis outage both
        authenticate an unauthenticated caller (fails open).
```

## Run

```bash
bash run.sh
```

`run.sh` provisions the go-zero v1.9.4 checkout (if absent), installs the driver
into the checkout (the `internal` package can only be imported from inside the
module tree), and runs `go run ./zrpc/poc` offline against a warmed module cache.
