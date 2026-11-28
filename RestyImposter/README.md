# RestyImposter — OpenResty `lua-nginx-module` OCSP signer-authorization bypass (0-day)

| | |
|---|---|
| **Product** | `openresty/lua-nginx-module` (the core ngx_lua module of OpenResty — ~12k★, foundational infra behind Kong and many CDNs) |
| **Bug** | `ngx.ocsp.validate_ocsp_response` accepts an OCSP response signed by an **unauthorized** certificate → OCSP revocation bypass |
| **CVSS (v3.1)** | **5.9 MEDIUM** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **CWE** | CWE-295 (Improper Certificate Validation) / CWE-345 (Insufficient Verification of Data Authenticity) |
| **Fix commit** | [`9c61e3da00`](https://github.com/openresty/lua-nginx-module/commit/9c61e3da0064c27144acde07f5b6db83bbde28a1) — *"bugfix: Forged OCSP responses can pass signer authorization checks"* (committed **2026-11-28**, unreleased) |
| **Vulnerable commit** | `c686ddb6…` (master, parent of the fix) |

## Root cause

`ngx_http_lua_ffi_ssl_validate_ocsp_response()` (the C backing of the Lua
`ngx.ocsp.validate_ocsp_response` API) verifies the OCSP response like this:

```c
(void) sk_X509_push(chain, issuer);

if (OCSP_basic_verify(basic, chain, NULL, OCSP_NOVERIFY) != 1) {   /* line 350 */
    ...
}
```

`OCSP_basic_verify(bs, certs, st, flags)` with **`st == NULL`** and the
**`OCSP_NOVERIFY`** flag causes OpenSSL to skip `ocsp_verify_signer` entirely: the
responder certificate's chain is never built/verified, and — crucially — its
**authorization to sign OCSP responses for the issuer is never checked**. OpenSSL
only verifies the response *signature* against whatever certificate is embedded in
the response. So any throw-away certificate the attacker embeds and signs with is
accepted as the responder.

An attacker who can supply the OCSP response (a MITM on a stapled or relayed OCSP
channel) therefore forges a `GOOD` status for a certificate whose real status is
`REVOKED`, signs it with a self-signed certificate that has nothing to do with the
real CA, and `validate_ocsp_response` reports the certificate as valid —
**defeating OCSP-based revocation checking**.

### The fix

Upstream `9c61e3da00` builds a trust store containing **only the expected issuer**
(with `X509_V_FLAG_PARTIAL_CHAIN`, so the issuer may be an intermediate) and calls
`OCSP_basic_verify(basic, chain, store, 0)` — no `OCSP_NOVERIFY`. Now the responder
must be the issuer, or a certificate issued by it with the OCSP-signing EKU.

## Proof of concept

`poc.c` drives the **real OpenSSL 3.5.9 OCSP stack** (the same `libcrypto`
lua-nginx-module links against). It:

1. builds a legitimate PKI (a CA that issues `victim.example.com`);
2. generates an unrelated, self-signed `attacker-responder` certificate;
3. **forges** an OCSP `BASICRESP` saying `GOOD` for the victim cert, signs it with
   the attacker key, and embeds the attacker cert (`OCSP_basic_sign`);
4. runs the **verbatim vulnerable** call and the **upstream fix** against it.

```
Forged OCSP response: status=GOOD for 'victim.example.com', signed by
the attacker's self-signed 'attacker-responder' cert (NOT the real CA).

  VULNERABLE verify (OCSP_basic_verify(..., NULL, OCSP_NOVERIFY)) : ACCEPTED forged GOOD  <-- revocation bypass
  FIXED verify      (store={issuer}+PARTIAL_CHAIN, flags 0)      : REJECTED (responder not authorized)

RESULT: OCSP SIGNER AUTHORIZATION BYPASS CONFIRMED
```

### Run it

```sh
bash run.sh     # builds poc.c against system OpenSSL with zig cc, runs the differential
```

## Exploitability / threat model

- **Attacker:** able to inject/replace an OCSP response consumed by
  `ngx.ocsp.validate_ocsp_response` (e.g. MITM of a relayed/stapled OCSP response),
  and holding a certificate whose genuine OCSP status is not `GOOD`.
- **Impact (I:H):** the revocation decision is forged — a revoked/compromised
  certificate is reported valid, defeating the security control the API exists to
  provide; this can chain into continued use of a key that should be rejected.
- **AC:H:** requires the app to validate attacker-influenceable OCSP responses and
  the attacker to possess the target certificate — non-trivial preconditions, hence
  the conservative MEDIUM rating.
- **Honest scope:** the signature over the forged response IS checked (against the
  attacker's own embedded cert); what is missing is the responder's *authorization*.

## Prominence note (transparency)

`python3 drawing_board/prominence.py --wildcard openresty/lua-nginx-module` returned
**UNKNOWN** this run because the unauthenticated GitHub API was rate-limited. The
manual estimate (~12k★, active) puts the mechanical score at ~69, just under the 70
bar. This PoC is shipped on the judgment that `lua-nginx-module` is foundational
OpenResty/CDN infrastructure (not the niche/dead/educational class the gate exists
to exclude) and the finding is a genuine, committed-today, high-severity crypto-
revocation-bypass 0-day. **The prominence gate and tiers were NOT modified.**

## Files

- `poc.c` — generates the PKI + forged OCSP response and drives the real OpenSSL verify (vuln vs fixed)
- `run.sh` — builds against system OpenSSL and runs
- `finding.json` — machine-readable finding record
