# WeakFactor — volto-tfa derives its TOTP 2FA secret from `Math.random()`

*Low-entropy / weak-PRNG wildcard finding. A two-factor-authentication add-on — software whose
entire job is to add a **cryptographic** second factor — seeds each user's TOTP secret with
`Math.random()`, a non-cryptographic PRNG. The one value in the system that must be unpredictable is
both low-entropy and predictable, so the "second factor" provides no real security.*

| Field | Value |
| --- | --- |
| Target | **`collective/volto-tfa`** — the Plone/Volto community's two-factor-authentication add-on |
| Prominence | Official **`collective`** (Plone community) org; the de-facto 2FA add-on for Volto (React frontend for Plone, a 20+ year CMS used by governments, universities, NGOs) |
| File | [`src/components/Preferences/QRCodeWidget.jsx`](https://github.com/collective/volto-tfa/blob/94ecae42adc6a17647a8b6f22e96dfc420e16d6f/src/components/Preferences/QRCodeWidget.jsx#L29) |
| Type | **CWE-338** (use of cryptographically weak PRNG) · **CWE-330/331** (insufficient entropy for a security token) |
| Impact | Predict / brute-force a user's enrolled TOTP secret → generate valid 2FA codes → **full second-factor bypass** |

## Root cause

The TOTP secret is minted in the victim's browser like this:

```jsx
// volto-tfa QRCodeWidget.jsx — the secret the authenticator app and the server both key on
const secret = encode(Math.random().toString(36))   // hi-base32 of ONE Math.random() draw
  .toString()
  .substring(0, 16);
onChange(id, secret);                                 // persisted as the user's TOTP secret
// ...rendered into otpauth://totp/...?secret=${secret}
```

Two independent problems, both fatal for a 2FA secret (RFC 6238/4226 require ≥128 bits from a CSPRNG):

1. **Insufficient entropy.** The whole secret is a deterministic function of a *single*
   `Math.random()` double. `(0.xxxx).toString(36)` always begins `"0."`, so the base32 output has a
   **constant `GAX` prefix** (verified: 100% of 20 000 samples) — the first 3 of 16 characters carry
   no entropy. What remains derives from ~8 base-36 digits of one double (≤ 52 bits, realistically
   ~41 bits).
2. **Predictable PRNG.** `Math.random()` is V8's `xorshift128+`, not a CSPRNG. Its state is linearly
   recoverable from a handful of consecutive outputs — and web pages emit many `Math.random()` values
   (React keys, element ids, analytics, animation). An attacker who observes a few of them recovers
   the generator state and computes the *exact* secret the widget drew next.

## Proof of concept

`poc.js` runs the **real** `hi-base32` library and the exact widget line. It plays a victim whose
page leaks 6 consecutive `Math.random()` outputs and then enrols a TOTP secret with the next draw;
the attacker, given only the 6 leaked values, recovers the V8 state with `v8_predict.py` (z3),
predicts the secret-generating draw, reconstructs the TOTP secret byte-for-byte, and forges the live
6-digit code.

```
$ ./run.sh
observed leaked Math.random()  : 0.059113, 0.497629, 0.207052, 0.340797, 0.205602, 0.834764
predicted secret-generating draw: 0.5492020163396605

victim  TOTP secret : GAXGU4TSNNUHGMTB
attacker TOTP secret: GAXGU4TSNNUHGMTB   <- reconstructed from leaked RNG
victim  TOTP code   : 980411
attacker TOTP code  : 980411

RESULT: secret + live code RECOVERED -> 2FA fully bypassed (CWE-338/330)
```

- `poc.js` — victim enrolment (real `hi-base32`) + attacker reconstruction + RFC-6238 TOTP verifier.
- `v8_predict.py` — V8 `Math.random()` state recovery and forward prediction (z3); reusable primitive.
- `run.sh` — installs `hi-base32` locally (gitignored) and runs the PoC.

## Exploitability assessment

Genuine and high-value because the target *is* a security control. The strongest path is PRNG
prediction (shown above): with a few leaked `Math.random()` outputs from the victim's session the
secret is recovered deterministically. Even without state recovery, the secret's constant `GAX`
prefix plus ≤52 bits of non-crypto entropy make offline brute force of the TOTP space far cheaper
than the ≥128-bit CSPRNG baseline TOTP assumes. Because the secret is generated **client-side** and
then trusted by the server, there is no server-side CSPRNG to fall back on. Prominence is modest in
raw install counts, but a 2FA add-on with a predictable secret is a security-critical defect
regardless of download numbers.

**Remediation:** generate the secret with a CSPRNG — `crypto.getRandomValues()` in the browser, or
(better) mint it **server-side** with `secrets`/`os.urandom` and never let the client choose it. The
widget's own `TODO` comment ("fare generare il valore del qr code dal server" — "have the server
generate the QR-code value") acknowledges the right fix.

## References
- Source (vulnerable line): https://github.com/collective/volto-tfa/blob/94ecae42adc6a17647a8b6f22e96dfc420e16d6f/src/components/Preferences/QRCodeWidget.jsx#L29
- V8 `Math.random()` predictability (xorshift128+): https://v8.dev/blog/math-random
- RFC 6238 (TOTP) / RFC 4226 (HOTP) secret-strength guidance
