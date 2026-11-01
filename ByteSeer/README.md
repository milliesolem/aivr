# ByteSeer — `crypt.randomBytes()` (npm `crypt`) is fully predictable

| | |
|---|---|
| **Name** | ByteSeer |
| **Target** | npm [`crypt`](https://www.npmjs.com/package/crypt) (v0.0.2, unchanged since 2011) — ~24M weekly downloads |
| **Vuln class** | CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator) |
| **Proof** | 18 leaked bytes of a 24-byte secret → the remaining 6 recovered exactly via GF(2) state recovery of V8's `Math.random` |

## Vulnerability

The `crypt` package ships a CSPRNG-shaped API used by downstream code for
keys/tokens/salts/IVs:

```js
// crypt.js (unpkg.com/crypt@latest/crypt.js, unchanged since 2011)
randomBytes: function(n) {
  for (var bytes = []; n > 0; n--)
    bytes.push(Math.floor(Math.random() * 256));   // <-- V8 Math.random!
  return bytes;
},
```

V8's `Math.random()` is **xorshift128+** — a fast, fully linear (over GF(2))
PRNG, not a CSPRNG. Each `crypt` byte reveals 8 bits of the 64-bit `state0`
per output; 16–18 observed bytes yield ≥128 linear equations over the 128-bit
state, solved in milliseconds by Gaussian elimination. Any secret derived
from `crypt.randomBytes()` is therefore predictable from a partial
observation (hex prefix in logs, nonce in a URL, part of an IV, …) — and, in
the same way, fully recoverable by anyone who can observe enough of the
stream.

## Entropy / root-cause analysis

- **Key/byte entropy:** 0 beyond what the attacker already saw. V8
  `Math.random` carries no cryptographic security; the npm package name and
  API (`randomBytes`, mirroring Node's CSPRNG `crypto.randomBytes`) misleads
  callers into using it for secret material.
- **Root cause:** 2011-era code predating `crypto.getRandomValues`; the
  package has no maintainer-driven replacement and remains one of the
  most-downloaded crypto-named packages on npm.

## Exploit chain

1. Attacker observes 18 bytes of a `crypt.randomBytes(24)`-derived secret
   (leaked prefix / nonce / counter in logs or URLs).
2. GF(2) Gaussian elimination recovers the V8 xorshift128+ state.
3. The inverse xorshift step walks the generator backward, predicting every
   remaining byte of the secret exactly (V8's 64-value cache is consumed in
   reverse order).

## Exploitability assessment

- **Library-level primitive weakness:** every downstream caller that uses
  `randomBytes` for secrets is broken by design; this PoC proves the
  prediction math against the real package on Node 20.
- **Honest scope:** no single downstream victim is demonstrated; the impact
  is the reusable weakness itself in a hugely-downloaded dependency. Remediate
  by replacing with `crypto.randomBytes` (Node) or `crypto.getRandomValues`.

## Run

```bash
npm install        # installs crypt@0.0.2
python3 poc.py     # needs Python 3 + Node (>=18); pure stdlib, no z3
```

`secret_gen.js` mints a 24-byte key with the real `crypt` package; `poc.py`
recovers the V8 state from the leaked 18-byte prefix and predicts the
remaining 6 bytes. Expect `RESULT: PASS`.

## Remediation

- In `crypt`: replace the body with `crypto.getRandomValues`/`crypto.randomBytes`.
- Downstream: never use `crypt.randomBytes` (or any `Math.random`-derived
  value) for keys, tokens, salts, IVs or nonces.
