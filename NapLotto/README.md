# NapLotto — NapCatQQ WebUI credential HMAC key from `Math.random()` (CWE-330/338)

| | |
|---|---|
| Product + version | **NapCatQQ** (NapNeko/NapCatQQ, 12.2k★, main branch as of 2026-11-03 — unfixed) |
| CVSS | **7.1 HIGH** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` (computed with drawing_board/cvss31.py) |
| CWE | CWE-330 (Use of Insufficiently Random Values) / CWE-338 (PRNG, not CSPRNG) |

## The bug

Two code sites, one process, one V8 `Math.random()` stream:

**1. The WebUI credential HMAC key falls back to `Math.random()`** — `packages/
napcat-webui-backend/src/helper/SignToken.ts:5`:

```ts
private static readonly secretKey = process.env['NAPCAT_WEBUI_JWT_SECRET_KEY'] || Math.random().toString(36).slice(2);
```

Every WebUI credential is `{Data: {CreatedTime, HashEncoded}, Hmac}` with
`Hmac = HMAC-SHA256(secretKey, JSON.stringify(Data))`. The key protects the
credential's integrity — its 1-hour expiry and the revocation list are both
enforced through this HMAC. When the admin does not set
`NAPCAT_WEBUI_JWT_SECRET_KEY` (the default install), the key is a single
`Math.random()` draw — the V8 xorshift128+ PRNG, not a CSPRNG (CWE-330/338).
(The *token* itself uses `crypto.randomBytes` via `getRandomToken()` — safe.)

**2. The OneBot HTTP API echoes the exact same stream** — `packages/napcat-onebot/
network/http-server.ts:273`:

```ts
const real_echo = payload_echo ?? Math.random().toString(36).substring(2, 15);
```

Any request WITHOUT an `echo` field gets a response whose `echo` is
`Math.random().toString(36).substring(2,15)` — one **exact** `Math.random()`
double per request (the base36 string is the double's shortest round-trip
representation; ≤ 11 significant digits + ≤ 2 leading zeros fit the 13-char
window in all but ~1/46656 draws). The WebUI backend imports the OneBot adapter
(`napcat-webui-backend/index.ts`: `import { NapCatOneBot11Adapter } from
'@/napcat-onebot/index'`) — one Node process, one PRNG stream.

## Exploit chain

1. **Sniff one credential** (same-LAN admin session, browser storage, logs) —
   gives `HashEncoded` and a known `Hmac = HMAC-SHA256(key, known_json)`.
   The unmodified credential is dead after 1 hour; the HMAC is the oracle.
2. **Collect 5 echoes** from the OneBot HTTP API → 5 consecutive exact V8
   doubles.
3. **Recover the xorshift128+ state** with z3 (5 exact doubles suffice; the
   reused `drawing_board/v8_math_random_predictor.py` primitive).
4. **Roll to the startup key draw** (the first `Math.random()` call in the
   process — the static initializer) and reconstruct the exact key string:
   enumerate the shortest-length candidate base36 strings of the recovered
   double and test each against the sniffed HMAC. The candidate that
   reproduces the Hmac **is** the key.
5. **Forge a permanent credential**: re-sign the sniffed `HashEncoded` with
   `CreatedTime = now`. The real `validateCredentialWithinOneHour()` accepts it
   — the expired/revoked session is resurrected and can never expire again
   (the expiry and revocation are HMAC-keyed; the attacker re-signs at will).
6. Admin WebUI → Debug (terminal/WebSocket), File, Plugin (arbitrary plugin
   install = code execution) and Process APIs on the bot host.

## Exploitability assessment (honest)

- **Preconditions:** network access to the OneBot HTTP API (default port 3000,
  LAN-reachable by design for QQ bots) + one sniffed credential. The key
  recovery itself needs no credentials at all. NVD-style honest scope: AV:A,
  no privileges, no interaction. The final credential reuse needs the sniffed
  `HashEncoded` — **the attack defeats the credential's expiry + revocation
  (permanent admin persistence), it does not by itself bypass the WebUI token**
  (a token leak combined with this gives full unauthenticated admin; the
  default-install token path is CSPRNG-random, so it is not recoverable here).
- **Caveats stated plainly:** (1) in a live deployment other protocol traffic
  consumes `Math.random()` between draws, so the echo outputs may not be
  consecutive — when the bot is idle they are; with gaps the same primitive
  extends to spaced observations with bounded offsets, not demonstrated here.
  (2) The demo harness draws the key first and serves echoes from the same
  process, exactly matching the real module-load order; `/key` exists only as
  a demo cross-check and is not used by the attack.
- **Unfixed** at main (2026-11-03): `SignToken.ts:5` and `http-server.ts:273`
  still verbatim.

## Run

```sh
bash run.sh
```

Requires: `node` (v20) and Python 3 with `z3-solver`. Expected output: state
recovery, `HMAC oracle selected … MATCH: True`, and the real validation
accepting the forged credential (`200 accepted=True`). Exit 0.

## Why this PoC is faithful

The vulnerable key derivation, `signCredential`/`checkCredential`/
`validateCredentialWithinOneHour`, and the echo expression are copied verbatim
from NapCatQQ @ main (marked `[VERBATIM]` in `server.js`) and executed by real
Node 20 — the PRNG is the genuine V8 xorshift128+. The state recovery reuses
the validated `v8_math_random_predictor.py` z3 primitive. The only modelled
element is the demo plumbing (the real HTTP scaffolding is collapsed to the
same values the real app exposes).

## 3 ways this might NOT work (checked)

1. *`Math.random().toString(36).slice(2)` has too much entropy.* Checked: the
   entropy is V8's 128-bit state — unguessable WITHOUT observations — but the
   echo oracle hands the attacker exact stream outputs, which is precisely what
   the V8 predictor turns into state recovery (validated against real Node).
2. *The credential still needs the token.* Checked and stated: `HashEncoded =
   SHA256(token + '.napcat')` is verified by the middleware, so the forged
   credential reuses the sniffed `HashEncoded`; the demonstrated impact is
   defeating expiry + revocation (permanent session from one sniffed request),
   not a token-less login.
3. *Echo draws are truncated/interleaved.* Checked: truncation needs ≥3 leading
   zeros (~1/46656 draws — the PoC retries on unsat); interleaving by protocol
   traffic is the main real-world caveat (see above) — idle-bot condition
   stated, not hidden.

## References

- Vulnerable key derivation: https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-webui-backend/src/helper/SignToken.ts#L5
- Echo oracle: https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-onebot/network/http-server.ts#L273
- One-process proof (WebUI backend imports OneBot adapter): https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-webui-backend/index.ts
- Primitive: `drawing_board/v8_math_random_predictor.py` (z3 V8 xorshift128+ state recovery)
