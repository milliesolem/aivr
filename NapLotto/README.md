# NapLotto — NapCatQQ WebUI credential HMAC key from `Math.random()` (CWE-330/338)

| | |
|---|---|
| Product + version | **NapCatQQ** (NapNeko/NapCatQQ, 12.2k★, main branch as of 2026-11-03 — unfixed) |
| CVSS | **5.9 MEDIUM** `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N` (computed with drawing_board/cvss31.py) |
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
`Math.random().toString(36).substring(2, 15)` — one V8 Math.random() double per
request, base36-encoded. The WebUI backend imports the OneBot adapter
(`napcat-webui-backend/index.ts`: `import { NapCatOneBot11Adapter } from
'@/napcat-onebot/index'`) — one Node process, one PRNG stream. (The emitter has
a measured ±1-ulp round-trip quirk, ~13% of draws — handled by the PoC's
tolerance search, below.)

## Exploit chain

1. **Sniff one credential** (WebUI default host is `::`, so sessions are
   reachable on the LAN; or browser storage / logs) — gives `HashEncoded` and a
   known `Hmac = HMAC-SHA256(key, known_json)`. The unmodified credential dies
   after 1 hour; the HMAC is the oracle.
2. **Collect 5 echoes** from the OneBot HTTP API → 5 V8 doubles (each within a
   1-ulp tolerance, brute-forced in the state recovery).
3. **Recover the xorshift128+ state** with z3 (reused
   `drawing_board/v8_math_random_predictor.py`; ±1-ulp combos, first sat wins).
4. **Roll forward to the startup key draw** (the first `Math.random()` call in
   the process — the static initializer; the echoes follow it on the same
   64-value cache) and identify the exact key string by testing base36
   candidate strings (parse within 1 ulp of the recovered double) against the
   sniffed HMAC. The candidate that reproduces the Hmac **is** the key.
5. **Forge a credential**: re-sign the sniffed `HashEncoded` with
   `CreatedTime = now`. The real `validateCredentialWithinOneHour()` accepts it
   — the expired/revoked session is resurrected and, until the process is
   restarted or the token changed, never expires again (expiry and revocation
   are HMAC-keyed; the forged Data is not blacklisted and the attacker
   re-signs at will).
6. Admin WebUI → Debug (terminal/WebSocket), File, Plugin (arbitrary plugin
   install = code execution) and Process APIs on the bot host.

## Exploitability assessment (honest)

- **Preconditions (3, stated explicitly):**
  1. **Operator-enabled, attacker-reachable OneBot HTTP server** — the OneBot
     HTTP adapter is **disabled by default** (`HttpServerConfigSchema`:
     `enable: false`, `httpServers: []`, default `host: '127.0.0.1'`); the
     operator must enable an HTTP server and bind it to an interface the
     attacker can reach. (The WebUI itself defaults to `host: '::'`, so the
     credential-sniff precondition is realistic independently.)
  2. **One captured admin credential** (`HashEncoded` + `Hmac`) — the forged
     credential reuses it; the attack defeats expiry + revocation, it does
     NOT by itself bypass the WebUI token (a token leak combined with this
     gives full unauthenticated admin).
  3. **An observation window in which the 5 echoes are consecutive draws** —
     other protocol traffic consumes `Math.random()` between draws; on an idle
     bot the oracle is the only consumer. (Spaced observations with bounded
     offsets extend the same primitive — not demonstrated here.)
- **Scope:** AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N = 5.9 MEDIUM. "Permanent" is
  bounded by process restart (a new key is drawn per process) and token change.
- **Caveats stated plainly:** the 10-position forward scan assumes key + echoes
  share the first 64-cache batch (fresh process — the realistic attack window);
  the demo harness draws the key first and serves echoes from the same process,
  exactly matching the real module-load order; `/key` exists only as a demo
  cross-check and is not used by the attack (the HMAC oracle is).
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
`validateCredentialWithinOneHour`/`isCredentialRevoked`, and the echo
expression are transcribed from NapCatQQ @ main (marked `[VERBATIM]` in
`server.js`; only the in-memory `store` is a stand-in) and executed by real
Node 20 — the PRNG is the genuine V8 xorshift128+. The state recovery reuses
the validated `v8_math_random_predictor.py` z3 primitive with a measured
±1-ulp tolerance for the radix-36 emitter quirk (13% misparse measured over
300 draws).

## 3 ways this might NOT work (checked)

1. *`Math.random().toString(36).slice(2)` has too much entropy.* Checked: the
   entropy is V8's 128-bit state — unguessable WITHOUT observations — but the
   echo oracle hands the attacker stream outputs, which is precisely what the
   V8 predictor turns into state recovery (validated against real Node).
2. *The credential still needs the token.* Checked and stated: `HashEncoded =
   SHA256(token + '.napcat')` is verified by the middleware, so the forged
   credential reuses the sniffed `HashEncoded`; the demonstrated impact is
   defeating expiry + revocation, not a token-less login.
3. *The OneBot HTTP server is off by default / not reachable.* Checked and
   stated as precondition #1 — the finding holds for operator-enabled
   deployments (the common self-hosted case), and the WebUI itself is
   LAN-reachable by default, which covers the sniff precondition.

## References

- Vulnerable key derivation: https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-webui-backend/src/helper/SignToken.ts#L5
- Echo oracle: https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-onebot/network/http-server.ts#L273
- One-process proof (WebUI backend imports OneBot adapter): https://github.com/NapNeko/NapCatQQ/blob/main/packages/napcat-webui-backend/index.ts
- Primitive: `drawing_board/v8_math_random_predictor.py` (z3 V8 xorshift128+ state recovery)
