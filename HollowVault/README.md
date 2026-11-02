# HollowVault — Bruno "encrypted" secret store falls back to a machine‑id key + zero IV

*Low‑entropy / broken‑crypto wildcard finding.* [**Bruno**](https://github.com/usebruno/bruno)
— the popular open‑source API client (a Postman alternative) — stores the user's
**secret environment variables, OAuth2 access/refresh tokens, AI‑provider API keys,
and the cookie‑jar passkey** at rest with AES‑256‑CBC. Whenever the OS keyring is
unavailable, the key is **`SHA256(machine‑id)`** (the machine id is *not* a secret)
and the IV is **16 zero bytes**. Any local reader — or, in containers, anyone who
knows the hostname — recovers every credential with **no brute force and no secret**.

| Field | Value |
| --- | --- |
| Target | **Bruno** (`usebruno/bruno`) — open‑source API client / Postman alternative |
| Prominence | **47,980 ★ · 3,066 forks**, `@usebruno/cli` **≈381,000 downloads/week**, last push **2026‑11‑01** (hyper‑active). `prominence.py` **SCORE 100.0 → PASS** |
| Vulnerable file | `packages/bruno-electron/src/utils/encryption.js` @ `23233cb` (current `main`) |
| Type | **CWE‑329** (missing/zero IV, non‑random) · **CWE‑330/CWE‑916** (key from a predictable, non‑secret, unsalted source) · **CWE‑327** (unauthenticated CBC) · CWE‑311/312 (ineffective at‑rest protection) |
| Impact | Local disclosure of all stored API tokens, DB passwords, OAuth2 tokens, AI keys & cookies; constant key across cloned VMs/containers |

## Severity

| Field | Value |
| --- | --- |
| CVSS 3.1 | **6.2 MEDIUM** `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (local confidentiality; PR:N for malware/dependency running in the victim's own session — the "encryption" is zero defense‑in‑depth. A co‑tenant needing a local account is `PR:L` ≈ 5.5) |

## Root cause

`encryptString()` dispatches to an AES‑256‑CBC helper whenever Electron's
OS‑backed `safeStorage` is **not** available:

```js
// packages/bruno-electron/src/utils/encryption.js   (VERBATIM @ 23233cb, L32–L41)
function aes256Encrypt(data, passkey = null) {
  const rawKey = passkey || machineIdSync();                         // ← key source
  const iv = Buffer.alloc(16, 0); // Default IV for new encryption   // ← STATIC ZERO IV  (CWE-329)
  const key = crypto.createHash('sha256').update(rawKey).digest();   // ← unsalted SHA256 (CWE-916)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);      // ← no MAC          (CWE-327)
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
```
```js
function encryptString(str, passkey = null) {
  if (passkey !== null && passkey !== undefined) { ... aes256Encrypt(str, passkey) ... } // always zero‑IV
  if (safeStorage && safeStorage.isEncryptionAvailable()) { ...safeStorage ($00)... }     // OS keyring path
  const encryptedString = aes256Encrypt(str);                                             // ← fallback: machine‑id key
  return `$${AES256_ALGO}:${encryptedString}`;                                            //   stored as "$01:<hex>"
}
```
Permalink: <https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/utils/encryption.js#L32-L41>

`machineIdSync()` is `@usebruno/node-machine-id`, which returns **`sha256(raw machine‑id)`**, where the raw id is:

```js
// @usebruno/node-machine-id  (guid[platform])
linux:   '( cat /var/lib/dbus/machine-id /etc/machine-id 2>/dev/null || hostname ) | head -n1'
darwin:  'ioreg -rd1 -c IOPlatformExpertDevice'   // IOPlatformUUID
win32:   'REG QUERY HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid'
```

So the effective key is `SHA256(SHA256(machine‑id))` — and **the machine‑id is not a secret**:

* Linux `/etc/machine-id` is world‑readable (mode `0644`); if both id files are
  missing (minimal containers) it falls back to **`hostname`**.
* macOS `IOPlatformUUID` is readable by any process via `ioreg`.
* Windows `HKLM\…\MachineGuid` is readable by any user.

### Why it breaks

1. **The key is derived from a public, per‑machine constant** (CWE‑330/916). Any
   local process can compute `SHA256(machineIdSync())` and decrypt. There is no
   per‑user secret, no passphrase, no salt, no KDF stretching.
2. **The IV is 16 zero bytes** (CWE‑329). With a fixed key *and* fixed IV, the
   scheme is fully deterministic: equal secrets → equal ciphertext, and secrets
   sharing a 16‑byte prefix share leading ciphertext blocks (ECB‑like leakage).
3. **No authentication** (CWE‑327): raw CBC, no HMAC/GCM tag.
4. **Container/VM key collapse**: images that bake in one `/etc/machine-id`, or
   that have none (→ `hostname`), give **one identical key for every install**,
   so ciphertext from one host is decryptable on any other.

### What is protected by this scheme

All of these call `encryptString`/`encryptStringSafe` with **no passkey**, so on a
keyring‑less host they are written as `$01:` blobs keyed by the machine‑id:

| Secret | Call site |
| --- | --- |
| Environment **secret variables** (API tokens, DB passwords) | [`store/env-secrets.js#L40`](https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/store/env-secrets.js#L40) |
| Global / workspace env secrets | [`store/global-environments.js#L42`](https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/store/global-environments.js#L42) |
| **OAuth2** access + refresh tokens | [`store/oauth2.js#L132`](https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/store/oauth2.js#L132) |
| **AI‑provider API keys** | [`store/ai-keys.js#L17`](https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/store/ai-keys.js#L17) |
| Cookie‑jar **passkey** (a `randomBytes(32)` that then encrypts all saved cookies) | [`store/cookies.js#L37`](https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/store/cookies.js#L37) |

The cookie passkey is strong (`crypto.randomBytes(32)`), but it is *wrapped* with
the machine‑id key — so recovering the wrapper recovers the passkey, hence all
cookies. The random passkey buys nothing.

## Proof of concept

Everything is offline, no `npm install`, Node built‑ins only. The PoC vendors
Bruno's **verbatim** `encryption.js` (only the two `require()` paths are redirected
to local shims — the `electron` shim reports `safeStorage` unavailable, i.e. the
exact keyring‑less fallback, and `machine-id` is a byte‑faithful port of
`@usebruno/node-machine-id`'s Linux/macOS path). Victim and attacker are separate
processes that share **no** key material.

```bash
cd poc/HollowVault
bash run.sh
```

### Output (verbatim)

```
----- 1/3  victim stores secrets via Bruno's own encryption code -----
   env secret  authToken   -> $01:825370641cdf7f02e3083458428cf02dd49f5550676908c46ebb1167797beebb...
   env secret  dbPassword  -> $01:5bb7c2fcaa7375b394a94566365f3c1c698406aa85ad5a8725ded9d2c5fcc4b8...
   env secret  stripeKey   -> $01:5bb7c2fcaa7375b394a94566365f3c1c0f1f22112d836ec58a7057192dada1dd...
   oauth2 creds           -> $01:e5703106b446fd4b51b462413a5f16e6226479d6f377aa3caccf6f6f42d09bad...
   ai provider key        -> $01:5bb7c2fcaa7375b394a94566365f3c1ccd4c4bdd2ca07fc3cef0c84fde51895f...

----- 2/3  attacker recovers them with only the public machine-id -----
[1] Machine-id is NOT a secret. Any local process can read it:
      $ cat /etc/machine-id   ->  a378fa27692a4e5891e18ee3fff24ee8
[2] Derived Bruno's key from the public machine-id:
      rawKey = machineIdSync()      = b5df0cc3c030db37e5c333914396320f7677ac29bfe4c8bfbbb1bec93250a247
      key    = sha256(rawKey)[0:8]  = c503aebc3ae5de5f...
      iv     = 00000000000000000000000000000000  (zero)
[3] Decrypting every stored credential (attacker has no key material):
      env  Production/authToken   = Bearer EXAMPLE-not-a-real-prod-bearer-7f3b9c2a1d
      env  Production/dbPassword  = EXAMPLE-not-a-real-postgres-password
      env  Production/stripeKey   = EXAMPLE-not-a-real-stripe-live-key-9Hq2
      oauth2 access_token          = EXAMPLE-not-a-real-google-oauth-access-token
      oauth2 refresh_token         = EXAMPLE-not-a-real-google-oauth-refresh-token
      ai anthropic key             = EXAMPLE-not-a-real-anthropic-api-key-0042
[4] Static zero IV => deterministic ciphertext (CWE-329):
      encrypt("duplicate-secret-value") twice equal? true

----- 3/3  verify against ground truth + Bruno's decryptString --------
RESULT: 6/6 credentials recovered WITHOUT any secret.  PASS
```

> Notice `dbPassword`, `stripeKey`, and the AI key share the **same leading
> ciphertext block** (`$01:5bb7c2fcaa7375b394a94566365f3c1c…`) in step 1: they all
> begin with the 16‑byte prefix `EXAMPLE-not-a-re`, and the static zero IV makes the
> first CBC block a pure function of (key, first 16 plaintext bytes). That block
> equality is a live, visible instance of the CWE‑329 leak — before any decryption.

The attacker reconstructs the key purely from the host's public machine‑id and
decrypts every stored credential; `verify.js` confirms 6/6 against ground truth and
that Bruno's own `decryptString(encryptString(x)) == x`.

## Threat model (honest)

* **In scope / demonstrated:** on any Bruno host where Electron
  `safeStorage.isEncryptionAvailable()` is **false** — i.e. no usable OS keyring:
  headless/minimal Linux, many server/WSL/Docker/CI setups, keyring‑less sessions —
  every stored secret is written as `$01:` and is decryptable by **any** party that
  can read the store file (`<userData>/secrets.json`, `oauth2.json`, etc.). The
  "key" (`SHA256(machine‑id)`) is world‑readable locally. Realistic readers: a
  co‑tenant on a shared/multi‑user box, malware or a **malicious dependency /
  postinstall** in a repo the developer opens, a cloud‑synced or backed‑up
  `~/.config/bruno`, or a decommissioned disk / VM image.
* **Escalation (no local access):** minimal containers often have **no**
  `/etc/machine-id`, so the key degrades to `SHA256(SHA256(hostname))`; cloned VMs
  and container images frequently **share one machine‑id**. Either case yields a
  *constant* key, so ciphertext exfiltrated from one host is decryptable offline by
  anyone who knows (or guesses) the hostname / shared id.
* **The static zero IV (CWE‑329) is unconditional** for the `aes256` path (incl. the
  cookie‑value path keyed by the passkey): identical secrets always produce
  identical ciphertext.
* **Out of scope / not claimed:** on a normal desktop **with** a working keyring,
  env secrets instead get the `$00:` prefix and are protected by the OS store; this
  finding is specifically the *silent, cosmetic* fallback. (Note Electron's own
  keyring‑less `basic_text` backend is itself a hardcoded‑key scheme, so "no keyring
  → secrets trivially recoverable" holds either way.) No formal CVE is assigned; this
  is a new report against current `main` (`23233cb`, unfixed).

## Remediation

1. **Never derive the key from the machine‑id** (or any non‑secret). If no OS
   keyring is present, either (a) refuse to store secrets and tell the user, or (b)
   derive a key from a **user‑supplied passphrase** via a salted KDF
   (scrypt/argon2/PBKDF2 ≥ 310k) with a random per‑install salt.
2. **Use a random per‑message IV** with `createCipheriv` (and store it alongside the
   ciphertext) — never `Buffer.alloc(16, 0)`.
3. **Use an AEAD** (`aes-256-gcm`) and store `iv || tag || ciphertext`.
4. Make the weak fallback **loud**, not silent: surface that secrets are stored
   without OS‑backed protection so users can opt into a passphrase.

## References

- Vulnerable function: <https://github.com/usebruno/bruno/blob/23233cb6b664080fac6e384a7256224f30edb42a/packages/bruno-electron/src/utils/encryption.js#L32-L41>
- Key source (`@usebruno/node-machine-id`): <https://unpkg.com/@usebruno/node-machine-id@2.0.0/index.js>
- npm `@usebruno/cli`: <https://www.npmjs.com/package/@usebruno/cli>
- CWE‑329 (no/zero IV): <https://cwe.mitre.org/data/definitions/329.html> · CWE‑916 (weak key derivation): <https://cwe.mitre.org/data/definitions/916.html> · CWE‑330 (insufficiently random values): <https://cwe.mitre.org/data/definitions/330.html>
