# CipherFlip — Ciphertext Bit-Flipping in npm `aes256`

| Field | Value |
|-------|-------|
| **Package** | [aes256](https://www.npmjs.com/package/aes256) v1.1.0 (35k downloads/week) |
| **CWE** | CWE-353 (Missing Integrity Check), CWE-327 (Broken Crypto), CWE-916 (Weak KDF) |
| **Source** | [index.js](https://unpkg.com/aes256@latest/index.js) |

## Vulnerability

The `aes256` npm package encrypts data with **AES-256-CTR** but provides **no authentication** — no HMAC, no GCM tag, no integrity check of any kind.

In CTR mode, encryption is a simple XOR of a keystream with the plaintext:

```
ciphertext[i] = plaintext[i] ⊕ keystream[i]
```

This makes the ciphertext **trivially malleable**: if an attacker knows the plaintext at any position, they can XOR the corresponding ciphertext bytes to produce any desired value — and the library decrypts the tampered data with **no error**.

### Vulnerable Code

```javascript
// AES-256-CTR — a stream cipher mode with NO authentication
var CIPHER_ALGORITHM = 'aes-256-ctr';

// Key derived from unsalted SHA-256(password) — no stretching, no salt
var sha256 = crypto.createHash('sha256');
sha256.update(key);

// Random IV is good, but NO MAC/tag means ciphertext is malleable
var cipher = crypto.createCipheriv(CIPHER_ALGORITHM, sha256.digest(), iv);
```

### Attack: Privilege Escalation via Bit-Flip

An application stores user roles as encrypted JSON:
```json
{"role":"user","name":"alice","canDelete":false}
```

An attacker intercepts the ciphertext (from a cookie, database, or API) and XORs 4 bytes to change `"user"` → `"root"`:

```
byte[25] ⊕ ('u' ⊕ 'r') = 0x07  →  'r'
byte[26] ⊕ ('s' ⊕ 'o') = 0x1c  →  'o'
byte[27] ⊕ ('e' ⊕ 'o') = 0x0a  →  'o'
byte[28] ⊕ ('r' ⊕ 't') = 0x06  →  't'
```

The library decrypts the tampered ciphertext to `{"role":"root",...}` — privilege escalation without knowing the key.

### Additional Weakness: Unsalted KDF

The key is derived via `SHA256(password)` with no salt and no iterations:
- Same password → same AES key (rainbow-table vulnerable)
- No key stretching (PBKDF2/scrypt/argon2) = fast brute-force

## Proof of Concept

```bash
cd poc/CipherFlip
npm install    # installs aes256@1.1.0
node poc.js
```

**Output**: Demonstrates role escalation (`"user"` → `"root"`), boolean flip (`false` → `true`), and the deterministic KDF.

## Remediation

Use authenticated encryption (AES-256-GCM) with a proper KDF:
- **`cryptr`** (756k dl/wk): AES-256-GCM + PBKDF2 with 100k iterations + random salt
- **`simple-encryptor`** (55k dl/wk): AES-256-CBC + HMAC + random IV

## References

- [npm: aes256](https://www.npmjs.com/package/aes256) — 35k weekly downloads
- [CWE-353: Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
