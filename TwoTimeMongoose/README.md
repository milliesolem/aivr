# TwoTimeMongoose — AES‑CTR keystream reuse in `mongoose-field-encryption`

*Low‑entropy / weak‑crypto wildcard finding. A library that encrypts sensitive
MongoDB fields reuses **one fixed AES‑CTR keystream** for every field of every
document, turning the whole encrypted database into a two‑time pad: all plaintext
is recoverable from the ciphertext **without the secret**.*

| Field | Value |
| --- | --- |
| Target | **`mongoose-field-encryption`** (npm) — field‑level encryption plugin for Mongoose/MongoDB |
| Downloads | **~23,800 / week** (npm `last-week`, 2026‑10‑23→29); latest `7.0.1` |
| Repo / license | https://github.com/wheresvic/mongoose-field-encryption · MIT |
| Vulnerable mode | **AES‑256‑CTR** via `crypto.createCipher` — the **default & only** algorithm in all `1.x`, still shipped as `useAes256Ctr: true` and auto‑used to decrypt legacy data in `7.x` |
| Type | **CWE‑323** Reusing a Nonce/Key Pair in Encryption · **CWE‑329** no random IV · **CWE‑327** broken KDF (`createCipher` = MD5 EVP_BytesToKey) |
| Impact | Full recovery of every encrypted field (PII, SSNs, card numbers) from a leaked DB/backup, **no secret required** |

## The bug

`mongoose-field-encryption`'s CTR path encrypts with the deprecated `crypto.createCipher`:

```js
// lib/mongoose-field-encryption.js
const deprecatedAlgorithm = "aes-256-ctr";

const encryptAes256Ctr = function (text, secret) {
  const cipher = crypto.createCipher(deprecatedAlgorithm, secret);   // <-- line 10
  let crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
};
```
Permalink: https://github.com/wheresvic/mongoose-field-encryption/blob/c9c0063d0a80f86b95957bd5acf6db043f483c1f/lib/mongoose-field-encryption.js#L9-L14

`crypto.createCipher(alg, secret)` derives **both** the key **and** the IV / initial
counter block deterministically from `secret` (OpenSSL `EVP_BytesToKey`, MD5, no salt).
There is **no random IV/nonce**. In CTR mode the cipher is just a keystream generator:

```
ciphertext = plaintext XOR AES_CTR_keystream(key, counter)
```

Because `key` **and** `counter` are a fixed function of the secret, the **exact same
keystream** encrypts every field of every document. That is a textbook *two‑time pad*:

```
C_a XOR C_b  ==  P_a XOR P_b          (the secret cancels)
```

Two further facts make this a live, high‑reach issue rather than a museum piece:

1. **It was the default.** Every `1.0.0 – 1.2.1` release used `aes-256-ctr` as the one
   and only algorithm, so any database first encrypted on `1.x` is full of two‑time‑pad
   ciphertext.
2. **Current versions still produce and consume it.** `7.x` keeps it as a supported
   option (`useAes256Ctr: true`) and its `decrypt()` **auto‑falls back to the CTR path**
   for any legacy (colon‑less) value:
   ```js
   if (encryptedArray.length === 1) {            // lib/...js:63
     return decryptAes256Ctr(encryptedArray[0], secret);
   }
   ```

## Why this is "low entropy"

A secure AEAD/CBC scheme draws a fresh random IV per message, so the effective keystream
space is 2^(IV bits) per encryption. Here the IV/counter is a **constant** derived from
the secret — **0 bits of per‑message randomness**. The entire confidentiality of an
arbitrarily large database collapses onto a **single reused keystream**, which an
attacker reconstructs from one known plaintext (or by crib‑dragging common field
prefixes) — no brute force, no secret, just XOR.

## Proof of concept

Files (all offline; the attacker step never imports the library and never sees the secret):

- `victim_store.js` — encrypts 4 users' `email / ssn / card` with the library's own
  exported `encryptAes256Ctr(text, secret)` (real npm package, or the byte‑identical
  copy in `vendored/`), and writes `encrypted_db.json` (the "leaked dump").
- `attacker_decrypt.js` — reads **only** `encrypted_db.json`; detects the keystream reuse,
  recovers the keystream from the attacker's **own** known record (a registered user
  knows their own email), and decrypts **everyone's** fields.
- `verify.js` — cross‑checks the attacker's secret‑free output against the library's real
  `decrypt(hex, secret)`.

```bash
cd poc/TwoTimeMongoose
bash run_poc.sh
```

### Output (verbatim)

```
 ATTACKER: recover all plaintext from encrypted_db.json — NO secret
[1] Detecting two-time-pad reuse (no secret, no plaintext needed):
    C(ssn#1) ^ C(ssn#2) = 000000000300010007060002030c0d
    -> leading bytes are 00 because both plaintexts start with "SSN:" (prefix cancels)
    -> confirms a FIXED keystream is reused for every field.

[2] Recovered 30 keystream bytes from the attacker's own known email.
[3] Decrypting the ENTIRE database with the recovered keystream (no secret):
    id  email                             ssn               card
    1   alice.nguyen@hospital.org         SSN:123-45-6789   CARD:4111111111111111
    2   bob.carter@hospital.org           SSN:222-33-4444   CARD:5500005555555559
    3   attacker.mallory@evilcorp.test    SSN:999-88-7777   CARD:340000000000009
    4   dana.lopez@hospital.org           SSN:456-78-9012   CARD:6011000990139424

 VERIFY: attacker output vs. the library's real secret-based decryption
[verify] attacker-recovered fields matching the library's true decryption: 12/12
```

Step [1] proves the reuse using **no plaintext at all** (the shared `"SSN:"` prefix makes
`C_a XOR C_b` start with zero bytes). Step [2]–[3] recover the full keystream from one
known field and decrypt the whole table. `verify.js` confirms 12/12 fields match the
library's own decryption.

## Exploitability

| Criterion | Assessment |
| --- | --- |
| Secret required | **No** — recovery is pure XOR once the keystream is known |
| Known plaintext | One field the attacker already knows (their own record) — or crib‑drag shared prefixes/formats |
| Preconditions | Possess the encrypted data (DB dump, backup, replica, `mongodump`, log) and the app uses the CTR mode (default on `1.x`; opt‑in/legacy on `2.x–7.x`) |
| Blast radius | Every field of every document encrypted under that secret |

## Remediation

- **Never use `crypto.createCipher`.** It uses a weak MD5 KDF and a fixed IV. Use
  `createCipheriv` with a **random per‑message IV/nonce** (the library's modern CBC path
  already does this) — and migrate/re‑encrypt any legacy `aes-256-ctr` data.
- Prefer an **AEAD** (`aes-256-gcm`) with a random 96‑bit nonce per field and store
  `nonce || tag || ciphertext`; derive the key with a salted KDF (scrypt/PBKDF2/HKDF).
- Maintainers: remove the `useAes256Ctr` option and the colon‑less decrypt fallback, or
  gate them behind an explicit, loud "legacy, insecure" migration tool.

## References

- npm: https://www.npmjs.com/package/mongoose-field-encryption
- Vulnerable function: https://github.com/wheresvic/mongoose-field-encryption/blob/c9c0063d0a80f86b95957bd5acf6db043f483c1f/lib/mongoose-field-encryption.js#L9-L14
- Legacy auto‑fallback: https://github.com/wheresvic/mongoose-field-encryption/blob/c9c0063d0a80f86b95957bd5acf6db043f483c1f/lib/mongoose-field-encryption.js#L63-L64
- Node docs — `crypto.createCipher` deprecation (DEP0106): https://nodejs.org/api/deprecations.html#DEP0106
- CWE‑323: https://cwe.mitre.org/data/definitions/323.html · CWE‑329: https://cwe.mitre.org/data/definitions/329.html
