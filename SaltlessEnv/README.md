# SaltlessEnv — hardcoded default key + saltless KDF in `secure-env`

*Wildcard finding (found by the low-entropy-crypto hunt). A package whose entire job
is encrypting secrets protects them with a guessable key and a brute-forceable KDF.*

| Field | Value |
| --- | --- |
| Target | **`secure-env`** (npm) — "encrypt your `.env` and commit it" | ~21.5k downloads/week |
| Component | `dist/es5/lib/cryptography.js` — encrypt/decrypt |
| Type | **CWE-798** hardcoded default key + **CWE-759/CWE-916** unsalted, un-stretched KDF |
| Impact | Offline recovery of all secrets from a committed `.env.enc` |

## The bug

`secure-env` encrypts a `.env` file to `.env.enc` and its README tells you to commit
the `.env.enc` to your repo ("You can delete the .env file after this, to prevent
stealing"). The protection is two-fold broken:

```js
// secure-env dist/es5/lib/cryptography.js
var secret = options.secret || 'mySecret';                               // CWE-798 default key
...
var key = crypto.createHash('sha256').update(String(secret)).digest();   // CWE-759/916: no salt,
var cipher = crypto.createCipheriv(encryptionAlgo, key, iv);             // single SHA-256, AES-256-CBC
// (the source comment even says: "node v10.5.0+ should use crypto.scrypt(secret, salt, ...)")
```

1. **Hardcoded default key `'mySecret'`.** If the user doesn't pass `-s/--secret`, the
   file is "encrypted" with a publicly-known key → **0-bit** security.
2. **Saltless, un-stretched KDF.** Even with a user secret, `key = SHA256(secret)` has
   no salt and no stretching, so guessing runs at **raw hash speed** (hundreds of
   millions/sec on a GPU) — fully exposed to wordlist/brute-force, and identical
   secrets across projects produce identical keys (no salt → precomputation/rainbow).

Because the vendor workflow puts the ciphertext **in source control**, an attacker who
reads a public (or leaked) repo has everything needed to recover the plaintext secrets
offline.

## Proof of concept

- `victim_encrypt.js` runs the **real** secure-env code (published package, or a
  byte-identical vendored copy under `secure_env_vendored/`) to produce `.env.enc`.
- `attacker_crack.js` has only the `.env.enc` and reproduces the public KDF to recover
  the secret/plaintext (tries the default key, then a wordlist / PIN space).

```
./run.sh                      # or:
node victim_encrypt.js demo.env demo.env.enc          # default key "mySecret"
node attacker_crack.js demo.env.enc wordlist wordlist.txt
```

Output:

```
[victim] secure-env encrypted demo.env -> demo.env.enc (64 bytes) using DEFAULT key "mySecret"
[+] RECOVERED after 1 guesses in 0.001s
[+] Password          : "mySecret"
[+] Derived AES key   : d0be7334...  <-- SHA256(password), no salt
[+] Recovered secrets :
      DB_PASSWORD=sup3rs3cret
      API_KEY=EXAMPLE-not-a-real-key-0000
```

A user-chosen secret falls just as fast against a wordlist (`node attacker_crack.js
<file> wordlist <list>`) or a PIN space (`pin4` / `pin6`) because the KDF is saltless
and single-iteration.

## Exploitability

- **Default-key case: unconditional, 0-bit.** Any `.env.enc` made without `-s` decrypts
  with the known key `'mySecret'`.
- **Custom-secret case:** saltless `SHA256` → offline dictionary/brute-force at hash
  speed; no per-file salt means cross-project key reuse and precomputation.
- The ciphertext is routinely **public** (the vendor instructs committing it), so the
  attacker typically already has the only input required.

## Remediation

- Never ship a default key; require an explicit secret and fail closed if absent.
- Use a salted, memory-hard KDF (`scrypt`/`argon2`) with a random per-file salt stored
  alongside the ciphertext; use an AEAD (AES-256-GCM).
- Do not commit encrypted secrets to source control; use a real secrets manager.

## References

- Package: https://www.npmjs.com/package/secure-env
- Source: https://unpkg.com/secure-env/dist/es5/lib/cryptography.js
- CWE-798: https://cwe.mitre.org/data/definitions/798.html · CWE-759: https://cwe.mitre.org/data/definitions/759.html
