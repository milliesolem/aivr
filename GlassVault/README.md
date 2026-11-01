# GlassVault — Qiniu Kodo Browser hardcoded-key credential decryption

| Field | Value |
| --- | --- |
| Product | [Qiniu Kodo Browser](https://github.com/qiniu/kodo-browser) — official desktop client for Qiniu object storage |
| Affected | `v2.3.3` (current at time of writing); the hardcoded key is in every release |
| CVSS | ~5.9 MEDIUM `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (local, confidentiality) |
| CWE | CWE-798 (hardcoded credentials/key), CWE-321 (hardcoded crypto key), CWE-327 (deprecated `createCipher`, no IV) |
| Prominence | Official client of Qiniu (one of China's largest cloud providers) |

## Summary

Kodo Browser stores the user's cloud credentials — `accessKey` + `accessSecret`
(full access to their Qiniu object-storage buckets) — in browser localStorage,
"encrypted" with AES-256-CBC using a **hardcoded key** and Node's deprecated
`crypto.createCipher()` (which takes no IV).

The key is a compile-time constant in the public source:

```ts
// src/renderer/modules/auth/cipher.ts
const ALGORITHM = "aes-256-cbc";
const KEY = "x82m#*lx8vv";

export function cipher(data: string, key: string = KEY, algorithm: string = ALGORITHM): string {
  const cip = crypto.createCipher(algorithm, key);   // <-- no IV, hardcoded key
  ...
}
```

```ts
// src/renderer/modules/auth/persistence.ts
class AuthInfoSerializer extends serializer.JSONSerializer<AuthInfo> {
  serialize(value: AuthInfo): string {
    return cipher(JSON.stringify({
      accessKey: value.accessKey, accessSecret: value.accessSecret, ...
    }));
  }
}
```

## Root-cause analysis

1. **The key is public.** `KEY = "x82m#*lx8vv"` is checked into the repository, so
   "encryption" provides zero secrecy against anyone who can read the source (or
   the shipped JS bundle).
2. **No IV / no salt.** `createCipher(algo, password)` derives key *and* IV from
   the password alone via the unsalted `EVP_BytesToKey()` (MD5-based) KDF. The
   same plaintext always encrypts to the identical ciphertext, and a single known
   plaintext/ciphertext pair reveals the keystream.

The only thing standing between an attacker and the victim's cloud credentials is
a string visible in the public GitHub repo.

## Exploit chain

```
victim logs in to Kodo Browser
      │  AuthInfoSerializer.serialize()
      ▼
cipher(JSON)  with key "x82m#*lx8vv"  (createCipher, no IV)
      │
      ▼
localStorage["auth-info"] = "<hex blob>"   (Electron app-data dir)
      │  any local process / malware / attacker with FS read
      ▼
attacker reads the blob, decrypts with the PUBLIC key
      ▼
accessKey + accessSecret recovered → full bucket access
```

## Proof-of-concept

`poc.js` replicates the exact `cipher`/`decipher` functions and proves the flaw:

```
$ node poc.js
[1] Fidelity check vs the app's own test vector
    cipher("test cipher") = d8734177789bda96d17e693599380615
    matches cipher.test.ts expectation: true
[2] Determinism (createCipher, no IV)
    cipher(x) == cipher(x)  ->  true
[4] Attacker decrypts with the PUBLIC hardcoded key
    accessKey     = AK-EXAMPLE-qiniu-access-key
    accessSecret  = SK-EXAMPLE-qiniu-secret-key
RESULT: PASS
```

The `cipher("test cipher")` output matches the app's own unit test
(`cipher.test.ts`), confirming byte-exact fidelity.

## Exploitability assessment

| Criterion | Assessment |
| --- | --- |
| Attack vector | Local — any process/malware with read access to the app's localStorage |
| Complexity | Trivial — key is public, decryption is a 5-line `createDecipher` |
| Prerequisites | Read access to the Electron app-data directory |
| Impact | Full disclosure of Qiniu cloud credentials (accessKey/accessSecret) |
| Limitation | Not remotely exploitable by itself; requires local code execution/read |

## Remediation

* Derive a per-installation key (or use OS keychain / `safeStorage` in Electron)
  instead of a compile-time constant.
* Use `crypto.createCipheriv()` with a random, per-encryption IV, and preferably
  an authenticated mode (AES-GCM).
* Migrate stored secrets to the OS credential store (`safeStorage` /
  `keytar`-style), which is what desktop clients should use for cloud credentials.

## References

- Vulnerable source: <https://github.com/qiniu/kodo-browser/blob/master/src/renderer/modules/auth/cipher.ts>
- Usage: <https://github.com/qiniu/kodo-browser/blob/master/src/renderer/modules/auth/persistence.ts>
- Test vector: <https://github.com/qiniu/kodo-browser/blob/master/src/renderer/modules/auth/cipher.test.ts>
