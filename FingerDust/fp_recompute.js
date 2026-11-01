// Attacker-side re-implementation of react-secure-storage's key derivation.
//
// This is a straight port of the library's own (open-source) logic:
//   secureKey = String( murmurhash3_32( fingerprintString, 256 ) ) + HASH_KEY
//
// It uses the SAME public npm module the library uses (murmurhash-js) so the
// hash is bit-identical. Correctness is proven at runtime: feeding the right
// inputs reproduces the key that decrypts the library's real ciphertext.
//
// Upstream references:
//   fingerprint.ts      -> secureKey = clientJS.getFingerprint() + HASH_KEY
//   fingerprint.lib.ts  -> getFingerprint() concatenates public attributes,
//                          then: murmurhash3_32_gc(key, 256)   // 32-bit output
const murmur = require("murmurhash-js/murmurhash3_gc");

// Hardcoded in the library for every install that doesn't set an env override.
const HASH_KEY = "E86E2612010258B35137";
const MURMUR_SEED = 256;

// Rebuild the exact string fingerprint.lib.ts#getFingerprint() concatenates.
// `env` carries the per-browser inputs; everything else is constant in the lib.
function fingerprintString(env) {
  const bar = "|";
  let key = "";
  key += env.userAgent + bar; // navigator.userAgent
  key += env.hostname + bar; // window.location.hostname
  key += `Color Depth: ${env.colorDepth}, Device XDPI: , Device YDPI: ` + bar; // getScreenPrint()
  key += (env.plugins || "") + bar; // getPlugins() -> "" on modern browsers
  key += (env.fonts || "") + bar; // getFonts()   -> always "" (detection is disabled upstream)
  key += "true" + bar; // isLocalStorage()
  key += "true" + bar; // isSessionStorage()
  key += env.timezone + bar; // getTimeZone() e.g. "-05"
  key += env.language + bar; // getLanguage()
  key += env.systemLanguage + bar; // getSystemLanguage()
  key += (env.cookieEnabled === false ? "false" : "true") + bar; // isCookie()
  key += env.canvas; // getCanvasPrint() (no trailing bar)
  if (key.endsWith(bar)) key = key.substring(0, key.length - 1);
  return key;
}

function fingerprintInt(env) {
  return murmur(fingerprintString(env), MURMUR_SEED) >>> 0;
}

// The full AES passphrase the library hands to CryptoJS.
function secureKeyFromEnv(env) {
  return String(fingerprintInt(env)) + HASH_KEY;
}

// The full AES passphrase for a raw 32-bit murmur value (used by brute force).
function secureKeyFromInt(n) {
  return String(n >>> 0) + HASH_KEY;
}

module.exports = {
  HASH_KEY,
  MURMUR_SEED,
  fingerprintString,
  fingerprintInt,
  secureKeyFromEnv,
  secureKeyFromInt,
};
