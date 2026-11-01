// VICTIM side. Runs the REAL, unmodified `react-secure-storage` npm package
// (see node_modules/react-secure-storage) inside a normal browser profile and
// stores sensitive values the way an app would. It then writes out:
//
//   leaked_localstorage.json  -> the encrypted localStorage (what an attacker
//                                who gets a profile backup / sync blob / stolen
//                                laptop / read-only XSS would obtain)
//   public_intel.json         -> data an attacker already has for free: the
//                                User-Agent (in every HTTP request & access
//                                log), the site hostname, and Accept-Language.
//   .victim_truth.json        -> ground truth (true key + plaintext) used ONLY
//                                by verify steps, never by the attacker.
//
// The attacker scripts never import react-secure-storage and are never given
// the key, the timezone, the color depth, or the canvas value.

const fs = require("fs");
const path = require("path");
const { installBrowserEnv } = require("./browser_env");

// A concrete, ordinary desktop browser profile. Everything here is either
// public (UA, hostname) or extremely low-cardinality (colorDepth, language,
// timezone) or constant-per-platform (canvas).
const PROFILE = {
  userAgent:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  hostname: "app.example-bank.test",
  colorDepth: 24,
  language: "en-US",
  // A representative canvas fingerprint data URL for Chrome-on-Windows. In a
  // real browser this exact string is produced by every user on the same
  // OS/browser/GPU family, so it is shared across a whole population of users.
  canvasDataUrl:
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAAB4CAYAAACL-" +
    "WIN10-CHROME-INTEL-UHD-CANVAS-RENDER-CLUSTER-0007",
  cookieEnabled: true,
};

// TZ is fixed by run.sh (Etc/GMT+5) so the fingerprint is reproducible.
installBrowserEnv(PROFILE);

// Load the real library AFTER globals exist (it reads them at import time).
const secureStorage = require("react-secure-storage").default;

const SECRETS = {
  auth_token: "EXAMPLE-not-a-real-key-session-7f3a9c21b4e8",
  account_number: "GB29-NWBK-6016-1331-9268-19",
  ssn: "SSN:078-05-1120",
  balance: "1375522.40",
};

secureStorage.clear();
for (const [k, v] of Object.entries(SECRETS)) {
  secureStorage.setItem(k, v);
}

// Dump the encrypted localStorage exactly as it sits on disk.
const dump = {};
for (const [k, v] of Object.entries(global.localStorage)) {
  if (typeof v === "string") dump[k] = v;
}

const outDir = __dirname;
fs.writeFileSync(
  path.join(outDir, "leaked_localstorage.json"),
  JSON.stringify(dump, null, 2)
);

// What an attacker gets for free from HTTP traffic / logs.
fs.writeFileSync(
  path.join(outDir, "public_intel.json"),
  JSON.stringify(
    {
      note: "attacker-observable data (server access logs + request headers)",
      userAgent: PROFILE.userAgent,
      hostname: PROFILE.hostname,
      acceptLanguage: PROFILE.language,
    },
    null,
    2
  )
);

// Ground truth for verification ONLY (never read by the attacker).
const getFingerprint = require("react-secure-storage/dist/fingerprint").default;
fs.writeFileSync(
  path.join(outDir, ".victim_truth.json"),
  JSON.stringify(
    { trueSecureKey: getFingerprint(), plaintext: SECRETS, profile: PROFILE },
    null,
    2
  )
);

console.log("[victim] stored", Object.keys(SECRETS).length, "secrets with the REAL react-secure-storage");
console.log("[victim] wrote leaked_localstorage.json (encrypted) and public_intel.json");
console.log("[victim] sample ciphertext (auth_token):");
const sampleKey = Object.keys(dump).find((k) => k.includes("auth_token"));
console.log("         " + dump[sampleKey]);
