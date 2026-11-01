// Independent check: does the attacker's secret-free recovery (Attack 1) match
// the victim's real plaintext and the key the real library actually used?
const fs = require("fs");
const truth = JSON.parse(fs.readFileSync(__dirname + "/.victim_truth.json"));
const rec = JSON.parse(fs.readFileSync(__dirname + "/.recovered.json"));

let ok = 0, total = 0;
for (const [k, v] of Object.entries(truth.plaintext)) {
  total++;
  const got = rec.recovered["@secure.s." + k];
  if (got === v) ok++;
  console.log(`    ${k.padEnd(16)} expected=${JSON.stringify(v)} recovered=${JSON.stringify(got)} ${got === v ? "OK" : "MISMATCH"}`);
}
const keyMatch = rec.key === truth.trueSecureKey;
console.log(`[verify] attacker key == library's real key: ${keyMatch} (${rec.key})`);
console.log(`[verify] fields recovered by the attacker (no secret): ${ok}/${total}`);
process.exit(ok === total && keyMatch ? 0 : 1);
