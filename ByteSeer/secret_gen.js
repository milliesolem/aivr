// Generate a 24-byte "API key" with the real npm `crypt` package — the same
// Math.random()-based randomBytes that has shipped since 2011 (~24M weekly
// downloads). The first 18 bytes "leak" (e.g. a hex prefix in logs or a URL).
const crypt = require("crypt");

const bytes = crypt.randomBytes(24);
const key = Buffer.from(bytes);
console.log("FULL_KEY: " + key.toString("hex"));
console.log("LEAKED_PREFIX: " + key.subarray(0, 18).toString("hex"));
