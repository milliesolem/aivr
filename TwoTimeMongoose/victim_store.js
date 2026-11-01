#!/usr/bin/env node
'use strict'
/*
 * VICTIM side — a Mongoose/MongoDB app encrypting sensitive user fields with
 * mongoose-field-encryption's AES-256-CTR mode.
 *
 * This is the real, supported configuration:
 *   - it was the DEFAULT (and only) algorithm in every 1.x release, and
 *   - it is still selectable today via `fieldEncryption({ ..., useAes256Ctr: true })`,
 *     and current versions still auto-decrypt this legacy ciphertext.
 *
 * We call the package's own exported `encryptAes256Ctr(text, secret)` so the
 * ciphertext is byte-for-byte what the library (and thus the database) stores.
 * Prefers the published npm package; falls back to the vendored verbatim copy.
 *
 * Output: encrypted_db.json — a "stolen database dump". It contains ONLY the
 * encrypted field values (hex). The secret is never written to it.
 */
const fs = require('fs')

function loadLib () {
  try { return require('mongoose-field-encryption') }
  catch (e) { return require('./vendored/mongoose-field-encryption.js') }
}
const { encryptAes256Ctr, decrypt } = loadLib()

// The app's single field-encryption secret (as a developer would configure it).
const SECRET = 'prod-mongoose-field-secret-2026'

// Plaintext records (what really lives in the application).
const USERS = [
  { id: 1, name: 'Alice Nguyen',  email: 'alice.nguyen@hospital.org',      ssn: 'SSN:123-45-6789', card: 'CARD:4111111111111111' },
  { id: 2, name: 'Bob Carter',    email: 'bob.carter@hospital.org',        ssn: 'SSN:222-33-4444', card: 'CARD:5500005555555559' },
  { id: 3, name: 'Mallory Stone', email: 'attacker.mallory@evilcorp.test', ssn: 'SSN:999-88-7777', card: 'CARD:340000000000009'  },
  { id: 4, name: 'Dana Lopez',    email: 'dana.lopez@hospital.org',        ssn: 'SSN:456-78-9012', card: 'CARD:6011000990139424' },
]

// Encrypt the sensitive columns exactly as the library's pre-save hook would.
const encRecords = USERS.map(u => ({
  id: u.id,
  name: u.name, // say the app chose not to encrypt the display name
  email_enc: encryptAes256Ctr(u.email, SECRET),
  ssn_enc:   encryptAes256Ctr(u.ssn,   SECRET),
  card_enc:  encryptAes256Ctr(u.card,  SECRET),
}))

fs.writeFileSync('encrypted_db.json', JSON.stringify({ records: encRecords }, null, 2))

// Ground-truth file (NOT used by the attacker) so run_poc.sh can verify correctness.
fs.writeFileSync('.ground_truth.json', JSON.stringify({ secret: SECRET, users: USERS }, null, 2))

console.log(`[victim] encrypted ${USERS.length} users' {email,ssn,card} with AES-256-CTR via mongoose-field-encryption`)
console.log(`[victim] wrote encrypted_db.json (the "leaked" dump) — secret stays only with the victim`)
// sanity: the library decrypts its own output
const back = decrypt(encRecords[0].email_enc, SECRET)
console.log(`[victim] self-check: library decrypt(email_enc[0]) = "${back}"`)
