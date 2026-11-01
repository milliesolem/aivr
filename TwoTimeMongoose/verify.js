#!/usr/bin/env node
'use strict'
/* Ground-truth check: confirm the attacker's secret-free recovery matches what the
 * REAL library produces when it decrypts with the actual secret. */
const fs = require('fs')
function loadLib () {
  try { return require('mongoose-field-encryption') }
  catch (e) { return require('./vendored/mongoose-field-encryption.js') }
}
const { decrypt } = loadLib()

const gt = JSON.parse(fs.readFileSync('.ground_truth.json', 'utf8'))
const db = JSON.parse(fs.readFileSync('encrypted_db.json', 'utf8'))
const rec = JSON.parse(fs.readFileSync('.recovered.json', 'utf8'))

let ok = 0, total = 0
for (const r of db.records) {
  const truth = {
    email: decrypt(r.email_enc, gt.secret),
    ssn: decrypt(r.ssn_enc, gt.secret),
    card: decrypt(r.card_enc, gt.secret),
  }
  const got = rec.find(x => x.id === r.id)
  for (const f of ['email', 'ssn', 'card']) {
    total++
    if (got[f] === truth[f]) ok++
    else console.log(`  MISMATCH id=${r.id} ${f}: attacker="${got[f]}" truth="${truth[f]}"`)
  }
}
console.log(`[verify] attacker-recovered fields matching the library's true decryption: ${ok}/${total}`)
process.exit(ok === total ? 0 : 1)
