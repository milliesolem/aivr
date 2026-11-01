#!/usr/bin/env node
'use strict'
/*
 * The *victim* side: a developer protecting their secrets exactly as the secure-env
 * README instructs.  This script uses the REAL secure-env code to produce `.env.enc`.
 *
 * It prefers the published npm package (`secure-env`); if that is not installed it
 * falls back to the byte-identical copy of secure-env@1.2.0 vendored under
 * ./secure_env_vendored/ so the PoC still runs fully offline.
 *
 * Usage: node victim_encrypt.js <inputEnv> <outputEnc> [secret]
 *        (omit [secret] to exercise secure-env's hard-coded default key "mySecret")
 */
const fs = require('fs')
const path = require('path')

function loadSecureEnvCrypto () {
  try {
    return require('secure-env/dist/es5/lib/cryptography.js') // the real npm package
  } catch (e) {
    return require('./secure_env_vendored/cryptography.js')   // verbatim offline copy
  }
}

const { encrypt } = loadSecureEnvCrypto()

const inputFile = process.argv[2] || '.env'
const outputFile = process.argv[3] || inputFile + '.enc'
const secret = process.argv[4] // undefined -> secure-env uses 'mySecret'

const opts = { inputFile, outputFile }
if (secret !== undefined) opts.secret = secret

if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile)
encrypt(opts)

// encrypt() is stream-based and emits no awaitable handle; poll for completion.
const started = Date.now()
;(function wait () {
  if (fs.existsSync(outputFile) && fs.statSync(outputFile).size > 16) {
    console.log(`[victim] secure-env encrypted ${inputFile} -> ${outputFile} ` +
                `(${fs.statSync(outputFile).size} bytes)` +
                (secret === undefined ? ' using DEFAULT key "mySecret"' : ` using secret "${secret}"`))
    process.exit(0)
  }
  if (Date.now() - started > 5000) {
    console.error('[victim] encryption timed out'); process.exit(1)
  }
  setTimeout(wait, 30)
})()
