#!/usr/bin/env node
'use strict'
/* Quantify how little work secure-env's KDF forces an attacker to do. */
const crypto = require('crypto')
const { benchmarkHashRate } = require('./attacker_crack.js')

const rate = benchmarkHashRate()
console.log(`\n[bench] secure-env KDF = 1x SHA-256 (no salt, no stretching)`)
console.log(`[bench] This machine tests ~${rate.toLocaleString()} passwords/sec on ONE CPU core (plain Node).`)
console.log(`[bench]   -> a GPU rig (hashcat, SHA-256) does 10s of BILLIONS/sec.`)

// Time ONE guess under a *correct* KDF for comparison.
const t0 = process.hrtime.bigint()
crypto.scryptSync('guess', crypto.randomBytes(16), 32, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
const scryptMs = Number(process.hrtime.bigint() - t0) / 1e6
console.log(`\n[bench] One guess under scrypt(N=16384) = ${scryptMs.toFixed(2)} ms`)
console.log(`[bench] Slowdown factor vs secure-env   ~= ${Math.round((scryptMs / 1000) * rate).toLocaleString()}x`)

const spaces = [
  ['4-digit PIN', 1e4],
  ['6-digit PIN', 1e6],
  ['top-10k passwords', 1e4],
  ['rockyou (14.3M)', 14344391]
]
console.log(`\n[bench] Offline exhaustion time at ${rate.toLocaleString()} guesses/s (single core):`)
for (const [name, n] of spaces) {
  const s = n / rate
  const human = s < 1 ? `${(s * 1000).toFixed(1)} ms` : s < 120 ? `${s.toFixed(1)} s` : `${(s / 60).toFixed(1)} min`
  console.log(`[bench]   ${name.padEnd(22)} ${n.toLocaleString().padStart(12)} guesses  ->  ${human}`)
}
