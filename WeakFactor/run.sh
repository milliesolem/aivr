#!/usr/bin/env bash
# WeakFactor PoC — predict a volto-tfa TOTP secret from leaked Math.random() outputs.
set -u
cd "$(dirname "$0")"

# hi-base32 is the exact base32 library volto-tfa uses; install it locally (gitignored).
if [ ! -d node_modules/hi-base32 ]; then
  echo "[*] installing hi-base32 (first run only) ..."
  timeout 120 npm install --silent >/dev/null 2>&1 || { echo "npm install failed"; exit 1; }
fi

# The attacker's state-recovery step needs z3.
python3 -c "import z3" 2>/dev/null || {
  echo "[*] installing z3-solver ..."
  timeout 120 pip install --break-system-packages -q z3-solver >/dev/null 2>&1 || true; }

node poc.js
