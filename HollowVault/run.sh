#!/bin/bash
# HollowVault PoC — fully offline, no npm install, Node built-ins only.
set -e
cd "$(dirname "$0")"

echo "#############################################################"
echo "# HollowVault — Bruno secret-store decryption (machine-id key + zero IV)"
echo "#############################################################"
echo
echo "----- 1/3  victim stores secrets via Bruno's own encryption code -----"
timeout 60 node victim_bruno.js
echo
echo "----- 2/3  attacker recovers them with only the public machine-id -----"
timeout 60 node attacker_decrypt.js
echo
echo "----- 3/3  verify against ground truth + Bruno's decryptString --------"
timeout 60 node verify.js
