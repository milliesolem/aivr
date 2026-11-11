#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] FrpMimic — frp OIDC missing audience (client ID) validation"
echo "[*] building (go-oidc v3.21.0, the exact library frp vendors) ..."

# go-oidc v3.21.0 needs go >= 1.25; the host ships 1.24 so let the toolchain
# auto-fetch 1.25 (or use it if already present).
export GOFLAGS=-mod=mod
unset GOTOOLCHAIN || true

timeout 180 go build -o /tmp/opencode/frpmimic.bin . 2>&1 || {
    echo "[!] build failed — retrying with explicit go1.25 toolchain" >&2
    GOTOOLCHAIN=go1.25.0 timeout 180 go build -o /tmp/opencode/frpmimic.bin . 2>&1
}

echo "[*] running ..."
timeout 60 /tmp/opencode/frpmimic.bin
