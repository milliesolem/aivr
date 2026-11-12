#!/usr/bin/env bash
# TunnelPicklock — real exploit against the actual cloudflared project.
# Provision: real cloudflared release 2026.10.7 checkout (driver's go.mod replace)
#            + Go module cache, then run the Python exploit orchestration.
set -u
cd "$(dirname "$0")"

export GOTOOLCHAIN=go1.27.3
export GOMODCACHE=/home/millie/tmp/audit/gomodcache
export GOCACHE=/home/millie/tmp/audit/gocache

CHECKOUT=/home/millie/tmp/audit/cloudflared-2026.10.7
if [ ! -d "$CHECKOUT/.git" ]; then
  mkdir -p /home/millie/tmp/audit
  git clone --depth 1 --branch 2026.10.7 https://github.com/cloudflare/cloudflared "$CHECKOUT" || {
    echo "FAILED to provision the vulnerable cloudflared checkout (network?)" >&2; exit 3; }
fi

exec python3 exploit.py
