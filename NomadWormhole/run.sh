#!/usr/bin/env bash
# NomadWormhole — hashicorp/nomad client sandbox escape via symlink swap.
# Drives the verbatim vulnerable (v2.1.0) and fixed (v2.1.1) makeExecutable()
# logic against a real filesystem (real symlink + real chmod on a host file).
set -u
cd "$(dirname "$0")"

GOTOOLCHAIN=local GOFLAGS=-mod=mod go run main.go
