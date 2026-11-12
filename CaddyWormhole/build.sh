#!/usr/bin/env bash
# CaddyWormhole — build the REAL vulnerable (v2.11.9) and fixed (master) Caddy binaries.
#
# Produces two full, unmodified `cmd/caddy` binaries:
#   $CACHE/caddy-vuln.bin   (tag v2.11.9 — the last public release, still vulnerable)
#   $CACHE/caddy-fixed.bin  (master @ fc6c202ea6 — carries the path-canonicalization fix)
#
# Everything is cached under /home/millie/tmp/aivr-caddy so the PoC can be re-run
# offline (run.sh calls this only when the binaries are missing).
set -u
CACHE="${AIVR_CADDY_CACHE:-/home/millie/tmp/aivr-caddy}"
mkdir -p "$CACHE"

export GOTOOLCHAIN=auto
export GOFLAGS=-mod=mod
export GOCACHE="${GOCACHE:-/home/millie/tmp/gocache}"
export GOTMPDIR="${GOTMPDIR:-/home/millie/tmp/gotmp}"
export GOMODCACHE="${GOMODCACHE:-/home/millie/go/pkg/mod}"
mkdir -p "$GOCACHE" "$GOTMPDIR"

clone() {  # $1=name  $2=url  $3=branch
  if [ ! -d "$CACHE/$1/.git" ]; then
    echo "[build] cloning $1 ($3) ..."
    git clone --depth 1 --branch "$3" "$2" "$CACHE/$1" || return 1
  fi
}

build() {  # $1=name  $2=out
  echo "[build] compiling $1 (this is the actual caddyserver/caddy cmd/caddy) ..."
  ( cd "$CACHE/$1/cmd/caddy" && \
    timeout 400 go build -o "$2" . ) || return 1
}

clone caddy-vuln  https://github.com/caddyserver/caddy.git v2.11.9 || exit 3
clone caddy-fixed https://github.com/caddyserver/caddy.git master     || exit 3

[ -x "$CACHE/caddy-vuln.bin" ]  || build caddy-vuln  "$CACHE/caddy-vuln.bin"  || exit 3
[ -x "$CACHE/caddy-fixed.bin" ] || build caddy-fixed "$CACHE/caddy-fixed.bin" || exit 3

echo "[build] done:"
ls -la "$CACHE/caddy-vuln.bin" "$CACHE/caddy-fixed.bin"
