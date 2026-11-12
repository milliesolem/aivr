#!/usr/bin/env bash
# ZeroSesame — real exploit against the actual go-zero project (v1.9.4).
#
# The driver imports the REAL vulnerable github.com/zeromicro/go-zero
# zrpc/internal/auth.Authenticator (v1.9.4, the latest release), builds it from
# the actual source, and calls its Authenticate() method — the exact code path
# the real UnaryAuthorizeInterceptor invokes on every RPC — against a faithful
# RESP Redis (miniredis).  An UNKNOWN app name (or any Redis error) fails open
# and is reported as authenticated.
set -u
cd "$(dirname "$0")"

CHECKOUT=/home/millie/tmp/audit/go-zero-v1.9.4
if [ ! -d "$CHECKOUT/.git" ]; then
  mkdir -p /home/millie/tmp/audit
  git clone --depth 1 --branch v1.9.4 https://github.com/zeromicro/go-zero "$CHECKOUT" || {
    echo "FAILED to provision the vulnerable go-zero checkout (network?)" >&2
    exit 3
  }
fi

# Install the exploit driver into the checkout.  The internal/auth package may
# only be imported from within the go-zero module tree, so the driver lives at
# zrpc/poc inside the real repo.
mkdir -p "$CHECKOUT/zrpc/poc"
cp driver/main.go "$CHECKOUT/zrpc/poc/main.go"

export GOTOOLCHAIN=local
export GOFLAGS=-mod=mod
export GOPROXY=off
export GOMODCACHE=/home/millie/tmp/audit/gomodcache
export GOCACHE=/home/millie/tmp/audit/gocache
export TMPDIR=/home/millie/tmp/audit/gotmp

cd "$CHECKOUT"
exec go run ./zrpc/poc
