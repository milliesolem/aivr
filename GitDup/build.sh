#!/usr/bin/env bash
# Build the GitDup PoC with zig cc (links glibc, whose allocator has the double-free detector
# that git aborts on: "free(): double free detected in tcache 2").
set -e
cd "$(dirname "$0")"
ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
if [ -x "$ZIG" ]; then CC="$ZIG cc"; else CC="${CC:-cc}"; fi
$CC -O0 -g -o poc poc.c
echo "built ./poc"
