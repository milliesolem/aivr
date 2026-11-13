#!/bin/bash
# OpenssSesame — OpenSSH sshd password-auth bypass on musl libc (CVE-2026-123158).
# Compiles the faithful reproduction (real OpenSSH sys_auth_passwd/xcrypt/pick_salt/
# shadow_pw + real musl crypt()) with the musl cross toolchain and runs it.
set -e
cd "$(dirname "$0")"

MUSL_CC="${MUSL_CC:-/home/millie/tools/toolchain/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc}"

BIN=/tmp/opencode/openssesame_exploit
"$MUSL_CC" -static -O2 -o "$BIN" exploit.c
"$BIN"
