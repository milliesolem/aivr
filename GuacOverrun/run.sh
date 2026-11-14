#!/usr/bin/env bash
# GuacOverrun — Apache Guacamole SSH agent sign-request heap OOB read (CWE-125).
set -u
cd "$(dirname "$0")"

ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
if [ -n "${CC:-}" ]; then
  "$CC" -O1 -o guac_ssh_agent_oob guac_ssh_agent_oob.c || { echo "compile failed"; exit 2; }
elif [ -x "$ZIG" ]; then
  "$ZIG" cc -O1 -o guac_ssh_agent_oob guac_ssh_agent_oob.c || { echo "compile failed"; exit 2; }
else
  cc -O1 -o guac_ssh_agent_oob guac_ssh_agent_oob.c || { echo "no C compiler"; exit 2; }
fi

OUT="$(./guac_ssh_agent_oob 2>&1)"
RC=$?
echo "$OUT"

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "GUAC-SSH-AGENT-OOB: HEAP OUT-OF-BOUNDS READ CONFIRMED"; then
  exit 0
fi
exit 1
