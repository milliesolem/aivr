#!/bin/bash
# XmssOverrun — real-code PoC against microsoft/SymCrypt (HEAD 286762b)
#
# Builds SymCrypt twice (vulnerable HEAD, and a patched copy where
# SymCryptXmssSetParams rejects cbHashOutput < 8), then runs the SAME
# harness against both. Vulnerable: SymCryptXmssSign segfaults (stack
# underflow write in SymCryptXmssRandomizedHash). Fixed: SetParams returns
# SYMCRYPT_INVALID_ARGUMENT cleanly.
#
# Requires (preinstalled under /home/millie/tools/toolchain on this host):
#   - zig 0.14 (zig cc)  -> /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0
#   - cmake              -> /home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
CMAKE=/home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64/bin/cmake
SYMCRYPT=/tmp/opencode/audit/SymCrypt
BUILD=/tmp/opencode/xmssoverrun-build

if [ ! -x "$ZIG" ] || [ ! -x "$CMAKE" ]; then
  echo "toolchain missing: need zig + cmake at $ZIG / $CMAKE"
  echo "falling back to the arithmetic model (exploit.py)"
  python3 "$HERE/exploit.py"
  exit 0
fi

mkdir -p /tmp/opencode
[ -d "$SYMCRYPT" ] || git clone --quiet https://github.com/microsoft/SymCrypt "$SYMCRYPT"

cat > /tmp/opencode/zigcc.sh  << EOF
#!/bin/bash
exec $ZIG cc "\$@"
EOF
cat > /tmp/opencode/zigcxx.sh << EOF
#!/bin/bash
exec $ZIG c++ "\$@"
EOF
cat > /tmp/opencode/zigar.sh  << EOF
#!/bin/bash
exec $ZIG ar "\$@"
EOF
cat > /tmp/opencode/zigranlib.sh << EOF
#!/bin/bash
exec $ZIG ar s "\$@"
EOF
chmod +x /tmp/opencode/zig*.sh

build_lib() {  # $1 = build dir
  rm -rf "$1"
  "$CMAKE" -S "$SYMCRYPT" -B "$1" \
    -DSYMCRYPT_USE_ASM=OFF -DSYMCRYPT_UNIT_TESTS=OFF -DSYMCRYPT_BUILD_MODULES=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=/tmp/opencode/zigcc.sh \
    -DCMAKE_CXX_COMPILER=/tmp/opencode/zigcxx.sh \
    -DCMAKE_AR=/tmp/opencode/zigar.sh \
    -DCMAKE_RANLIB=/tmp/opencode/zigranlib.sh > /dev/null 2>&1
  "$CMAKE" --build "$1" -j 6 > /dev/null 2>&1 || { echo "build $1 failed"; exit 1; }
}

cd "$SYMCRYPT" || exit 1
git checkout --quiet -- lib/xmss.c
build_lib "$BUILD-vuln"

# fix: reject n < 8 (RandomizedHash writes 8 bytes at idxBuf[n-8])
sed -i 's/if (cbHashOutput == 0 ||/if (cbHashOutput < sizeof(UINT64) ||/' "$SYMCRYPT/lib/xmss.c"
build_lib "$BUILD-fixed"
git checkout --quiet -- lib/xmss.c

CC=/tmp/opencode/zigcc.sh
INC=-I"$SYMCRYPT/inc"
VULN_LIBS="$BUILD-vuln/lib/libsymcrypt_common.a $BUILD-vuln/lib/libsymcrypt_mlkem.a $BUILD-vuln/lib/libsymcrypt_generic.a"
FIXED_LIBS="$BUILD-fixed/lib/libsymcrypt_common.a $BUILD-fixed/lib/libsymcrypt_mlkem.a $BUILD-fixed/lib/libsymcrypt_generic.a"

$CC -O1 -DSYMCRYPT_IGNORE_PLATFORM $INC "$HERE/xmss_crash.c" $VULN_LIBS -latomic -o "$HERE/xmss_crash_vuln" || exit 1
$CC -O1 -DSYMCRYPT_IGNORE_PLATFORM $INC "$HERE/xmss_crash.c" $FIXED_LIBS -latomic -o "$HERE/xmss_crash_fixed" || exit 1

echo
echo "=== VULNERABLE SymCrypt (HEAD 286762b) — custom XMSS params n=4"
timeout 120 "$HERE/xmss_crash_vuln" || echo ">>> VULNERABLE BUILD: SymCryptXmssSign SEGFAULTED (rc=$?) — stack underflow write in SymCryptXmssRandomizedHash"
echo
echo "=== FIXED SymCrypt (n < 8 rejected) — same harness"
timeout 120 "$HERE/xmss_crash_fixed" && echo ">>> FIXED BUILD: SymCryptXmssSetParams returned INVALID_ARGUMENT (0x800e) — no crash"
