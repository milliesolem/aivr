#!/usr/bin/env bash
# FourierOverrun — onnxruntime STFT unvalidated-rank std::terminate() DoS
# exit 0 = reproduced (control clean + both rank-mismatch triggers SIGABRT)
set -u
cd "$(dirname "$0")"

VENV="${ORT_VENV:-/tmp/opencode/aivr-venv}"

if [ ! -x "$VENV/bin/python" ]; then
  echo "[*] creating venv $VENV"
  timeout 120 python3 -m venv "$VENV" || { echo "venv creation failed"; exit 2; }
fi

needs_install=0
"$VENV/bin/python" -c "import onnxruntime, onnx" 2>/dev/null || needs_install=1
if [ "$needs_install" = "1" ]; then
  echo "[*] installing onnxruntime numpy onnx"
  tries=0
  while [ "$tries" -lt 2 ]; do
    tries=$((tries + 1))
    if timeout 240 "$VENV/bin/pip" install --quiet --disable-pip-version-check onnxruntime numpy onnx; then
      break
    fi
    echo "[!] pip attempt $tries failed, retrying"
  done
  "$VENV/bin/python" -c "import onnxruntime, onnx" 2>/dev/null || { echo "dependency install failed"; exit 2; }
fi

"$VENV/bin/python" -c "import onnxruntime; print('[+] onnxruntime', onnxruntime.__version__)"
"$VENV/bin/python" make_model.py || exit 2
"$VENV/bin/python" exploit.py
