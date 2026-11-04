#!/usr/bin/env bash
# LeroPickle — reproduce LeRobot learner gRPC SendInteractions pickle.load RCE.
set -uo pipefail
cd "$(dirname "$0")"

echo "== LeroPickle: LeRobot learner SendInteractions pickle deserialization RCE =="

# Runtime deps (grpcio + protobuf) are already installed; guard against absence.
python3 - <<'PY'
try:
    import grpc, google.protobuf  # noqa
except ImportError as e:
    raise SystemExit(f"missing runtime dep: {e}  (run: pip install --break-system-packages grpcio protobuf)")
PY

timeout 60 python3 exploit.py
exit $?
