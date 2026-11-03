#!/bin/bash
# NapLotto — NapCatQQ WebUI credential HMAC key recovery via OneBot echo oracle
# Starts the faithful Node demo server (real key-derivation + validation code),
# runs the Python attack (V8 state recovery + credential forgery), kills server.
# The port is unique per run ($$) so concurrent runs/gates never cross-talk.
cd "$(dirname "$0")" || exit 1

PORT=$((19300 + ($$ % 300)))
export NAPLOTTO_PORT=$PORT
BASE="http://127.0.0.1:$PORT"

node server.js > /tmp/naplotto_server.log 2>&1 &
SERVER_PID=$!

cleanup() { kill "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT

# bounded wait for the server
for i in $(seq 1 30); do
  if curl -s -o /dev/null "$BASE/echo"; then break; fi
  sleep 0.2
done

python3 attack.py "$PORT"
RC=$?
cat /tmp/naplotto_server.log
exit $RC
