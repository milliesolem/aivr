#!/usr/bin/env python3
"""Recover V8 (Node/Chrome) Math.random() state from observed outputs and predict
future ones. V8 fills a 64-value cache and returns it in REVERSE, so each consumed
output walks the xorshift128+ stream backward -> we invert the step.

Usage: v8_predict.py <leaked.json> <n_future>
Prints JSON: the mantissa integers (state0>>12) of the next <n_future> outputs, so
the caller can rebuild the exact IEEE-754 double V8 returned as mantissa * 2**-52.
"""
import json, sys
from z3 import BitVec, BitVecVal, LShR, Solver, sat

MASK = (1 << 64) - 1

def inv_rshift_xor(y, s):
    x = y
    while True:
        nx = y ^ (x >> s)
        if nx == x: return x
        x = nx

def inv_lshift_xor(y, s):
    x = y
    while True:
        nx = (y ^ ((x << s) & MASK)) & MASK
        if nx == x: return x
        x = nx

def inv(ns0, ns1):                 # inverse of one xorshift128+ step
    s1 = ns0
    w = ns1 ^ s1 ^ (s1 >> 26)
    s0 = inv_lshift_xor(inv_rshift_xor(w, 17), 23)
    return s0 & MASK, s1 & MASK

def recover_state_before(gen_order):
    s = Solver()
    S0, S1 = BitVec('S0', 64), BitVec('S1', 64)
    a, b = S0, S1
    for d in gen_order:
        na = b
        t = a ^ (a << 23)
        t ^= LShR(t, 17); t ^= b; t ^= LShR(b, 26)
        a, b = na, t
        s.add(LShR(a, 12) == BitVecVal(int(d * (1 << 52)), 64))
    assert s.check() == sat, "unsat: need more/consecutive outputs"
    m = s.model()
    return m[S0].as_long(), m[S1].as_long()

def predict_mantissas(observed, n_future):
    a, b = recover_state_before(observed[::-1])
    out = []
    for _ in range(n_future):
        out.append(a >> 12)        # mantissa; double = mantissa * 2**-52
        a, b = inv(a, b)
    return out

if __name__ == "__main__":
    leaked = json.load(open(sys.argv[1]))
    n = int(sys.argv[2])
    print(json.dumps(predict_mantissas(leaked, n)))
