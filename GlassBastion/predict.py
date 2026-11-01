#!/usr/bin/env python3
# Recover V8 (Node/Chrome) Math.random() state from a few observed outputs and
# predict subsequent ones. V8 fills a 64-cache and returns it in reverse, so each
# consumed output walks the xorshift128+ stream backward -> we invert the step.
import json, sys
from z3 import BitVec, BitVecVal, LShR, Solver, sat

MASK = (1 << 64) - 1

def to_mant(d):
    return int(d * (1 << 52))

# forward step (concrete). double for this step = (ns0 >> 12)/2^52
def fwd(s0, s1):
    ns0 = s1
    t = s0 ^ ((s0 << 23) & MASK)
    t ^= t >> 17
    t ^= s1
    t ^= s1 >> 26
    return ns0, t & MASK

def inv_rshift_xor(y, shift):
    x = y
    while True:
        nx = y ^ (x >> shift)
        if nx == x:
            return x
        x = nx

def inv_lshift_xor(y, shift):
    x = y
    while True:
        nx = (y ^ ((x << shift) & MASK)) & MASK
        if nx == x:
            return x
        x = nx

# inverse of fwd: given (ns0, ns1) return (s0, s1)
def inv(ns0, ns1):
    s1 = ns0
    w = ns1 ^ s1 ^ (s1 >> 26)
    u = inv_rshift_xor(w, 17)
    s0 = inv_lshift_xor(u, 23)
    return s0 & MASK, s1 & MASK

def recover_state_before(gen_order):
    """z3-recover the state just before the earliest generation value fed."""
    s = Solver()
    S0, S1 = BitVec('S0', 64), BitVec('S1', 64)
    a, b = S0, S1
    for d in gen_order:
        na = b
        t = a ^ (a << 23)
        t ^= LShR(t, 17)
        t ^= b
        t ^= LShR(b, 26)
        a, b = na, t
        s.add(LShR(a, 12) == BitVecVal(to_mant(d), 64))
    assert s.check() == sat, "unsat"
    m = s.model()
    return m[S0].as_long(), m[S1].as_long()

def predict_future(observed, n_future):
    gen_order = observed[::-1]                 # oldest-generation first
    S0, S1 = recover_state_before(gen_order)   # state right before gen_order[0]
    out = []
    a, b = S0, S1
    for _ in range(n_future):
        out.append((a >> 12) / float(1 << 52)) # ToDouble(current state0) = next Node output
        a, b = inv(a, b)                        # walk backward one step
    return out

if __name__ == "__main__":
    seq = json.load(open(sys.argv[1]))
    use = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    observed, held = seq[:use], seq[use:]
    pred = predict_future(observed, len(held))
    print("fed      :", [round(x, 6) for x in observed])
    print("predicted:", [round(x, 6) for x in pred])
    print("actual   :", [round(x, 6) for x in held])
    ok = all(abs(p - a) < 1e-9 for p, a in zip(pred, held))
    print("RESULT:", "PREDICTION MATCHES real Node Math.random()" if ok else "mismatch")
