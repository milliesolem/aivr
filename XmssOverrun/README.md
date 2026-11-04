# XmssOverrun — CWE-787 stack underflow write in SymCryptXmssRandomizedHash

| Product + version        | CVSS 3.1                                    | CWE            |
|--------------------------|---------------------------------------------|----------------|
| microsoft/SymCrypt @ `286762b` (v103.13.0, HEAD) | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **6.2 MEDIUM** | **CWE-787** (stack out-of-bounds write) |

**Status:** 0-day at HEAD — `lib/xmss.c:1514` is live upstream.

## The bug

`SymCryptXmssSetParams` accepts custom XMSS parameter sets with a hash output
length `n` (`cbHashOutput`) as small as **1 byte** — the only validation
(`lib/xmss.c:393`) is *nonzero, ≤ hash result size, ≤ 64*:

```c
if (cbHashOutput == 0 ||
    cbHashOutput > pHash->resultSize ||
    cbHashOutput > SYMCRYPT_HASH_MAX_RESULT_SIZE)   // SHA-256 resultSize=32 -> n=4 accepted
```

`SymCryptXmssRandomizedHash` then computes the index position as
`cbHashOutput - sizeof(Idx)` on a 64-byte stack buffer:

```c
// lib/xmss.c:1511-1514
BYTE idxBuf[SYMCRYPT_HASH_MAX_RESULT_SIZE];                 // 64 bytes
...
SYMCRYPT_STORE_MSBFIRST64(&idxBuf[pParams->cbHashOutput - sizeof(Idx)], Idx);
//                                     n - 8  ->  NEGATIVE index for n < 8
```

With `n = 4` the 8-byte big-endian sign index is written at `idxBuf[-4]`:
4 bytes BELOW the buffer, into the slot holding the spilled `pbMsg` pointer
(critic-verified in the compiled function: the Idx store at `rbp-0x1a4`
overwrites the pointer spill at `rbp-0x1a8`). The sign index's upper bytes
are 0, so the store **zeroes the pointer's high 4 bytes** — a deterministic
64->32-bit pointer truncation — and the subsequent SHA-256 append reads from
the truncated address and crashes. The first 4 bytes of `idxBuf` are also
overwritten (low bytes of the index).

This is the same bug class Microsoft just fixed as issue #56 in the same file
(commit `2b930b4`, v103.13.0: "Add bounds check on cbPrefix for custom XMSS
parameter sets"): a **custom-parameter validation gap in the XMSS code**. The
randomized-hash length gap was left unfixed.

## Reachability (threat model, stated honestly)

Custom parameter sets are an explicitly supported public feature
(`SymCryptXmssSetParams` is the documented API for them; the changelog and the
#56 fix show Microsoft treats validation gaps there as security bugs). The
trigger is a caller that creates a custom XMSS parameter set with `n` 1..7
(e.g. 4) and signs — the library accepts the parameters and then corrupts its
own stack. A remote attacker influences this only if an application exposes
custom XMSS parameter configuration; the direct precondition is a local
caller choosing `n < 8`. That is the honest scope of this finding: a real
memory-safety bug in the supported custom-parameter path, not a remote
exploit primitive.

## PoC (real code — compiled from source)

```
bash run.sh
```

`run.sh` compiles SymCrypt HEAD (vulnerable) and a patched copy (SetParams
rejects `n < 8`) with zig cc and runs the same harness against both:

- **VULNERABLE build:** `SymCryptXmssSetParams(n=4)` -> `SYMCRYPT_NO_ERROR`,
  keygen succeeds, then `SymCryptXmssSign` **segfaults** (SIGSEGV, rc=139).
- **FIXED build:** `SymCryptXmssSetParams(n=4)` -> `SYMCRYPT_INVALID_ARGUMENT`
  (0x800e); no crash.

Same caller code; only the parameter validation differs.

`exploit.py` additionally models the exact index arithmetic
(`idxBuf[n - 8]`) and shows which bytes of the stack frame the 8-byte write
corrupts for each `n` in 1..7 (the below-buffer bytes are the spilled
`pbMsg` pointer slot in the compiled function — see the critic note above).

## Fix

Reject tiny hash outputs in `SymCryptXmssSetParams` (mirroring the #56
cbPrefix fix):

```c
if (cbHashOutput < sizeof(UINT64) ||          // RandomizedHash writes 8 bytes at idxBuf[n-8]
    cbHashOutput > pHash->resultSize ||
    cbHashOutput > SYMCRYPT_HASH_MAX_RESULT_SIZE)
{
    scError = SYMCRYPT_INVALID_ARGUMENT;
    goto cleanup;
}
```

## Remediation

Add the `n >= 8` validation to `SymCryptXmssSetParams` (and audit the sibling
LMS/Winternitz paths for the same `n - sizeof(...)` index pattern; `lms.c`
uses fixed 4-byte indices but is worth the same review).
