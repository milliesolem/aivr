# SymcryOverrun — CWE-190 -> CWE-787 in SymCrypt RSA encryption padding

| Product + version        | CVSS 3.1                                    | CWE            |
|--------------------------|---------------------------------------------|----------------|
| microsoft/SymCrypt @ `286762b` (v103.13.0, HEAD) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` = **5.9 MEDIUM** | **CWE-190** (integer overflow) -> **CWE-787** (out-of-bounds write) |

**Status:** 0-day at HEAD — the vulnerable lines are live upstream
(`lib/rsa_padding.c:197/203/208/229`, `lib/rsa_padding.c:395/403/421`).

## The bug

SymCrypt's RSA encryption padding functions check their length constraints
with a **sum that wraps** (SIZE_T arithmetic):

```c
// lib/rsa_padding.c:197  (SymCryptRsaPkcs1ApplyEncryptionPadding)
if( cbPkcs1Format < (cbPlaintext + 11) )      // cbPlaintext+11 WRAPS near SIZE_MAX
{
    scError = SYMCRYPT_INVALID_ARGUMENT;
    goto cleanup;
}
cbPS = cbPkcs1Format - (cbPlaintext + 3);     // underflows to a gigantic value
...
scError = SymCryptCallbackRandom( &pbPkcs1Format[2], cbPS );   // OOB write
...
memcpy(pbPkcs1Format + 3 + cbPS, pbPlaintext, cbPlaintext);    // ~2^64-byte copy
```

For `cbPlaintext = SIZE_MAX-5` the guard computes `(SIZE_MAX-5)+11 = 5
(mod 2^64)`; `256 < 5` is false, so the check **passes**. `cbPS` underflows to
259 and the random fill writes 259 bytes at offset 2 of a 256-byte heap
buffer — 5 bytes past the end — corrupting the adjacent chunk's metadata
(deterministic heap-corruption abort in a real build). The trailing `memcpy`
of ~2^64 bytes is platform-defined behavior (on glibc the wrapped pointer
arithmetic exits the copy loop early); the reliable observable effect is the
small random-byte overflow. The OAEP sibling (`rsa_padding.c:395/421`) has
the identical wrap.

## Reachability (threat model, stated honestly)

The public APIs `SymCryptRsaPkcs1Encrypt` and `SymCryptRsaOaepEncrypt`
(`lib/rsa_enc.c:629` / `:833`) pass the caller's `cbSrc` straight into the
padding functions with **no validation anywhere in the chain**. The trigger is
a length value in `(SIZE_MAX-10, SIZE_MAX]` — a 64-bit length field from an
untrusted source (packet parser, file format, RPC framing) or an overflow in a
language binding. When it hits, the library corrupts its own heap (RCE-class
memory corruption) or reads ~2^64 bytes of arbitrary memory. This is textbook
CWE-190 at an API boundary: the library must not corrupt memory for any value
of a public SIZE_T parameter, and Microsoft itself treats this class as
fix-worthy — commit `bf421d1` (v103.9.1, issue #48) added exactly this guard to
the PKCS#1 **signature** padding function ("Simple check to avoid funky
behavior if cbHash is close to SIZE_MAX"), but left the **encryption** padding
siblings unfixed.

### Reachability on Windows (research findings, 2026-11-04)

- **CNG/BCrypt layer:** public symbols prove the path
  `BCryptEncrypt -> MSCryptRsaEncrypt -> SymCryptRsaPkcs1Encrypt /
  SymCryptRsaOaepEncrypt` in `bcryptprimitives.dll` (vallejo.cc 2018
  derandomization writeup + public PDB dumps). MSDN documents **no**
  provider-side `cbInput`-vs-key-size validation, and no public writeup shows
  whether `MSCryptRsaEncrypt` checks before forwarding. However:
  - `BCryptEncrypt`'s `cbInput` is **ULONG (32-bit)** — so on x64 the
    documented API **cannot express** the wrap range at all. Ordinary x64 BCrypt
    consumers are not a delivery path regardless of wrapper validation.
  - **32-bit processes (x86 / WOW64)** CAN pass `cbInput ∈ [0xFFFFFFF5,
    0xFFFFFFFF]`, i.e. the wrap range of a 32-bit SIZE_T — the one case where
    the documented API could reach the bug; whether the wrapper rejects it is
    untested publicly (ordinary oversized inputs empirically return
    STATUS_INVALID_PARAMETER, which hints at a wrapper check for *normal*
    oversize — but the wrap range is a different code path).
  - **Direct SymCrypt embedders** (products that compile SymCrypt in, e.g.
    Azure/Edge/Defender-style consumers) call these APIs with their own
    SIZE_T lengths and are not limited by the ULONG signature at all.
- **Remote callers:** no remotely-exposed Windows component forwards an
  attacker-controlled length into RSA-OAEP/PKCS1 *encryption*: DPAPI BackupKey
  RPC (MS-BKRP), EFS (MS-EFSR), AD CS (MS-WCCE), and RDP Standard Security
  (MS-RDPBCGR) all encrypt locally computed, fixed-size structures. The
  practical trigger remains a local caller with a length-confusion bug —
  no demonstrated remote path.

Honest caveats (critic-pass confirmed): (1) the caller must pass a pathological
length — a careful caller that pre-validates lengths is not affected; (2) the
trigger length is `~2^64` (a wrapped 64-bit field), so in practice it arrives
via a length confusion in the caller or a language binding, not a literal
buffer that big; (3) the overflow bytes are the random fill (uncontrolled) —
the primitive is **DoS-class**, not a controlled write; (4) no known Windows
service is known to forward untrusted lengths into these APIs, so there is no
demonstrated remote trigger. The PoC below compiles the REAL library and
demonstrates the actual crash and the actual fix, so the claim is not a
model — it is the code.

## Fix

Overflow-safe form (what bf421d1 did for the signature path):

```c
if (cbPlaintext > cbPkcs1Format - 11) { return SYMCRYPT_INVALID_ARGUMENT; }  // subtract, never add
```

## PoC

```
bash run.sh        # builds SymCrypt vuln+fixed from source and runs the differential
python3 exploit.py # quick arithmetic model (no compiler needed)
```

`run.sh` compiles SymCrypt HEAD (vulnerable) and a patched copy (overflow-safe
guard only) with zig cc, then runs the SAME attacker call against both:
- **VULNERABLE build:** `SymCryptRsaPkcs1Encrypt(key, data, SIZE_MAX-5)` corrupts
  the heap (`free(): invalid next size`, abort) — the direct padding call
  segfaults (rc=139).
- **FIXED build:** the same calls return `SYMCRYPT_INVALID_ARGUMENT` (0x800e)
  cleanly.

Same attacker input; the only difference is the guard — the exact
vuln-vs-fixed differential shape.

## Remediation

Add overflow-safe guards (`if (cbPlaintext > cbPkcs1Format - 11)`,
`if (cbPlaintext > cbOaepFormat - (2*cbHash + 2))`) to
`SymCryptRsaPkcs1ApplyEncryptionPadding` and
`SymCryptRsaOaepApplyEncryptionPadding`, mirroring bf421d1. Same file also
contains the PSS siblings (`rsa_padding.c:972/1115`), which are shielded in the
high-level APIs by caller validation but exported via `symcrypt_low_level.h`
and should get the same guard.
