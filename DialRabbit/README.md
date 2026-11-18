# DialRabbit — libphonenumber C++ RFC3966 phone-context catastrophic backtracking (ReDoS / CWE-1333, CWE-400)

| Field | Value |
| --- | --- |
| **Product / version** | [google/libphonenumber](https://github.com/google/libphonenumber) C++ — all releases through **v9.0.43** (`86ea33c`, 2026-11-04), i.e. every release ever cut |
| **CVSS 3.1** | **7.5 HIGH** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **CWE** | CWE-1333 (inefficient regular-expression complexity) → CWE-400 (uncontrolled resource consumption) |
| **Fix** | [`981600c`](https://github.com/google/libphonenumber/commit/981600cc587fb87483ad294a61daa187afc64b2c) (PR [#4070](https://github.com/google/libphonenumber/pull/4070), 2026-11-06) — **master only, no release contains it** |
| **Vulnerable code** | `cpp/src/phonenumbers/phonenumberutil.cc:793-795`, `848-849`, `2214-2217` |

## Summary

`PhoneNumberUtil::Parse()` accepts RFC 3966 `tel:` URIs and validates the
attacker-supplied `phone-context` parameter in `IsPhoneContextValid()`. The
domain-label regexes built in `PhoneNumberRegExpsAndMappings` are ambiguous:

```cpp
// phonenumberutil.cc:793-795 (v9.0.43)
rfc3966_domainlabel_(StrCat("[", alphanum_, "]+((\\-)*[", alphanum_, "])*")),
rfc3966_toplabel_(StrCat("[", kValidAlphaInclUppercase,
                         "]+((\\-)*[", alphanum_, "])*")),
// :848-849
rfc3966_domainname_pattern_(regexp_factory_->CreateRegExp(StrCat(
    "^(", rfc3966_domainlabel_, "\\.)*", rfc3966_toplabel_, "\\.?$")))
```

`((\-)*[alnum])*` gives an exponential number of ways to split each label, and
the outer `(label\.)*` multiplies that across labels. A phone-context of the
form `(aa.){N}aa!` matches every label greedily and then fails on the final
`!`; the ICU backtracking engine (libphonenumber's default regex backend,
`USE_ICU_REGEXP=ON`) explores ~2^N paths. `FullMatch()` has no timeout, so the
calling thread never returns.

The upstream fix rewrites both labels unambiguously:

```cpp
rfc3966_domainlabel_(StrCat("[", alphanum_, "]+(\\-+[", alphanum_, "]+)*")),
rfc3966_toplabel_(StrCat("[", kValidAlphaInclUppercase, "][", alphanum_,
                         "]*(\\-+[", alphanum_, "]+)*")),
```

## Exploit chain

1. Attacker sends any request whose phone number reaches the C++ parser, e.g.
   `tel:253-0000;phone-context=aa.aa.…aa.aa!` (30 × `aa.` + `aa!`).
2. `PhoneNumberUtil::Parse` (`:2138`) → `ParseHelper` (`:2281`) →
   `BuildNationalNumberForParsing` (`:2223`, call at `:2291`).
3. `BuildNationalNumberForParsing` extracts the `phone-context` value and calls
   `IsPhoneContextValid` (`:2229`).
4. `IsPhoneContextValid` (`:2203`) tries `rfc3966_global_number_digits` (fails
   in µs), then `rfc3966_domainname_pattern_->FullMatch()` (`:2216`).
5. `FullMatch()` spends unbounded CPU in ICU backtracking. One request pins one
   server worker thread; ~N_workers requests stall the service.

No authentication, no victim interaction, no special configuration beyond the
library's default build.

## Proof of concept

`redos.cc` compiles the **real project source** — `regexp_adapter_icu.cc`
(plus `string_byte_sink.cc`, `default_logger.cc`, `logger.cc`) vendored
verbatim from v9.0.43 in `src/phonenumbers/` — with zig cc against the ICU 78
regex engine, and drives `ICURegExpFactory::CreateRegExp(...)->FullMatch(...)`
with the two patterns exactly as constructed in `phonenumberutil.cc`
(`phonenumberutil_v9.0.43.cc` is included as the audit copy of the vulnerable
file). Each measurement runs in a forked child so the pathological case is
killed after a fixed budget.

```
bash run.sh
```

Expected output (this host, ICU 78.3):

```
=== DialRabbit: libphonenumber C++ RFC3966 phone-context ReDoS ===
engine      : REAL src/phonenumbers/regexp_adapter_icu.cc (ICU 78.3)
vulnerable  : ^([A-Za-z0-9]+((\-)*[A-Za-z0-9])*\.)*[A-Za-z]+((\-)*[A-Za-z0-9])*\.?$
fixed (981600c): ^([A-Za-z0-9]+(\-+[A-Za-z0-9]+)*\.)*[A-Za-z][A-Za-z0-9]*(\-+[A-Za-z0-9]+)*\.?$
input       : phone-context = ("aa." * N) + "aa!"  [upstream test input]

[-] vulnerable pattern, exponential growth:
    [parent] n=6  match=0  0.6 ms
    [parent] n=8  match=0  5.3 ms
    [parent] n=10 match=0  96.6 ms
    [parent] n=12 match=0  597.9 ms
    [parent] n=14 match=0  6114.2 ms

[-] vulnerable pattern, upstream payload (N=30, 15 s budget):
    [parent] n=30 no result after 15000 ms -> worker thread still inside FullMatch, killed

[+] fixed pattern (upstream 981600c), N=30:
    [parent] n=30 match=0 (rejected) in 0.015 ms
    [parent] global-number-digits alternative: match=0 in 0.002 ms

PHONENUMBER-REDOS-CONFIRMED
```

Exit code 0 means the vulnerable pattern hung and the fixed pattern rejected
the same input in constant time.

## Exploitability / threat model

- **Who is harmed:** any service that parses user-supplied phone numbers with
  the C++ library — account signup, 2FA/SMS gateways, CRM imports, e-commerce
  checkout. The attacker is an unauthenticated remote party.
- **Impact:** CPU exhaustion / indefinite thread pinning. With N=30 labels the
  match is effectively infinite (2^30 paths × ~µs per path ⇒ hours-to-days);
  a handful of concurrent requests drains a request-thread pool, so the whole
  service becomes unavailable. Not a crash and not memory corruption.
- **Boundary:** the vulnerable string comes from the request, not from
  configuration; no authentication or tenant check precedes `Parse()`.
- **Honest limitation:** the *full* C++ library could not be linked in this
  sandbox (libprotobuf-dev/protoc and abseil headers are absent and cannot be
  installed as a non-root user within budget). The PoC therefore compiles the
  library's real ICU regexp adapter and matches the exact vulnerable pattern
  string against the exact input the real `IsPhoneContextValid()` passes to it;
  it does not call `PhoneNumberUtil::Parse` end-to-end. The call chain is
  verified by reading the vendored `phonenumberutil_v9.0.43.cc`
  (lines 2138/2229/2216).

## Why it might not work (and how each was checked)

1. **“The library rejects the input before the regex.”** Checked
   `BuildNationalNumberForParsing`: `ExtractPhoneContext` only locates the
   `phone-context` substring; the *first* validation is `IsPhoneContextValid`,
   which reaches the domainname regex for a non-`+` value. Nothing normalises or
   length-caps the value first.
2. **“RE2 is the default backend, so no backtracking.”** Checked
   `cpp/CMakeLists.txt`: `option (USE_ICU_REGEXP "Use ICU regexp engine" ON)`
   and the ICU adapter is the default; RE2 is opt-in. The PoC uses the real ICU
   adapter, and the upstream regression test explicitly names “the ICU regex
   backend”.
3. **“The fix is already in a release.”** Checked out tag `v9.0.43`
   (`86ea33c`, 2026-11-04) and grepped its `phonenumberutil.cc`: it still
   contains `]+((\\-)*[`; the fix commit is 2026-11-06 and is not an ancestor of
   v9.0.43. No later release exists (HEAD `36931ee`, 2026-11-16).

## Files

- `redos.cc` — driver (real adapter + exact patterns + forked timing harness)
- `run.sh` — builds with zig cc and runs; locates ICU via `ICU_PREFIX`
- `src/phonenumbers/` — project sources vendored verbatim from v9.0.43
- `phonenumberutil_v9.0.43.cc` — audit copy of the vulnerable file
- `finding.json` — machine-checkable evidence contract
