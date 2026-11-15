# JqMimic — jq 1.8.2 silently truncates numeric JSON tokens at a raw NUL byte

| | |
|---|---|
| **Product / version** | jq 1.8.2 — official static Linux amd64 release binary (`jq-linux-amd64`, released 2026-06-20). Bug is long-standing (upstream regression test cites issue #3110); still live in 1.8.2, the latest release. |
| **CVSS 3.1** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` → **3.7 LOW** (validated with `drawing_board/cvss31.py`) |
| **CWE** | CWE-436 (Interpretation Conflict) primary; CWE-170 (Improper Null Termination) root cause; CWE-20 (Improper Input Validation) |

## Summary

jq's JSON scanner classifies a raw `0x00` byte as an ordinary literal character
(`classify()` default case) and appends it to the current token buffer. When the
token is a **numeric literal**, `check_literal()` then treats that buffer as a
NUL-terminated C string (`p->tokenbuf[p->tokenpos] = 0;`) and parses it with
`jvp_strtod()` / decNumber. Everything after the NUL is silently discarded and
**no parse error is raised** — even though RFC 8259 forbids raw NUL in JSON text.

Result: `{"amount":100\x00999}` is accepted with exit status 0 and
`.amount` evaluates to `100`. Any consumer of the *same bytes* that ignores or
strips NUL characters (text loaders, `tr -d '\0'`, iconv, C-string readers, log
pipelines) reads `100999`. A jq-based policy gate and the downstream system
therefore disagree about the value of the same document.

## Fix

Upstream fix (unreleased, master only, 2026-08-23):

- commit `fbee8f48bac154aeb6edfbd79792181ac19914a3` —
  <https://github.com/jqlang/jq/commit/fbee8f48bac154aeb6edfbd79792181ac19914a3>
- PR <https://github.com/jqlang/jq/pull/3606> "Reject raw NUL bytes in the parser
  instead of silently truncating tokens"

The fix is a five-line addition to `classify()` in `src/jv_parse.c`:

```c
case '\0':
  // RFC 8259 forbids raw NUL in JSON text. Treating it as a literal lets it
  // slip into the token buffer, where check_literal() reads the buffer as a
  // NUL-terminated C string and silently truncates the token. Reject it.
  return INVALID;
```

It ships with an upstream regression test asserting
`jq: parse error: Invalid character at line 1, column 3` for `printf '12\0003'`.
No release contains the fix: 1.8.2 is the latest tag (2026-06-20) and the fix
landed two months later.

## Vulnerable code (jq 1.8.2)

`src/jv_parse.c:581` — NUL is not special-cased, so it falls through to LITERAL:

```c
static chclass classify(char c) {
  switch (c) {
  ...
  default:
    return LITERAL;          /* 0x00 lands here */
  }
}
```

`src/jv_parse.c:536-537` — the token buffer is then read as a C string:

```c
    p->tokenbuf[p->tokenpos] = 0;
    jv number = jv_number_with_literal(p->tokenbuf);   /* stops at the embedded NUL */
```

`src/main.c:661` — the entry point: stdin/file documents are fed to this parser.

## Exploit chain

1. Attacker submits a webhook / import / API record whose body is
   `{"amount":100\x00999}` (raw NUL, not `\u0000`; JSON escaping `\u0000`
   *is* handled correctly by jq and does not trigger the bug).
2. The victim's policy gate uses jq — e.g. `jq -e '.amount <= 100'` — which
   parses the numeric token as `100`, approves the record, and exits 0.
3. A second stage consumes the same raw bytes and removes NULs as padding
   (`tr -d '\0'`, iconv, a C-string reader, an ETL loader). It sees `100999`.
4. The over-limit record is accepted/recorded: the gate and the ledger disagree.

The PoC models exactly that pipeline with the real 1.8.2 binary: the gate
returns exit 0 and the NUL-stripped ledger reads `100999`.

## PoC files

- `jq-1.8.2` — official static Linux amd64 binary from the jq-1.8.2 GitHub
  release; SHA-256 `b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f`
  (checked by `run.sh` before execution).
- `poc.py` — driver: runs real jq on the crafted bytes, models the gate + ledger,
  and applies the upstream fixed `classify()` rule as a labelled control.
- `run.sh` — checksum check + driver.

## Run

```bash
bash run.sh        # exit 0 and prints JQMIMIC-CONFIRMED when the bug triggers
```

Expected (observed) output:

```
== 1. top-level number token with raw NUL ==
   input bytes : 31 30 30 00 39 39 39   ('100' NUL '999')
   jq .        : rc=0 stdout='100' stderr=''
== 2. object field used by a policy gate ==
   jq .amount  : rc=0 stdout='100' stderr=''
== 3. victim pipeline: jq gate + NUL-tolerant ledger ==
   gate: jq -e '.amount <= 100' -> exit 0 (APPROVED)
   ledger import (NULs stripped): amount = 100999
== 4. control: same bytes through the fixed classify() rule ==
   fixed jq (NUL -> INVALID): Invalid character
   negative control {"amount":100}: jq='100' ledger=100 (agree)
== verdict ==
   jq 1.8.2 accepted RFC-invalid JSON (raw NUL), truncated the token to
   100, and the jq gate approved a record whose ledger value is 100999.
JQMIMIC-CONFIRMED
```

## Preconditions / threat model (honest)

- The victim must use jq to make a decision on attacker-influenced JSON
  (extremely common in shell/CI/automation, but not universal).
- A **second** consumer of the same bytes must tolerate or strip NULs for the
  value divergence to become a policy bypass. Without such a consumer the impact
  is limited to jq silently accepting malformed input and corrupting its own
  output (data loss).
- jq does **not** truncate raw NULs inside JSON *strings* (it rejects raw
  control characters there) — only numeric tokens take the `check_literal()`
  C-string path. That is why the payload is a number.
- Severity is therefore LOW/MEDIUM at most: this is a validation/parsing
  differential, not memory corruption.

## Self-critique — three ways this might not work

1. **"jq might reject the NUL in 1.8.2."** Checked against the real release
   binary: `printf '100\000999' | jq .` prints `100` and exits 0; the same on
   `{"amount":100\000999}` yields `.amount == 100`. The fix commit and its
   upstream regression test confirm the vulnerable behaviour pre-fix.
2. **"The downstream consumer would also reject/strip the payload."** True for
   strict parsers. The PoC models a NUL-tolerant loader (the `tr -d '\0'` /
   C-string class) and states this precondition explicitly; the PoC's negative
   control shows a well-formed document behaves consistently, so the divergence
   is caused by the NUL, not by the harness.
3. **"A gate could compare rawer bytes or use a JSON library instead of jq."**
   Then it is not affected. The finding is specifically about jq-based gates;
   commit 0c7d133 etc. show upstream treats parser hardening as security-relevant.
   No sanitisation exists before the sink: `classify()` is the only validation
   layer and it passes 0x00 through.

## Evidence

- Vulnerable: jq 1.8.2 (latest release, static Linux amd64, SHA-256 pinned).
- Fixed: master `fbee8f4` only (2026-08-23), unreleased.
- Dynamic result against the official binary: `JQMIMIC-CONFIRMED`
  (see `finding.json` → `evidence.observed_result`).
