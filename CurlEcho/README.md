# CurlEcho — curl `http_rw_hd()` header-terminator validation bypass (0-day)

| | |
|---|---|
| **Product + version** | libcurl `<= 8.23.0` (latest release, 2026-10-14) — `lib/http.c` HTTP/1.1 + RTSP header parser |
| **CVSS** | 3.7 LOW — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **CWE** | CWE-436 (Interpretation Conflict) / CWE-116 (Improper Neutralization) |

## Fix commit
**[3f684481b82e3f7ccbf61f79afb96fb4f0c67b60](https://github.com/curl/curl/commit/3f684481b82e3f7ccbf61f79afb96fb4f0c67b60)** —
"http: reject malformed header terminators" (2026-11-10, issue [#23859](https://github.com/curl/curl/issues/23859),
reported by christos-cantina-security). **Not yet in any release** — 8.23.0 predates the fix.

## The vulnerability

`http_rw_hd()` classifies the end of the response header block from the **first byte** of a
line alone, then writes the whole line to the client header sink without calling
`Curl_verify_header()` (which rejects NUL and spurious CR on ordinary headers and chunked trailers):

```c
/* lib/http.c:4115 (curl 8.23.0) */
if((0x0a == *hd) || (0x0d == *hd)) {
    /* "Empty header line means end of headers!" — only *hd is checked, so a
       CR-prefixed line like "\rX-Bad: a<NUL>b\r\n" is accepted as the terminator. */
    curlx_dyn_addn(&last_header, hd, hdlen);        /* whole line copied      */
    ...
    result = http_on_response(data, ..., &last_header, ...);
    /* -> http_on_response() writes last_hd via http_write_header() at the "out:"
       label WITHOUT Curl_verify_header(), so NUL/bare-CR bytes reach the app. */
}
```

## Exploit chain

1. A malicious (or MITM / SSRF-reached) HTTP/1.1 or RTSP server sends a response whose
   end-of-headers line is CR-prefixed and carries a payload, e.g.
   `HTTP/1.1 200 OK\r\n` + `\rX-Bad: a<NUL>b\r\n`.
2. curl's header splitter treats the `\r`-prefixed line as the empty terminator and copies
   the entire line (including the NUL and the bare CR) into `last_header`.
3. `http_on_response()` writes that buffer to `CURLOPT_HEADERFUNCTION` / `curl -D` / `curl -i`
   **without** `Curl_verify_header()`, while `curl_easy_perform()` returns `CURLE_OK` (0).
4. The same NUL/bare-CR bytes in a *normal* header line are rejected with
   `CURLE_WEIRD_SERVER_REPLY` (8) — the terminator line is the one sink that skips the check.

## Run

```bash
bash run.sh     # builds with zig cc (or cc/gcc) and runs the PoC
```

Expected output (abridged) — the injected header hex is byte-identical to the reporter's
real-libcurl capture:

```
=== VULNERABLE (curl 8.23.0) ===
  [header sink] len=17 hex=485454502f312e3120323030204f4b0d0a   (= "HTTP/1.1 200 OK\r\n")
  [header sink] len=13 hex=0d582d4261643a206100620d0a           (= "\rX-Bad: a\0b\r\n")
  transfer result = 0 (CURLE_OK)

=== FIXED (commit 3f68448, unreleased) ===
  [header sink] len=17 hex=485454502f312e3120323030204f4b0d0a
  [fixed] Invalid header termination -> CURLE_WEIRD_SERVER_REPLY
  transfer result = 8 (WEIRD_SERVER_REPLY)

=== NEGATIVE CONTROL: NUL in a NORMAL header (rejected in both) ===
  [verify] NUL/CR rejected (normal header)
  vulnerable transfer result = 8 (WEIRD_SERVER_REPLY)

CURLECHO-CONFIRMED
```

`poc.c` ports the line-splitter (`memchr '\n'`), the vulnerable vs fixed terminator
classification, and `Curl_verify_header`'s NUL/CR rejection, and drives the crafted response
through both paths.

## Exploitability assessment

- **Preconditions:** attacker controls response bytes (malicious origin, MITM, SSRF); victim
  reads headers via `CURLOPT_HEADERFUNCTION` / `-D` / `-i`. No non-default option or privilege.
- **Threat model:** a server that can already inject arbitrary header *lines* gains the ability
  to inject NUL, bare-CR, and arbitrary payload on the *terminator* line, on a transfer that
  reports success — defeating curl's explicit NUL/CR rejection hardening.
- **Impact:** LOW, honestly bounded. curl itself suffers no confidentiality/integrity/availability
  loss — it faithfully delivers bytes to a documented, length-delimited, non-NUL-terminated sink.
  No memory corruption, RCE, credential leak, or request smuggling (reporter verified ASan-clean,
  byte-identical output; `curl_easy_header()` is unaffected). Downstream harm requires a consumer
  that treats the header buffer as a C string or trusts the separator line as a record boundary —
  plausible but unproven in the wild (hence the HIGH attack complexity and LOW rating). The
  security value is that it defeats curl's explicit NUL/CR-rejection hardening.
