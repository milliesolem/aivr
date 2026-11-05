# CurlMimic — curl zstd content decoder accepts truncated streams

| Product + version | CVSS | CWE |
|---|---|---|
| curl (libcurl) 8.23.1-DEV / 8.24.x, HEAD `116c5ae` (unfixed) | **5.3** MEDIUM (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`) | CWE-345 (insufficient verification of data authenticity) |

## Summary

curl's HTTP content decoders recently gained an "incomplete stream" check: when a
compressed response body ends before its decoder reaches the end-of-stream state,
curl now rejects it (`CURLE_BAD_CONTENT_ENCODING`). That hardening landed for
**gzip** and **deflate** (commit `0036b55`) and for **brotli** (commit `f789f35`),
which all register a dedicated `*_do_flush` that raises
*"… stream ended before completion"*.

The **zstd** decoder was missed. `lib/content_encoding.c` registers the zstd writer
with the *default* flush:

```c
static const struct Curl_cwtype zstd_encoding = {
  "zstd", NULL, CURL_CW_FLAG_BLOWUP,
  zstd_do_init, zstd_do_write,
  Curl_cwriter_def_flush,   /* <-- no incomplete-stream check (gzip/brotli have one) */
  zstd_do_close, sizeof(struct zstd_writer)
};
```

and `zstd_do_write` only checks `ZSTD_isError()`, ignoring `ZSTD_decompressStream`'s
"remaining input needed" hint. A truncated `Content-Encoding: zstd` body is therefore
silently accepted and its partial decompressed output written to the target.

## Exploit chain

1. curl requests a URL with `--compressed` (or HTTP content decoding, the default).
2. The server (or a MITM truncating the response) sends `Content-Encoding: zstd`
   followed by a zstd frame cut off before its end/checksum.
3. `zstd_do_write` decompresses the partial frame without error; `Curl_cwriter_def_flush`
   performs no completeness check; curl exits 0 and writes the truncated data.
   The same truncated payload under `gzip`/`brotli` returns exit 61 (rejected).

## Exploitability assessment (honest)

- **Impact:** data-integrity only (`C:N/I:L/A:N`) — curl silently accepts a truncated
  compressed response body, so a consumer receives incomplete data with no error
  signal. No memory-unsafety, no code execution.
- **Precondition:** the peer must be able to deliver (or truncate) a zstd-encoded
  response — a malicious/compromised server or an on-path attacker on plaintext HTTP.
- **PoC scope:** drives a **real curl built from source** (zig cc + libzstd + libz)
  against a local server serving identical-length truncated gzip vs zstd bodies; the
  gzip path rejects (61) while the zstd path accepts (0) and writes 1996 bytes.

## Run

```
bash run.sh
```

First run builds curl (zstd+zlib) from source with the zig toolchain and caches it
under `/tmp/opencode/curl-mimic/`. Expected output: gzip → `curl: (61) Gzip stream
ended before completion`; zstd → `exit=0` + partial data. Exit 0 = PASS.

## References

- Fix precedent (gzip/deflate): `curl/curl` commit `0036b55` "content encoding: reject incomplete zlib streams (gzip, deflate)"
- Fix precedent (brotli): `curl/curl` commit `f789f35` "content_encoding: reject incomplete brotli streams"
- Vulnerable code: `lib/content_encoding.c` `zstd_encoding` / `zstd_do_write` at HEAD `116c5ae`
