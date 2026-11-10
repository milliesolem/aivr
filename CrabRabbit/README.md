# CrabRabbit — Pingora response decompression has no output-size cap (decompression bomb)

Cloudflare **pingora** (the Rust proxy framework, ~27.8k★) shipped a brand-new
HTTP response-compression module (2026) that can *decompress* an upstream response
body (gzip or brotli). The decompressor accumulates decompressed bytes into an
unbounded growable buffer, so a malicious or compromised upstream can amplify
memory/CPU with a tiny "bomb" body.

| Field | Value |
|---|---|
| Product + version | Cloudflare pingora `HEAD 3f87e92` (2026-11-09), unfixed |
| CVSS | **6.5 MEDIUM** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` |
| CWE | CWE-770 (uncontrolled resource allocation) / CWE-409 (decompression bomb) |

## Vulnerable code

`pingora-core/src/protocols/http/compression/gzip.rs` — `Decompressor::encode()`:

```rust
let reserve_size = if input.len() < MAX_INIT_COMPRESSED_SIZE_CAP {
    input.len() * ESTIMATED_COMPRESSION_RATIO      // "cap the buf size amplification,
} else {                                            //  there is a DoS risk of always
    input.len()                                     //  allocate 3x the memory"
};
self.decompress.get_mut().reserve(reserve_size);    // reserve() is only a capacity HINT
self.decompress.write_all(input)                    // Vec<u8> GROWS to the FULL
                                                    // decompressed output — NO cap
```

`brotli.rs` (`DecompressorWriter<Vec<u8>>`) has the identical pattern (zstd/dcb/dcz
decompression is "not implemented" in this module, so gzip and brotli are the two
reachable decompressors). The author's own comment (`gzip.rs:47-48`) admits the DoS
risk but only caps the *initial reserve hint*, never the *actual* decompressed output.

## Exploit chain

1. Operator enables response decompression on a pingora server
   (`ResponseCompressionCtx::new(level, /*decompress_enable=*/ true, ..)` or
   `adjust_decompression(true)`).
2. A client asks for `Accept-Encoding: br` while the origin answers with
   `Content-Encoding: gzip` → `decide_action()` returns `Action::Decompress(Gzip)`.
3. The origin (malicious, or compromised) sends a small, highly-compressible gzip body.
4. `response_body_filter()` feeds each chunk to `Decompressor::encode()`, whose inner
   `Vec<u8>` grows to the full decompressed size (~1000×) with no limit → memory/CPU
   amplification that the plain streaming path does not have.

## Exploitability assessment

- **Attacker**: a malicious or compromised upstream/origin (semi-trusted — the operator
  configures it, but multi-tenant / customer-origin deployments make it a real boundary).
- **Reachability**: requires the *opt-in* decompression feature; NOT on by default
  (`ResponseCompressionBuilder::init()` passes `decompress_enable = false`).
- **Amplification**: gzip/deflate tops out near ~1032:1, so a single 16 KiB read-buffer
  chunk expands to ~16 MiB; the impact scales with the (configurable) buffer size and
  concurrent connections. Honest severity: **medium** (availability only, no
  confidentiality/integrity impact).
- **Fix**: cap decompressed output per chunk (e.g. wrap the decoder in `Take(MAX)`, or
  reject when the buffer exceeds a max size) — exactly the limit minio's zstd path
  applies via `WithDecoderMaxWindow`.

## Run

```bash
cd poc/CrabRabbit
bash run.sh          # or: python3 poc.py --ratio 800
```

The PoC is a faithful Python port of `Decompressor::encode()`: it feeds a 12,773-byte
gzip "bomb" (1026:1) through the un-capped path and shows the buffer grows to 13 MB, then
shows a patched variant (4 MiB cap) rejecting the same input.
