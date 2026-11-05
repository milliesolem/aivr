#!/usr/bin/env python3
"""Serve truncated gzip and zstd responses to demonstrate curl's divergent
handling. Uses an incompressible payload so the compressed frames are large
enough that truncation leaves partial decodable data."""
import gzip
import http.server
import os
import threading

import zstandard

PLAIN = os.urandom(2000)  # incompressible -> large frames

gz_full = gzip.compress(PLAIN)
gz_trunc = gz_full[:-16]

cctx = zstandard.ZstdCompressor()
zst_full = cctx.compress(PLAIN)
zst_trunc = zst_full[:-4]  # drop the frame checksum -> decoder reports incomplete


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/gzip":
            body, enc = gz_trunc, "gzip"
        elif self.path == "/zstd":
            body, enc = zst_trunc, "zstd"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Encoding", enc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "18888"))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"gzip full={len(gz_full)} trunc={len(gz_trunc)}  zstd full={len(zst_full)} trunc={len(zst_trunc)}", flush=True)
    server.serve_forever()
