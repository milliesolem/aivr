# FfmpegOverrun — FFmpeg `anlmdn` filter heap-buffer-overflow (CWE-787)

A heap out-of-bounds **write** in FFmpeg's `anlmdn` audio filter
(*adaptive non-local-means denoising*, `libavfilter/af_anlmdn.c`). The per-sample
denoising loop writes `H` output samples, but the output frame is only allocated
for `in->nb_samples` samples. When a stream's length is not a multiple of `H`,
the **final short frame** (fewer than `H` samples) makes the loop write past the
heap buffer — up to `(H-1) * 4` bytes (≈700 bytes at default settings, 44.1 kHz).

| Product + version            | CVSS 3.1                                    | CWE                    |
|------------------------------|---------------------------------------------|------------------------|
| FFmpeg ≤ n9.0.2 / n8.1.3 (latest releases, 2026-11) | **7.1 HIGH** — `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | CWE-787 (out-of-bounds write) |

> Note on severity: this is a genuine heap OOB **write** (memory corruption) found
> by Tencent Keen Security Lab / Secbuddy and confirmed by FFmpeg with ASAN
> ("Heap out of array write Replicated through UnModified FFmpeg with ASAN").
> The demonstrated, deterministic impact is a process abort (DoS); the write is
> bounded and carries denoised `float` data rather than fully attacker-chosen
> bytes, so C:N is honest (the overflow writes, it does not read/leak) and I:H is
> the *potential* heap-corruption consequence rather than a demonstrated precise
> arbitrary write. A network transcoding service that applies `anlmdn` to
> untrusted uploads would be `AV:N/UI:N` = 9.1 CRITICAL; the local
> file-processing model below is 7.1.

## Fix commit

`2e70a189b9025158d9db04abf6acd6692e87c797` — *"avfilter/af_anlmdn: do not write
past the end of a short last frame"* (Michael Niedermayer, 2026-11-06).
`Fixes: heap-buffer-overflow` / `Fixes: uQUc1sfqWcj8` /
`Found-by: Secbuddy, Tencent Keen Security Lab`. Merged to `master` only — **not
yet in any release** (n9.0.2 / n8.1.3 still contain the vulnerable loop).

## Vulnerable code (pre-fix, `libavfilter/af_anlmdn.c` @ n9.0.2)

```c
// filter_frame(): the output frame is sized to the SHORT frame length...
if (av_frame_is_writable(in)) {
    out = in;
} else {
    out = ff_get_audio_buffer(outlink, in->nb_samples);   // <-- in->nb_samples, NOT H
}

// filter_channel(): ...but the loop writes H samples into it.
for (int i = S; i < H + S; i++) {          // <-- should be `i < in->nb_samples + S`
    float P = 0.f, Q = 0.f;
    ...
    switch (om) {
    case IN_MODE:    dst[i - S] = f[i];           break;
    case OUT_MODE:   dst[i - S] = P / Q;          break;
    case NOISE_MODE: dst[i - S] = f[i] - (P / Q); break;
    }
}
```

The fix changes the loop bound to `i < in->nb_samples + S` so exactly
`in->nb_samples` samples are written.

## Exploit chain

1. **Craft** an audio file whose total sample count is **not** a multiple of the
   filter's block size `H`. With defaults (`patch=2000us`) at 44.1 kHz, `K=88`
   and `H=2K+1=177`; a 178-sample stream therefore ends with a 1-sample frame.
2. **Process** it with the `anlmdn` filter (`ffmpeg -i x.wav -af anlmdn ...`).
   `activate()` consumes `H` samples per frame via `ff_inlink_consume_samples`,
   and at EOF returns the remaining 1-sample short frame.
3. **Overflow** — `filter_channel()` writes `H=177` samples into the 1-sample
   (4-byte) output buffer, i.e. `(177-1)*4 = 704` bytes past the allocation.
4. **Detection** — the PoC builds FFmpeg with a canary-redzone `av_malloc`
   (ASAN is unavailable in this environment), so the overflow clobbers the
   redzone and aborts with a deterministic marker.

## Run instructions

```bash
bash run.sh
```

`run.sh` drives the two shipped **real** FFmpeg 9.0.2 binaries (compiled from
source with musl-gcc):
* `ffmpeg-vuln`  — unmodified n9.0.2 → on the 178-sample input it prints
  `AIVR-CANARY: HEAP-BUFFER-OVERFLOW detected ...` and aborts (exit 134).
* `ffmpeg-fixed` — same source with the one-line upstream fix → the identical
  input exits cleanly (exit 0), proving the overflow is the vulnerable loop.

Expected marker: `FFMPEGOVERRUN-OK: heap-buffer-overflow reproduced (vuln exit=134, fixed exit=0)`.

### Rebuilding the binaries from source (verification)

`build.sh` re-clones FFmpeg `n9.0.2`, applies the canary-redzone allocator patch
and builds both binaries. Requires network + `x86_64-linux-musl-gcc` (or zig cc).

## Threat model

The trigger requires the `anlmdn` filter to be explicitly applied (it is not on
the default decode path), and a stream length that is not a multiple of `H`.
Any application or service that denoises untrusted audio (media transcoders,
audio-processing backends) and uses FFmpeg ≤ n9.0.2 is exposed. The primitive is
a bounded heap overwrite: primarily a deterministic crash (DoS), with
theoretical heap-corruption / control-flow-hijack potential given the write is
attacker-influenced float data.
