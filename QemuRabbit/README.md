# QemuRabbit — QEMU virtio-snd guest→host memory exhaustion (0-day)

| Field | Value |
| --- | --- |
| Product | QEMU (hw/audio/virtio-snd.c — virtio sound device) |
| Version | master before `259b58e68e` / `9a0f03f815` (unreleased as of 2026-11-13) |
| CVSS 3.1 | **6.5 MEDIUM** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H` |
| CWE | CWE-400 / CWE-770 (Uncontrolled Resource Consumption) |
| Status | **0-day** — no CVE; fix on master (QEMU work_item 3587), not in a release |

## Root cause

`virtio_snd_set_pcm_params()` stored the guest-supplied `buffer_bytes` and
`period_bytes` with **no validation**, and the TX/RX transfer handlers allocated
a host buffer sized by the guest transfer descriptor with **no cap**:

```c
// set_pcm_params (no cap, no spec check)
st_params->buffer_bytes = le32_to_cpu(params->buffer_bytes);  // up to 4 GiB

// tx_xfer (unbounded host allocation)
size   = iov_size(elem->out_sg, elem->out_num) - msg_sz;      // guest-controlled
buffer = g_malloc0(sizeof(VirtIOSoundPCMBuffer) + size);      // HOST heap
```

A malicious guest sets `buffer_bytes = 0xffffffff` (4 GiB) per stream and queues
transfer descriptors of a matching size. Each transfer forces `g_malloc0` of
host memory proportional to the descriptor, and the same guest pages can back
many descriptors — so a modest guest can drive **unbounded host allocation** and
OOM the host (taking down every other VM).

**Fix** (2026-11-10, work_item 3587): cap `buffer_bytes` at 500 MiB, require
`period_bytes` to divide `buffer_bytes` (VIRTIO 5.14.6.6.3.2), and clamp each
transfer with `size = MIN(stream->params.buffer_bytes, size)`.

## Exploit chain

1. Guest sends `VIRTIO_SND_R_PCM_SET_PARAMS` with `buffer_bytes = 4 GiB`.
2. Guest queues TX transfer descriptors whose scatter-gather size is 4 GiB.
3. `virtio_snd_handle_tx_xfer` runs `g_malloc0(sizeof + 4 GiB)` per transfer.
4. Host memory is exhausted → host OOM → denial of service for the host.

## Run

```bash
bash run.sh
```

Compiles the verbatim vulnerable/fixed validation with the zig C toolchain and
prints `RESULT: GUEST->HOST MEMORY EXHAUSTION CONFIRMED`.

## Threat model / scope

Guest→host DoS only (no confidentiality/integrity impact, no code execution).
The vulnerable device is `virtio-snd`; the fix is unreleased, so every tagged
QEMU with `virtio-snd` is affected. This is an honest **MEDIUM** — a malicious
guest exhausting host memory is a recognised hypervisor security boundary (QEMU
maintainers themselves filed it as a security work item), but it is not remote
code execution.
