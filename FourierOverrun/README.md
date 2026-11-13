# FourierOverrun — onnxruntime STFT unvalidated-rank OOB read → `std::terminate()`

**Wildcard (0-day)** in **microsoft/onnxruntime** (~22k★, the de-facto ONNX inference
runtime). The standard-domain `STFT` CPU kernel reads the signal tensor's shape
dims *before* validating its rank; a rank-mismatched (shapeless/low-rank) model
input walks off the `gsl::span<int64_t>` shape buffer and calls `std::terminate()`,
aborting the whole process.

| Field    | Value                                                          |
| -------- | -------------------------------------------------------------- |
| Product  | microsoft/onnxruntime — `STFT` CPU kernel (`core/providers/cpu/signal/dft.cc`) |
| Version  | 1.31.1 (and earlier) — **unfixed** at HEAD `4af944ff`          |
| CVSS     | 5.5 **MEDIUM** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| CWE      | CWE-125 (out-of-bounds read) → unhandled `std::terminate()` (DoS) |

## Root cause

```cpp
// onnxruntime/core/providers/cpu/signal/dft.cc (HEAD 4af944ff)

Status STFT::Compute(OpKernelContext* ctx) const {              // line 634
  const auto* signal = ctx->Input<Tensor>(0);
  const auto& signal_shape = signal->Shape();
  // line 645 — reads signal_shape[NumDimensions()-1] BEFORE any rank check
  const auto is_real_valued = signal_shape.NumDimensions() == 2
                              || signal_shape[signal_shape.NumDimensions() - 1] == 1;
  const auto is_complex_valued = signal_shape.NumDimensions() > 2
                                 && signal_shape[signal_shape.NumDimensions() - 1] == 2;
  ...
  if (is_real_valued)
    ORT_RETURN_IF_ERROR((short_time_fourier_transform<float, float>(ctx, ...)));

// short_time_fourier_transform (line 535):
  const auto& signal_shape = signal->Shape();
  const auto batch_size  = signal_shape[0];   // line 552  <-- no rank check
  const auto signal_size = signal_shape[1];   // line 553  <-- OOB for rank-1
  const auto signal_components = ... NumDimensions() == 2 / 3 ...;  // rank check AFTER
```

For a **scalar (rank-0)** signal, `signal_shape.NumDimensions() - 1` underflows
(`size_t`), so line 645 reads `signal_shape[SIZE_MAX]`. For a **rank-1** signal
whose shape is `{1}`, `is_real_valued` becomes `true` (the `signal_shape[0] == 1`
branch) and control flows into `short_time_fourier_transform`, whose line 553 reads
`signal_shape[1]` out of bounds. Either way the `gsl::span` bounds contract fires and
calls `std::terminate()` — not an exception, a hard `SIGABRT` of the process.

This is the exact class already fixed (2026-10-29, PR #33517 / `9265e05ae9`) in six
sibling kernels (`Conv`, `ConvInteger`, `QLinearConv`, `CropAndResize`, `Einsum`,
`AffineGrid`); that fix did **not** cover the signal-domain kernels. The same
read-before-check exists in `DFT::Compute` (`dft.cc:427-428`), so a rank-0 `DFT`
input also aborts (noted in `finding.json`; `STFT` is the primary PoC because it
additionally aborts on rank-1 input).

## Exploit chain

1. Attacker crafts an ONNX model whose `STFT` node's `signal` input declares
   `tensor(float)` with **no shape** (graph input `shape=None`).
2. The victim runs the model through `onnxruntime` (CPU EP) with a rank-0 or rank-1
   `signal` tensor (any user-supplied tensor).
3. `STFT::Compute` / `short_time_fourier_transform` reads `signal_shape[...]` out of
   bounds → `std::terminate()` → `SIGABRT`.

## Run

```bash
bash run.sh    # (re)creates venv if needed, builds the model, runs the PoC
```

Expected output: control (rank-2 `signal`) → `RAN-OK`; rank-1 `{1}` and scalar
`signal` → `SIGABRT (-6)` with `terminate called without an active exception`.

## Exploitability assessment

- **Severity**: MEDIUM (5.5) — a denial of service of the inference process.
  `AV:L` / `UI:R` (requires the victim to run an attacker-supplied model), `A:H`
  (unconditional process abort). Disclosed honestly; a remote model-serving API
  would elevate the practical impact but the primitive itself is a process DoS.
- **Deterministic**: yes — the abort is a pure function of the rank mismatch.
- **Verified against the real wheel**: `onnxruntime==1.31.1` (PyPI), differential
  control vs trigger, both triggers `SIGABRT`.

## Self-critique (3 ways this might NOT trigger — checked against source)

1. **Schema shape inference might reject the model at load time.** The model
   declares `shape=None`, so shape inference has no rank to reject; the runtime
   tensor is only seen by the kernel. Confirmed by the control case building and
   running cleanly, and the trigger cases reaching the kernel (not a load error).
2. **`gsl::span` bounds checking might be compiled out of the release wheel.** The
   wheel is built with contract checking that terminates: the shipped siblings
   (AlignAbort/OrtOverrun/AttnOverrun) and this PoC all abort with the exact
   `terminate called without an active exception` message.
3. **The STFT op may not be registered / may reject rank at a higher layer.** It is
   registered in the standard domain (opset 17) and the kernel is reached: the
   control case returns a real output, and only the rank mismatch aborts.

## References

- Vulnerable lines (HEAD): `onnxruntime/core/providers/cpu/signal/dft.cc:645-646`
  (STFT::Compute) and `:552-553` (short_time_fourier_transform); `:427-428` (DFT).
- Class-fix precedent: microsoft/onnxruntime PR #33517 (`9265e05ae9`)
- Sibling PoCs: `poc/AlignAbort/`, `poc/OrtOverrun/`, `poc/AttnOverrun/`
