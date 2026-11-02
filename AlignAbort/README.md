# AlignAbort — onnxruntime RoiAlign missing input-rank validation → std::terminate() DoS

| | |
|---|---|
| Product / version | Microsoft ONNX Runtime (`onnxruntime` pip 1.31.1, latest release — verified; `main` @ 2026-11-02 `657cc524ed` — verified) |
| Severity / CVSS | **Medium 5.5** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` (crash-only DoS) |
| CWE | CWE-125 (Out-of-Bounds Read) / CWE-20 (Improper Input Validation) |

## What

`RoiAlign<T>::Compute` in `onnxruntime/core/providers/cpu/object_detection/roialign.cc`
reads tensor-shape dimensions **before** calling the input validator:

```cpp
const auto& x_dims = X_ptr->Shape();
const auto& rois_dims = rois_ptr->Shape();
const auto& batch_indices_dims = batch_indices_ptr->Shape();

auto num_channels = x_dims[1];          // line 271 — OOB for rank<2 X
auto num_rois = batch_indices_dims[0];  // line 272 — OOB for rank-0 batch_indices
auto num_roi_cols = rois_dims[1];       // line 273 — OOB for rank<2 rois

auto status = CheckROIAlignValidInput(X_ptr, rois_ptr, batch_indices_ptr);  // line 275 — validation AFTER indexing
```

`TensorShape::operator[]` returns `values_[idx]` from an `InlinedVector<int64_t>` backed
by a `gsl::span`; indexing past the span trips the GSL contract check, which in the
shipped builds calls `std::terminate()` — the process aborts (`SIGABRT`) with
`terminate called without an active exception`. (In builds compiled with contract
checks stripped, the same code becomes a genuine out-of-bounds read of adjacent heap
memory.) `roialign.h:56` additionally reads `X_ptr->Shape()[0]` with no rank check on X.

When the model's graph inputs carry **no shape** (or only dynamic dims), ONNX Runtime's
shape inference cannot reject a rank-mismatched runtime tensor, so the attacker
controls the rank that reaches the kernel — four independent triggers:

| trigger | malformed input | OOB access |
|---|---|---|
| A | `X` rank 1 | `x_dims[1]` (roialign.cc:271) |
| B | `X` rank 2 (missing H/W) | `x_dims[2]`/`x_dims[3]` at the `RoiAlignForward` call (roialign.cc:292-293) |
| C | `batch_indices` rank 0 | `batch_indices_dims[0]` (roialign.cc:272) |
| D | `rois` rank 1 | `rois_dims[1]` (roialign.cc:273) |

This is the exact bug pattern that upstream fixed in **six sibling kernels** on
2026-10-29 (PR #33517, commit `9265e05ae9` — Conv, ConvInteger, QLinearConv,
CropAndResize, Einsum, AffineGrid: "Validate runtime tensor ranks ... so invalid
runtime inputs return a clean INVALID_ARGUMENT ... instead of triggering
gsl::span contract-violation std::terminate() aborts"). `RoiAlign` was not included
and remains vulnerable at `main` as of 2026-11-02 (verified against
`raw.githubusercontent.com/microsoft/onnxruntime/main/...`).

## Exploit chain

1. Attacker crafts an ONNX model whose graph inputs declare element type but **no
   shape** (valid ONNX; onnxruntime loads it without complaint).
2. The model contains a standard-domain `RoiAlign` op (opset 16), present in every
   onnxruntime build (CPU/CUDA/DML/...; CPU kernel shown here).
3. Victim runs the model (`InferenceSession.run`) with a rank-mismatched tensor for
   `X`, `rois`, or `batch_indices` — e.g. a rank-1 float array where the kernel
   expects rank-4.
4. `RoiAlign::Compute` indexes the shape span out of bounds → `std::terminate()` →
   `SIGABRT`. Every run across fresh subprocesses crashed (trigger A reproduced 6/6).

## Threat model & impact (honest preconditions)

- **Who is harmed**: any party whose process runs untrusted ONNX models on
  onnxruntime: model-marketplace / "bring-your-own-model" inference services, MLOps
  platforms, model scanners, offline apps that open downloaded models (the AIVR-era
  agentic tooling routinely runs third-party models). The abort kills the **entire
  process** — all sessions/tenants on that worker, not just the attacker's job.
- **Preconditions**: (1) the model must omit input shapes (model author controls
  this — the model itself is the attack vehicle), (2) the victim runs the model,
  (3) the runtime tensors are attacker-influenced (or the malicious model is paired
  with malicious inputs). No auth needed to *trigger* once the model is accepted;
  the impact is availability only (no code execution, no data read/write observed).
- The conservative `AV:L/UI:R` vector (5.5 Medium) assumes a user opens a malicious
  model file. A service that automatically runs uploaded models maps to
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High** — README claims only
  the conservative number.

## Self-critique (3 ways this might not be a finding — and what I checked)

1. *"Maybe the runtime rejects rank-mismatched inputs before the kernel runs."*
   Checked empirically: with untyped graph inputs, `InferenceSession.run` delivers a
   rank-1 `X` straight to `RoiAlign::Compute`; the abort happens inside the kernel
   (control case with valid ranks runs fine, so the model itself is loadable and the
   op is reachable). Only models that *declare* input shapes get early rejection.
2. *"Maybe upstream already fixed RoiAlign."*
   Checked: `roialign.cc` at `main` on 2026-11-02 still has the index-before-validate
   order (lines 271-275); pip latest (1.31.1, 2026-10) still crashes (this PoC runs
   against it); the 2026-10-29 validation PR covered six siblings but not RoiAlign.
3. *"Maybe it's just an unhandled exception, not a real DoS."*
   Checked: the process terminates via `std::terminate()` (GSL contract), i.e. `SIGABRT`
   with no chance for Python-level exception handling — no try/except in the embedding
   app can contain it. Exit status -6 confirmed in subprocesses.

## Run

```bash
cd poc/AlignAbort
bash run.sh        # creates a venv in /tmp/opencode/aivr-venv, installs
                   # onnxruntime==1.31.1 + numpy + onnx, runs the 4 triggers + control
```

Expected output: a table of 5 cases — control `OK (exit 0)`, triggers A-D each
`SIGABRT (exit -6)` with `terminate called without an active exception` in stderr —
followed by `ALL TRIGGER CASES CRASHED — AlignAbort reproduced`. run.sh exits 0.

## Files

- `run.sh` — end-to-end repro (venv + deps + run)
- `make_model.py` — builds `alignabort.onnx` (untyped-input RoiAlign model)
- `exploit.py` — runs each trigger in a subprocess and verifies the abort
- `finding.json` — machine-checkable evidence contract
