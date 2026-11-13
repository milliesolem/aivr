# EmbedOverrun — onnxruntime `EmbedLayerNormalization` unvalidated `position_ids` rank → `std::terminate()` crash

**Wildcard (0-day)** in **microsoft/onnxruntime** (~22k★, the de-facto ONNX inference runtime used by Azure ML, Windows ML, and most ONNX model serving).

| Product + version | CVSS | CWE |
|---|---|---|
| microsoft/onnxruntime 1.31.1 (HEAD `4af944f`, unfixed) | **5.5** MEDIUM (`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`) | CWE-617 (reachable assertion) → CWE-248 (uncaught exception → `std::terminate()`) |

## Summary

The `com.microsoft.EmbedLayerNormalization` contrib op (a BERT-family kernel) takes an
optional `position_ids` input (input index 8). Its `CheckInputs` validator reads
`position_ids->Shape()[1]` **before** validating that `position_ids` is rank 2 — and, unlike
`input_ids`, onnxruntime's shape inference never validates the rank of `position_ids` at model
load time. A model that declares a rank-1 `position_ids` therefore loads successfully and then
aborts the runtime with `SIGABRT` when the invalid `TensorShape::operator[]` index trips the GSL
bounds contract and calls `std::terminate()`.

## Root cause

`onnxruntime/contrib_ops/cpu/bert/embed_layer_norm_helper.h` (HEAD `4af944f`):

```cpp
inline Status CheckInputs(const TOpKernelContext* context, bool quantizedVersion = false) {
  ...
  if (!quantizedVersion) {
    const Tensor* position_ids = context->template Input<Tensor>(8);  // optional

    if (nullptr != position_ids) {
      if (input_ids->Shape()[1] != position_ids->Shape()[1]) {   // <-- line 31: position_ids rank NEVER validated
        return ORT_MAKE_STATUS(ONNXRUNTIME, INVALID_ARGUMENT, ...);
      }
      if (position_ids->Shape()[0] != input_ids->Shape()[0] && position_ids->Shape()[0] != 1) {
        return ORT_MAKE_STATUS(ONNXRUNTIME, INVALID_ARGUMENT, ...);
      }
    }
  }
  ...
  const auto& input_dims = input_ids->Shape().GetDims();
  if (input_dims.size() != 2) { ... }   // <-- input_ids rank IS checked, but only AFTER line 31
```

The validator is `check-then-use` in the wrong order: it *uses* `position_ids->Shape()[1]` to
build an error message before it ever *checks* `position_ids` has a second dimension. For a
rank-1 `position_ids`, `Shape()[1]` indexes past the end of the shape vector.

## Exploit chain

1. Build a model with `EmbedLayerNormalization` (`com.microsoft`) and declare the optional
   `position_ids` input with **rank 1** (shape `[N]`).
2. onnxruntime **accepts** the model: its type-and-shape inference validates `input_ids` (rank 2)
   but has no rank rule for `position_ids` (contrast: declaring `input_ids` rank 1 yields a clean
   `ShapeInferenceError: input_ids shall be 2 dimensions`).
3. Run the model. `Compute` → `CheckInputs` → line 31 evaluates `position_ids->Shape()[1]` (invalid
   index for rank 1) → GSL contract check fails → `std::terminate()` → `SIGABRT`.

## Exploitability assessment

- **Preconditions:** an attacker able to feed onnxruntime a crafted model / tensor. This is the
  same threat model as the four sibling onnxruntime kernel bugs (AttnOverrun, FourierOverrun,
  OrtOverrun, AlignAbort): local processing of an untrusted `.onnx`, or a multi-tenant inference
  service that runs attacker-supplied models.
- **Impact:** uncaught abort → denial of service (crash of the host process). No memory
  corruption beyond the guarded shape-vector read; the GSL bounds check converts the OOB read
  into a deterministic crash rather than a corrupting read.
- **Who is the victim.** The party harmed is the operator who runs an attacker-supplied model
  (`UI:R`): a multi-tenant inference service (Azure ML / model-serving hosts) whose shared worker
  is crashed by one tenant's malicious model, or an application that processes an untrusted
  `.onnx` file and is aborted. This is the same victim model as any parser/decoder DoS (a
  malicious document crashes the viewer), not "the attacker crashing their own process".
- **Honest scope:** this is a crash-only DoS, not code execution. CVSS `AV:L` reflects that the
  malicious model is supplied to a local/self-hosted runtime; a remote inference deployment
  accepting arbitrary models would rate `AV:N` but is an uncommon/explicit configuration.

## Fix

None at HEAD `4af944f` (2026-11). The repair is to validate `position_ids` rank before reading
`Shape()[1]` (e.g. `ORT_ENFORCE(position_ids->Shape().NumDimensions() == 2, ...)` ahead of the
line-31 comparison), mirroring the existing `input_ids` rank check at lines 53–57.

## Run

```bash
bash run.sh          # creates a venv (if needed), installs onnxruntime/onnx/numpy, then:
                     #   make_model.py  -> build control + vulnerable .onnx
                     #   exploit.py     -> control runs clean, vulnerable SIGABRTs
```

Expected output:

```
[+] onnxruntime 1.31.1
[CONTROL] position_ids rank 2  -> rc=0
[CONTROL] OK: rank-2 position_ids ran clean (no crash)
[VULN]   position_ids rank 1  -> rc=-6
    stderr: terminate called without an active exception
[VULN]   OK: onnxruntime aborted with SIGABRT — terminate called without an active exception
```

## Self-critique (three ways this might NOT fire, and how each was checked)

1. **Shape inference might reject a rank-1 `position_ids` at load.** *Checked:* the vulnerable
   model loads (`InferenceSession` succeeds) and only aborts at `run()`. The loader's shape rule
   covers `input_ids` but not `position_ids` (verified empirically: rank-1 `input_ids` is
   rejected with `ShapeInferenceError`, rank-1 `position_ids` is not).
2. **The crash might be at a different line than `position_ids->Shape()[1]`.** *Checked:* the
   control model (rank-2 `position_ids`) runs clean, and `input_ids` is rank 2 in both models, so
   `input_ids->Shape()[1]` is valid; the only OOB access on the `position_ids` path is
   `position_ids->Shape()[1]` at line 31 (`Shape()[0]` at line 35 is in-bounds for rank 1).
3. **The `TensorShape::operator[]` might not actually abort in the release wheel.** *Checked:*
   the released wheel aborts with `SIGABRT` (`-6`, "terminate called without an active
   exception"), matching the four sibling onnxruntime findings that use the same primitive.
