# OrtOverrun — onnxruntime MaxRoiPool unvalidated-rank OOB read → `std::terminate()`

| Product + version | CVSS | CWE |
|---|---|---|
| microsoft/onnxruntime 1.31.1 (HEAD `9ace214`, unfixed) | **5.5** MEDIUM (`CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`) | CWE-125 (OOB read) → CWE-248 (uncaught exception) |

## Summary

`MaxRoiPool` (opset 1, `onnxruntime/core/providers/cpu/nn/roi_pool.cc`) reads the
input `TensorShape` at fixed indices **before any rank validation**:

```cpp
const auto* X = context->Input<Tensor>(0);
const auto* R = context->Input<Tensor>(1);
if (X == nullptr || R == nullptr) return ...;      // only the null check
int batch_size = static_cast<int>(X->Shape()[0]);  // OOB if X is rank 0
int channels   = static_cast<int>(X->Shape()[1]);  // OOB if X is rank < 2
int height     = static_cast<int>(X->Shape()[2]);  // OOB if X is rank < 3
int width      = static_cast<int>(X->Shape()[3]);  // OOB if X is rank < 4
int num_rois   = static_cast<int>(R->Shape()[0]);  // OOB if rois is rank 0
ORT_ENFORCE(R->Shape()[1] == 5);                   // OOB if rois is rank < 2
```

A model whose graph inputs are declared with **type but no shape** bypasses
shape inference, so a runtime tensor with the wrong rank reaches the kernel and
the out-of-bounds `TensorShape::operator[]` trips the GSL contract check →
`std::terminate()` → **SIGABRT of the whole process** (not catchable).

This is the same "read `Shape()[i]` before validating the rank" bug class as the
previously-fixed RoiAlign (PR #33517), but `MaxRoiPool` was not covered by that
fix — it remains unvalidated at HEAD.

## Exploit chain

1. Build/obtain a model whose `MaxRoiPool` node has shapeless (type-only) inputs.
2. Feed a rank-mismatched tensor (e.g. a scalar or rank-2 `X`, or a rank-1 `rois`).
3. The kernel indexes `Shape()[3]` / `Shape()[1]` out of bounds → `std::terminate()`
   → SIGABRT, killing the inference process (any co-located sessions die too).

## Exploitability assessment (honest)

- **Reachability:** requires a model with a shapeless-input `MaxRoiPool` node plus a
  rank-mismatched feed (`UI:R`, local file/artifact the victim loads). Honest
  `AV:L/UI:R` framing — same as the fixed RoiAlign sibling (AlignAbort). A remote
  `AV:N` variant exists only if a model-serving endpoint accepts attacker-supplied
  ONNX models; that is disclosed, not claimed.
- **Impact:** process-abort DoS (A:H). No memory-corruption primitive demonstrated
  — the observable is a clean `std::terminate()`, not a corrupt heap.
- **PoC scope:** real `onnxruntime` 1.31.1 CPU wheel; control case runs clean, the
  three rank-mismatch cases all SIGABRT. Unfixed at HEAD `9ace214`.

## Run

```
bash run.sh
```

Expected: `control_valid_ranks` → exit 0; `A_scalar_X` / `B_rank2_X` /
`C_rank1_rois` → SIGABRT (-6). Exit 0 = PASS.
