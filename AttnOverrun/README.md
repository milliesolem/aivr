# AttnOverrun — onnxruntime AttnLSTM unvalidated-rank OOB read → `std::terminate()`

**Wildcard (0-day)** in **microsoft/onnxruntime** (~22k★, the de-facto ONNX inference
runtime). The `com.microsoft.AttnLSTM` CPU kernel reads the input tensor's shape
dims *before* validating its rank; a rank-mismatched (shapeless/low-rank) model input
walks off the shape span and calls `std::terminate()`, aborting the whole process.

| Field    | Value                                                          |
| -------- | -------------------------------------------------------------- |
| Product  | microsoft/onnxruntime — `AttnLSTM` CPU kernel (`deep_cpu_attn_lstm.cc`) |
| Version  | 1.31.1 (and earlier) — **unfixed** at HEAD `4af944ff`          |
| CVSS     | 5.5 **MEDIUM** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| CWE      | CWE-125 (out-of-bounds read) → unhandled `std::terminate()` (DoS) |

## Root cause

```cpp
// onnxruntime/contrib_ops/cpu/attnlstm/deep_cpu_attn_lstm.cc (HEAD 4af944ff)
Status DeepCpuAttnLstmOp::ComputeImpl(OpKernelContext& context) const {
  ...
  const Tensor& X = *context.Input<Tensor>(0);   // [seq_length, batch_size, input_size]
  ...
  auto& X_shape = X.Shape();
  int seq_length = narrow<int>(X_shape[0]);   // line 99
  int batch_size = narrow<int>(X_shape[1]);   // line 100
  int input_size = narrow<int>(X_shape[2]);   // line 101  <-- read BEFORE any rank check
  ...
  Status status = ValidateInputs(             // line 112  <-- rank check is AFTER
      X, W, R, B, sequence_lens, initial_h, initial_c, P, batch_size, ...);
```

`TensorShape` stores its dims in a `gsl::span<int64_t>`. `X_shape[2]` on a tensor
whose actual rank is `< 3` (a model input declared with *no shape*, fed a 2-D/1-D/0-D
tensor) indexes past the span, trips the span's bounds contract, and calls
`std::terminate()`. The abort is not an exception — it kills the entire process.

This is the exact class already fixed (2026-10-29, PR #33517 / `9265e05ae9`) in
`RoiAlign` and six sibling kernels; the fix missed `MaxRoiPool` (→ **OrtOverrun**,
CVE-track PoC) and `AttnLSTM` (→ this finding). There is a second, identical
read-before-check copy in the same file (lines 383–392: `X_shape[2]` is read, then
`if (X_shape.NumDimensions() != 3) return …`).

## Exploit chain

1. Attacker crafts an ONNX model whose `com.microsoft.AttnLSTM` node's input `X`
   declares `tensor(float)` with **no shape** (graph input `shape=None`).
2. The victim runs the model through `onnxruntime` (CPU EP) with an `X` tensor of
   rank 0/1/2 (any user-supplied tensor).
3. `ComputeImpl` reads `X_shape[2]` → out-of-bounds → `std::terminate()` → `SIGABRT`.

## Run

```bash
bash run.sh    # creates a venv (if needed), installs onnxruntime, builds the model, runs the PoC
```

Expected output: control (rank-3 `X`) → clean `INVALID_ARGUMENT`; rank-2 / rank-1 /
scalar `X` → `SIGABRT (-6)` with `terminate called without an active exception`.

## Exploitability assessment

- **Severity**: MEDIUM (5.5) — a denial of service of the inference process.
  `AV:L` / `UI:R` (requires the victim to run an attacker-supplied model), `A:H`
  (unconditional process abort). Disclosed honestly; a remote model-serving API
  would elevate the practical impact but the primitive itself is a process DoS.
- **Deterministic**: yes — the abort is a pure function of the rank mismatch.
- **Verified against the real wheel**: `onnxruntime==1.31.1` (PyPI), differential
  control vs trigger, all three triggers `SIGABRT`.

## References

- Vulnerable line (HEAD): `onnxruntime/contrib_ops/cpu/attnlstm/deep_cpu_attn_lstm.cc:99-101` / `:112`
- Class-fix precedent: microsoft/onnxruntime PR #33517 (`9265e05ae9`)
- Sibling PoCs: `poc/OrtOverrun/`, `poc/AlignAbort/`
