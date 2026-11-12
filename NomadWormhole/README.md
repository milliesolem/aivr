# NomadWormhole — hashicorp/nomad client sandbox escape via symlink swap

The Nomad task executor calls `makeExecutable()` on a task's command binary before
launching it. In v2.1.0 and earlier that function resolved the path with
`os.Stat`/`os.Chmod`, which **follow symlinks**. A malicious task can therefore
swap its own command path for a symlink pointing at an arbitrary **host** file,
and the executor (running as root) will `chmod` that host file — an escape of the
allocation sandbox.

| Product        | HashiCorp Nomad (client task executor) |
| -------------- | -------------------------------------- |
| Version        | <= 2.1.0 (vulnerable) — 2.1.1 (fixed) |
| CVSS 3.1       | 6.5 MEDIUM — `AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` |
| CWE            | CWE-59 (Improper Link Resolution Before File Access) |

## The bug

```go
// drivers/shared/executor/executor.go — makeExecutable() @ v2.1.0
func makeExecutable(binPath string) error {
	fi, err := os.Stat(binPath)          // follows the symlink
	...
	perm := fi.Mode().Perm()
	req := os.FileMode(0555)
	if perm&req != req {
		if err := os.Chmod(binPath, perm|req); err != nil {   // follows the symlink
			return fmt.Errorf("error making %q executable: %s", binPath, err)
		}
	}
	return nil
}
```

`binPath` is derived from the task's own (sandbox-writable) directory via
`lookupBin()`, which also lacked a lexical-containment check. The fix confines
the chmod through `os.Root`:

```go
// drivers/shared/executor/executor.go — makeExecutable() @ v2.1.1
func makeExecutable(taskDir, binPath string) error {
	...
	root, err := os.OpenRoot(taskDir)      // confinement
	defer root.Close()
	if err := root.Chmod(rel, perm|req); err != nil {   // refuses a link that escapes
		return fmt.Errorf("error making %q executable: %s", binPath, err)
	}
	return nil
}
```

The same audit (NMD-1638 / issue #28605, no public CVE) also fixed:

- **allocdir `Snapshot()` TOCTOU** (`client/allocdir/alloc_dir.go`): the
  allocation-watcher snapshot walked the alloc dir with `filepath.Walk` +
  `os.Readlink` + `os.Open`, a check-then-use gap a malicious task could win to
  archive a host file during a live-migration snapshot (data exfiltration, C:H).
- **`lookupBin()` `../` traversal**: `filepath.Join(taskDir, bin)` with no
  lexical containment let a task's `bin` reference escape the sandbox.

## Exploit chain

1. A malicious task inside a Nomad allocation plants a symlink at its command
   path pointing at a host file (e.g. `/host/path/script.sh`, mode 0644).
2. The executor resolves and `chmod`s the command: `os.Stat`/`os.Chmod` follow
   the symlink and change the **host** file's mode to `0755`.
3. Fixed: `os.OpenRoot(taskDir).Chmod(rel)` returns `path escapes from parent`
   and leaves the host file unchanged.

## Run

```bash
bash run.sh     # Go 1.24+, stdlib only
```

`main.go` drives the verbatim vulnerable (v2.1.0) and fixed (v2.1.1)
`makeExecutable()` logic against a real filesystem: a real symlink in a fake
task dir pointing at a real 0644 host file. Output ends with
`RESULT: SANDBOX ESCAPE CONFIRMED — ...`.

## Assessment

- **Reachability:** any attacker able to run a task (i.e. submit a job) on a
  Nomad client ≤ 2.1.0. The sandbox is meant to contain the task; this breaks
  that boundary.
- **Impact:** integrity violation on the host — the task can make an arbitrary
  host file executable (`0555|perm`). Combined with the sibling `Snapshot()`
  TOCTOU (host file read) the cluster-escape is broader. No direct code
  execution by this primitive alone; honest severity is MEDIUM (6.5).
- **Fix:** commit `3e48ce44034cfaaf7b18103abe5ffb46b2a6ccce`
  ("executor: only make command executable if in sandbox") and
  `81504bce76b2b61e913ab711cb5836d7936903b8`
  ("allocdir: do not archive symlinks that point outside sandbox"), backported
  silently into v2.1.1 (no CVE / no security advisory).

> **PoC fidelity note:** `makeExecutable()` is unexported and the full
> `drivers/shared/executor` package has heavy CGO/cgroup dependencies, so the
> exploit drives the verbatim function bodies (both versions) against a real
> filesystem with real `os.Chmod`/`os.OpenRoot`. Go 1.24's `os.Root` lacks the
> `Chmod` method (added in Go 1.26, which Nomad 2.1.1 requires); the fixed side
> enforces the same confinement via `root.Stat(rel)` before the chmod — see the
> comment in `main.go`.
