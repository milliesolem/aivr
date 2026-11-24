# NomadHiccup — HashiCorp Nomad allocdir snapshot TOCTOU symlink escape

| | |
|---|---|
| **Product / version** | HashiCorp Nomad client (`client/allocdir`) — current release (unreleased fix on `main`, Oct 2026) |
| **CVSS** | 5.6 MEDIUM — `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **CWE** | CWE-362 (TOCTOU race) → CWE-59 (link resolution) / CWE-22 (sandbox escape) |

Fix commit: [`81504bce76`](https://github.com/hashicorp/nomad/commit/81504bce76b2b61e913ab711cb5836d7936903b8)
("allocdir: do not archive symlinks that point outside sandbox") ·
Ref: [nomad#28605](https://github.com/hashicorp/nomad/issues/28605)

## Summary

`AllocDir.Snapshot` streams a running allocation's directory to another client as
a tar archive (alloc migration / the alloc watcher). It walks the alloc dir with
`filepath.Walk` and, for every entry that the walk's **Lstat** classified as a
regular file, opens it with `os.Open` and `io.Copy`s its contents into the
archive.

`os.Open` **follows symlinks**, and `filepath.Walk` hands `walkFn` a *walk-time*
`os.FileInfo`. That is a TOCTOU window: between "Walk saw a regular file" and
"Snapshot opens it", a still-running malicious task can replace one of its own
regular files with a **symlink to a host path** (Nomad's agent TLS key,
`/etc/shadow`, another allocation's secrets…). `Snapshot` then follows the
symlink and archives the **outside-sandbox** file's contents into the stream sent
to another client — an allocation-sandbox escape / cross-tenant & host file
disclosure. (The same unguarded `os.Open` also lets a FIFO/device entry **hang**
the snapshot — an availability side effect the fix addresses too.)

## Vulnerable code (parent `3e48ce44`, `client/allocdir/alloc_dir.go`)

```go
walkFn := func(path string, fileInfo os.FileInfo, err error) error {
    ...
    // Only the WALK-TIME Lstat view gates the symlink branch:
    if fileInfo.IsDir() || (fileInfo.Mode()&os.ModeSymlink != 0) {
        return nil
    }
    // Write the file into the archive — os.Open FOLLOWS a symlink swapped in
    // after Lstat, reaching outside the sandbox.
    file, err := os.Open(path)
    ...
    io.Copy(tw, file)
}
...
filepath.Walk(path, walkFn)
```

The commit message is explicit: *"the alloc watcher was potentially vulnerable to
symlink attacks when we snapshot an allocdir… we had an existing check but it had
a TOCTOU bug… this protects against malicious tasks that manage to avoid shutting
down in a timely fashion before the next client asks for the snapshot."*

## Fix

Open the walked tree through Go 1.24 `os.OpenRoot` and use `root.Open` — a path
jail that **refuses to traverse a symlink escaping the root** — plus a re-`Stat`
of the opened handle that rejects a non-regular file (`"%q changed type during
snapshot"`). This closes both the escape and the FIFO/device hang.

## This PoC

`poc.go` ports the **exact** pre-fix and post-fix `walkFn` bodies and drives them
against a real staged filesystem, reproducing the won-race state (the entry is a
regular file at Lstat time, a symlink to a host secret by open time):

```bash
bash run.sh   # GOTOOLCHAIN=local GOFLAGS=-mod=mod go run poc.go
```

Expected: `ESCAPE CONFIRMED` — the vulnerable archive contains the host secret;
`Control OK` — the fixed `os.OpenRoot` path refuses the escaping symlink
(`path escapes from parent`) and leaks nothing.

## Exploitability assessment (honest threat model)

- **Precondition (AC:H, PR:L, S:C):** the attacker must (1) run a task in an
  allocation (job submit = PR:L), (2) have that alloc snapshotted while still
  running — Nomad normally snapshots a *stopped* alloc, so the task must avoid a
  timely shutdown so the next client's migration request snapshots it live (as
  the maintainer notes), and (3) win the race between the walk's `Lstat` and
  `Snapshot`'s `os.Open`. Winning the TOCTOU reliably needs repeated attempts
  (hence AC:H). The payoff crosses the allocation sandbox (S:C) to read host /
  other-tenant files (C:H).
- **Three ways it might NOT fire, checked against source:**
  1. *Static symlink* — a symlink present at walk time is caught by the
     `fileInfo.Mode()&os.ModeSymlink` branch (header only, no contents). Checked:
     the leak requires the post-Lstat swap, which the PoC models exactly.
  2. *Target larger than the stale header size* — `tar.FileInfoHeader` uses the
     walk-time regular-file size; if the symlink target is larger, the tar writer
     errors. Checked: the attacker sizes its own file ≥ the target (the PoC pads
     `output.log` to 4096 bytes), so the whole secret fits.
  3. *Snapshot only runs on stopped allocs* — then there is no live task to win
     the race. Checked: the fix exists precisely for the "still-running
     allocation" case the maintainer calls out; this is the documented threat.
- **Faithfulness:** the PoC runs the real `os.Open` symlink-follow and the real
  Go 1.24 `os.OpenRoot` jail (the actual fix) against a real filesystem; only the
  surrounding `filepath.Walk` driver is a thin verbatim port. Secrets in samples
  use `EXAMPLE-not-a-real-key`.
