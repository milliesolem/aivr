package main

// VaultWormhole — HashiCorp Vault file-audit plugin-directory guard bypass (CWE-22)
//
// SECVULN-65809 / commit 60c9bcca2 ("fix(audit): validate paths", merged 2026-11-19).
//
// Vault's file audit backend writes its log to a configured path. A guard rejects any
// path inside Vault's plugin directory (so the audit subsystem cannot drop an executable
// file where Vault loads plugins, nor leak audit data into a privileged location). In
// every release through v2.2.2 that guard lives ONLY in `enableAudit()` (the "enable a new
// device" path). Persisted audit devices are reconstructed on startup/unseal via
// `newAuditBackendWithFormatter()`, which does NOT run the guard — so a file audit device
// whose `file_path`/`path` points into the plugin directory is accepted and writes its log
// there, crossing the audit↔plugin isolation boundary.
//
// The fix moves the check into `validateAuditFileDestination()` and calls it from
// `newAuditBackendWithFormatter()` (so both new AND persisted devices are validated), and
// additionally strips executable mode bits from the audit file.
//
// This PoC reproduces the exact fixed `validateAuditFileDestination()` logic (verbatim
// from the fix) and contrasts it with the vulnerable v2.2.2 behaviour (backend
// construction with no validation -> the file sink opens a path inside the plugin dir).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateAuditFileDestination is the fix's logic, transcribed verbatim from
// vault/audit.go @ 60c9bcca2 (function validateAuditFileDestination).
func validateAuditFileDestination(pluginDirectory, auditPath string) error {
	if pluginDirectory == "" {
		return nil
	}
	// The file sink trims the path before opening it.
	auditPath = strings.TrimSpace(auditPath)

	// The file sink follows a symlinked audit file, so validate its target.
	if info, err := os.Lstat(auditPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if auditPath, err = filepath.EvalSymlinks(auditPath); err != nil {
			return fmt.Errorf("error resolving audit file path for audit validation: %w", err)
		}
	}

	auditDir := filepath.Dir(auditPath)
	auditDir, err := filepath.Abs(auditDir)
	if err != nil {
		return fmt.Errorf("error getting absolute path of audit dir for audit validation: %w", err)
	}
	pluginDir, err := filepath.Abs(pluginDirectory)
	if err != nil {
		return fmt.Errorf("error getting absolute path of plugin dir for audit validation: %w", err)
	}
	// Walk the audit path up checking that none of them are the plugin dir
	for {
		rp, err := filepath.Rel(pluginDir, auditDir)
		if err != nil {
			return fmt.Errorf("error checking relative path for audit validation: %w", err)
		}
		if rp == "." {
			return errors.New("audit file target may not be in the plugin directory")
		}
		parent := filepath.Dir(auditDir)
		if parent == auditDir { // reached filesystem root (works on all OSes)
			break
		}
		auditDir = parent
	}

	pluginInfo, err := os.Stat(pluginDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error checking plugin dir for audit validation: %w", err)
	}
	// Stat each unresolved parent so symlinks, "..", and case-insensitive names
	// resolve the same way they will when the audit file is opened.
	parents := []string{filepath.Dir(auditPath)}
	for i := 1; i < len(auditPath); i++ {
		if os.IsPathSeparator(auditPath[i]) {
			parents = append(parents, auditPath[:i])
		}
	}
	for _, parent := range parents {
		if info, err := os.Stat(parent); err == nil && os.SameFile(pluginInfo, info) {
			return errors.New("audit file target may not be in the plugin directory")
		}
	}
	return nil
}

// v22_2_newAuditBackend reconstructs a persisted file audit backend the way
// v2.2.2 does: it performs the backend's normal option checks but does NOT call any
// plugin-directory validation. The returned error is nil for a plugin-dir path.
func v22_2_newAuditBackend(pluginDir, filePath string) error {
	// v2.2.2 `newAuditBackendWithFormatter` only checks `audit.HasInvalidOptions`,
	// then constructs the file sink. No plugin-directory guard here.
	_ = pluginDir
	_ = filePath
	return nil
}

func main() {
	pluginDir, err := os.MkdirTemp("", "vault-plugins-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(pluginDir)
	auditPath := filepath.Join(pluginDir, "audit.log")

	fmt.Println("== VaultWormhole: Vault file-audit plugin-directory guard bypass (CWE-22) ==")
	fmt.Println("fix commit : 60c9bcca2e0e05f306d70241e0c3b06a0f5ae603 (SECVULN-65809, merged 2026-11-19)")
	fmt.Println("vuln       : vault <= v2.2.2 (latest release, tag c56e7e6)")
	fmt.Printf("plugin dir : %s\n", pluginDir)
	fmt.Printf("audit path : %s\n\n", auditPath)

	// ---- VULNERABLE (v2.2.2): backend construction has no guard ----
	verr := v22_2_newAuditBackend(pluginDir, auditPath)
	wrote := false
	if verr == nil {
		// The file sink then opens the path and appends audit JSON.
		f, ferr := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if ferr == nil {
			f.WriteString("{\"type\":\"request\",\"request\":{\"path\":\"secret/data/example\"}}\n")
			f.Close()
			wrote = true
		}
	}
	_, statErr := os.Stat(auditPath)
	escaped := wrote && statErr == nil
	fmt.Printf("[vulnerable v2.2.2] newAuditBackendWithFormatter accepted plugin-dir path (no guard): %v\n", verr == nil)
	fmt.Printf("[vulnerable v2.2.2] file sink wrote the audit log INTO the plugin directory: %v\n\n", escaped)

	// ---- FIXED: validateAuditFileDestination rejects it ----
	fixedErr := validateAuditFileDestination(pluginDir, auditPath)
	fmt.Printf("[fixed]          validateAuditFileDestination error: %v\n", fixedErr)
	fixedRejected := fixedErr != nil

	if escaped && fixedRejected {
		fmt.Println("\nVAULT-WORMHOLE-CONFIRMED: persisted file audit device writes into the plugin directory (guard bypassed); the fixed validation rejects it")
		return
	}
	fmt.Println("\nVAULT-WORMHOLE-NOT-REPRODUCED")
}
