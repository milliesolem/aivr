# VaultWormhole — HashiCorp Vault file-audit plugin-directory guard bypass (CWE-22)

Vault's file audit backend writes its log to a configured path. A guard rejects any path
inside Vault's **plugin directory** — the directory Vault scans for executable plugins — so
the audit subsystem can't drop a file (which could be attacker-influenced, and which the fix
also strips of executable bits) where Vault would load it, nor leak audit data into a
privileged location.

In every release through **v2.2.2** that guard lives only in `enableAudit()` (the "enable a
new device" path). **Persisted** audit devices are reconstructed on startup/unseal via
`newAuditBackendWithFormatter()`, which does *not* run the guard — so a persisted file audit
device whose `file_path`/`path` points into the plugin directory is accepted and writes its
log there, crossing the audit↔plugin isolation boundary.

| | |
|---|---|
| **Product / version** | HashiCorp Vault / Vault Enterprise ≤ v2.2.2 (1.x lines too) |
| **CVSS** | **4.4 MEDIUM** — `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-22 (path traversal / improper path validation) |

- **Vulnerable file:** `vault/audit.go` — `newAuditBackendWithFormatter()` (L552) lacks the
  plugin-directory guard that `enableAudit()` (L136–158) has.
- **Fix:** [`60c9bcca2`](https://github.com/hashicorp/vault/commit/60c9bcca2e0e05f306d70241e0c3b06a0f5ae603)
  *SECVULN-65809 "fix(audit): validate paths"* (merged 2026-11-19) — extracts
  `validateAuditFileDestination()` and calls it from `newAuditBackendWithFormatter()`, and
  strips executable mode bits from the audit file.
- **Status:** the fix is **unreleased** — merged 2026-11-19, after the latest release
  `v2.2.2` (2026-11-12). Related prior finding: CVE-2026-5051 (legacy `path` option).

## Root cause

```go
// v2.2.2: enableAudit() validates the plugin-dir guard (L136-158) …
if c.pluginDirectory != "" {
    auditPath := entry.Options["file_path"]
    if auditPath == "" { auditPath = entry.Options["path"] }
    // … walk up the path and reject if it lands in the plugin dir
    return errors.New("audit file target may not be in the plugin directory")
}

// … but newAuditBackendWithFormatter() (L552) — the startup/unseal reconstruction
// path for PERSISTED devices — performs only HasInvalidOptions() and no guard.
// The fix adds:
if err := c.validateAuditFileDestination(entry, conf); err != nil { return nil, err }
```

## Exploit chain

1. A file audit device whose `file_path` points inside the plugin directory is **persisted**
   (written to the storage barrier — via storage access, a backup/restore, or a replication
   path — rather than the guarded `enableAudit` API).
2. On restart/unseal Vault reconstructs the device through `newAuditBackendWithFormatter()`,
   which does not validate the path.
3. The file sink opens `<plugin_dir>/…` and appends audit JSON — writing into the directory
   Vault scans for plugins (and which the fix also makes non-executable), and leaking audit
   records (request/response data) into a privileged location.

## Run

```bash
bash run.sh     # go run poc.go (stdlib only, offline)
```

Expected: `VAULT-WORMHOLE-CONFIRMED` — the vulnerable v2.2.2 path accepts and writes into the
plugin directory; the fixed `validateAuditFileDestination()` rejects it.

## Exploitability (honest)

This is a **defence-in-depth / isolation-boundary** bug, not a remote unauth RCE. Reaching it
requires the ability to persist a malicious audit-device config (storage-write access, or a
restore/replication injection) — hence `PR:H`, `AC:H`, and the MEDIUM (4.4) score. The
security value is that HashiCorp treats the audit↔plugin isolation as a boundary (SECVULN) and
the fix's executable-bit stripping points at the plugin-injection → RCE escalation that the
guard is meant to prevent. The PoC demonstrates the exact guard-bypass primitive (write into
the plugin directory) and the fix's rejection of it; it does not drive a live Vault plugin
load.
