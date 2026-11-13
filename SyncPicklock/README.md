# SyncPicklock — syncthing introducer folder-scope escape

An **introducer** in syncthing is a device that is allowed to vouch for other
devices, but only on folders that are actually shared with the introducer.
Before upstream commit [`466857ae`](https://github.com/syncthing/syncthing/commit/466857ae7a12671ab9b41140b9399c516497335f)
(`fix(model): introducers should not be able to add themselves to folders`,
first released in **v2.1.6**), `model.handleIntroductions()` trusted the folder
ID in the remote `ClusterConfig` without checking that the folder was shared
with the introducer. A malicious or compromised introducer could therefore name
any folder that exists on the victim — including a folder it has no access to —
and get itself appended to that folder's `Devices` list. Syncthing then treats
the introducer as a legitimate member and serves that folder's index and file
data to it.

- **Class:** CWE-639 / CWE-862 — authorization bypass through a user-controlled
  key / missing authorization
- **Impact:** an introducer can read (and, on send-receive folders, modify) a
  folder that was never shared with it
- **Affected:** syncthing through v2.1.5
- **Fixed:** v2.1.6, commit `466857ae`
- **Severity:** CVSS 3.1 `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = 6.8 (Medium).
  `AC:H` is deliberate: the victim does not advertise unshared folder IDs, so
  the attacker must know or guess the target folder's ID. Folder IDs are not
  secrets (common defaults, reused names, leaked by other peers), but treating
  discovery as non-trivial keeps the claim honest. Upstream shipped this as an
  ordinary bug fix, not a security advisory.

## Threat model

The attacker must already be a configured device and be marked as an
`Introducer` by the victim (the normal use case: a semi-trusted peer that
introduces other devices). The attacker does **not** need access to the target
folder, does not need to forge TLS identities, and does not need any local
access. Folder IDs are not secrets; they appear in normal `ClusterConfig`
traffic. This is exactly the boundary the upstream fix restores: an introducer
may vouch for folders shared with it, not for arbitrary folders.

## Reproduction

```bash
bash run.sh
```

The script:

1. extracts the vendored syncthing source snapshot at the vulnerable commit
   (`466857a^`, v2.1.5),
2. adds `poc_test.go` to `lib/model/` and runs it with `POC_MODE=vulnerable`,
3. applies the upstream `fix.patch` (the five-line `SharedWith` check in
   `lib/model/model.go`),
4. runs the same test with `POC_MODE=fixed`.

The driver calls the real `model.handleIntroductions()` with real
`config.FolderConfiguration`, `config.DeviceConfiguration` and
`protocol.ClusterConfig` values. No syncthing logic is re-implemented.

Expected tail:

```
VULNERABLE: introducer added itself to folder 'private', which is not shared with it
...
FIXED: introducer was refused access to folder 'private' while legitimate introductions still work
RESULT: INTRODUCER FOLDER SCOPE ESCAPE CONFIRMED
```

## Why this is the security decision point

`handleIntroductions()` returns the modified `folders` map, which the caller
writes back into the running configuration. A folder's `Devices` list is the
authorization input the model uses when deciding which connected devices may
receive that folder's index and file blocks. The vulnerable build logs
`Sharing folder vouched for by introducer` for the unshared folder; the fixed
build skips the entire folder because it is not `SharedWith(introducer)`, while
still introducing peers into folders that *are* shared with the introducer.

## Files

| File | Purpose |
| --- | --- |
| `poc_test.go` | driver (added to `lib/model/`; drives the real function) |
| `fix.patch` | upstream `466857ae` change to `lib/model/model.go` |
| `src.tar.gz` | vendored upstream source snapshot at `466857a^` |
| `run.sh` | vulnerable-vs-fixed reproduction |
| `finding.json` | machine-checkable evidence record |
