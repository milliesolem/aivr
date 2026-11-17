# FdbWormhole — CWE-22 path traversal in FoundationDB backup/restore (`fdbdecode --save`)

| Field | Value |
| --- | --- |
| **Product / version** | [apple/foundationdb](https://github.com/apple/foundationdb) **8.0.0** (tagged 2026-10-01) and earlier 7.x |
| **CVSS 3.1** | **6.5 MEDIUM** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` |
| **CWE** | CWE-22 (path traversal) → arbitrary file write (a "zip-slip" for FDB backups) |
| **Fix** | [`414a6ec8`](https://github.com/apple/foundationdb/commit/414a6ec83442fa5dfec1402f47ee645b7fefdb90) (PR [#14347](https://github.com/apple/foundationdb/pull/14347), follows [#14341](https://github.com/apple/foundationdb/pull/14341)) |
| **Release status** | merged to `main` 2026-10-26, backported to **7.4.10** (2026-11-16); **NOT in 8.0.0** — the current 8.x release is still vulnerable |

## Summary

FoundationDB's backup/restore tooling trusts the **file names** it lists out of a backup
container. `pathToLogFile()`, `pathToRangeFile()` and `pathToKeyspaceSnapshotFile()` in
`fdbclient/BackupContainerFileSystem.cpp` parse and validate **only the last path
component** of a listed name (`fileNameOnly()`), then store the **full, attacker-controlled
path** in `fileName`:

```cpp
static bool pathToLogFile(LogFile& out, const std::string& path, int64_t size) {
    std::string name = fileNameOnly(path);   // <-- only the last component is checked
    LogFile f;
    f.fileName = path;                        // <-- FULL path (../ intact) is kept
    ...
}
```

When `fdbdecode --save` (or `fdbrestore`) processes the listed file, `DecodeProgress::openFile()`
in `fdbbackup/FileDecoder.cpp` writes that path **verbatim**:

```cpp
if (save) {
    std::string dir = file.fileName;
    std::size_t found = file.fileName.find_last_of('/');
    if (found != std::string::npos) {
        std::string path = file.fileName.substr(0, found);
        if (!directoryExists(path)) platform::createDirectory(path);  // mkdir -p the dirname (../ included)
    }
    lfd = open(file.fileName.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);  // writes the FULL path
    write(lfd, buf.begin(), file.fileSize);                                  // attacker-controlled bytes
}
```

A listed name such as `logs/../../../../tmp/x/log,1,2,uid,1048576` therefore writes a file
**outside** the operator's intended output directory — an arbitrary-file-write primitive
(the classic CWE-22 "zip-slip" applied to FDB backup containers).

## Exploit chain

1. Attacker controls (or can inject files into) a backup container — an S3/BlobStore bucket or
   an archive listing, where `/` and `..` are legal in a key/name.
2. The container lists a file whose name has a valid log/range/snapshot suffix but a `..`
   prefix, e.g. `../FDBWORMHOLE_PWNED/log,1,2,0123456789abcdef,1048576`.
3. The operator runs `fdbdecode --save` against the container.
4. `pathToLogFile()` accepts the name; `openFile()` creates the parent directory and writes
   the attacker-controlled bytes at the escaped path — outside the decode directory.

## Fix

`relativePathIsContained()` (rejects absolute paths and any `..` component) is now applied to
every listed name via `listedPathIsContained()` before parsing, in the same commit that also
closes the identical pattern in `fetchCheckpointFile()` (checkpoint fetch), the profiler
output path, `MockS3Server`, and `BulkLoadUtil::assertLocalFolderContained()`.

## Run

```bash
bash run.sh
```

Expected: `PATH TRAVERSAL CONFIRMED` for the vulnerable 8.0.0 parser (file written outside the
output directory) and `BLOCKED` for the fixed `main` parser.

## Notes

- PoC compiles a single C++ driver that links the **verbatim** vulnerable functions
  (`fileNameOnly`/`pathToLogFile`/`pathToRangeFile` from 8.0.0 and `FileDecoder.cpp`'s save
  path) and the **verbatim** fixed functions (`relativePathIsContained`/`listedPathIsContained`
  from `main @ 414a6ec8`), with only the FDB logging/`StringRef` plumbing stubbed.
- Verified against the real tree: `git grep` of `8.0.0` shows `f.fileName = path;` with no
  containment check, while `7.4.10` and `main` both carry `listedPathIsContained()`.
- Honest severity (6.5 MEDIUM): the write is **filename-constrained** — the basename must
  still parse as a `log`/`range`/`snapshot` name, so the attacker controls the traversal
  directory and file bytes but cannot overwrite arbitrary-named critical files
  (`authorized_keys`, `/etc/passwd`). Hence `C:N/I:H/A:N`; no total-availability mechanism.
