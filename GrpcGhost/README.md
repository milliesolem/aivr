# GrpcGhost — gRPC `FrameProtector` use-after-free (CWE-416)

A use-after-free in gRPC's TLS **secure endpoint** frame protector. A benign
`ResourceQuota` memory-reclamation sweep racing with connection shutdown leaves a
reclaimer callback holding a `[self = Ref()]` strong reference to a `FrameProtector`
that `~Impl()` has already destroyed **in place** (without decrementing its refcount).
The in-flight callback then dereferences freed memory.

| | |
|---|---|
| **Product / version** | gRPC (grpc/grpc) — every release through **v1.85.4** (tagged 2026-11-21) |
| **CVSS** | **5.9 MEDIUM** — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **CWE** | CWE-416 (Use After Free) |

- **Vulnerable file:** `src/core/handshaker/security/secure_endpoint.cc` (also `pipelined_secure_endpoint.cc`)
- **Fix commit:** [`7f3d9778`](https://github.com/grpc/grpc/commit/7f3d97784206d35acd025cb861bf5f84f7bf2226) — *"[Secure Endpoint] Manage FrameProtector via OrphanablePtr to prevent Use After Free during reclamation"* (merged 2026-11-17).
- **Status:** the fix is **unreleased** — it is not an ancestor of `v1.85.4` or any earlier tag, so the bug is live in the latest release. No CVE has been assigned.

## Root cause

`FrameProtector` is reference-counted (`RefCounted<FrameProtector>`) but is
**embedded by value** inside `SecureEndpoint::Impl`:

```cpp
// secure_endpoint.cc @ v1.85.4
class FrameProtector : public RefCounted<FrameProtector> {       // line 83
  void MaybePostReclaimer() {                                     // line 168
    if (!has_posted_reclaimer_.exchange(true, std::memory_order_relaxed)) {
      memory_owner_.PostReclaimer(ReclamationPass::kBenign,
          [self = Ref()](std::optional<ReclamationSweep> sweep) { // line 172
            if (sweep.has_value()) {
              ...
              self->read_mu_.Lock();        // line 179  <-- dereferences freed memory
              ...
            }
          });
    }
  }
  void Shutdown() { shutdown_ = true; memory_owner_.Reset(); }    // line 572
};
// ...
grpc_core::FrameProtector frame_protector_;                       // line 1350 (embedded by value)
```

The lifetime bug is two-fold:

1. **Embedded-by-value + refcounted** — `~Impl()` destroys `frame_protector_` in place
   (its destructor runs, freeing `protector_`/staging buffers) but the refcount is
   *not* decremented — the refcount is owned by `RefCountedPtr`, not the object.
2. **Uncancellable in-flight callback** — when the reclamation sweep has already
   *popped* the reclaimer handle, `ReclaimerQueue::Handle::Orphan()` (invoked by
   `memory_owner_.Reset()` in `Shutdown()`) can no longer cancel it.

If the owning `Impl` is destroyed while the callback is in flight, the callback's
captured `[self = Ref()]` points at freed memory. The fix's own commit message states
it plainly: *"~Impl() destroyed frame_protector_ in place without decrementing its
reference count, and the reclaimer callback subsequently accessed freed memory."*

The fix converts `FrameProtector` to `InternallyRefCounted`, allocates it on the heap,
and holds it via `OrphanablePtr`; `~Impl()` then calls `FrameProtector::Orphan() ->
Unref()`, and the callback's `Ref()` keeps the object alive until it completes.

## Exploit chain

1. Attacker connects to a gRPC TLS endpoint and drives memory pressure (allocates
   staging/decryption buffers), which posts a **benign** reclamation and runs a sweep.
2. The sweep pops the reclaimer handle (callback becomes in-flight).
3. The connection is torn down → `Impl::Shutdown()` → `memory_owner_.Reset()` → the
   handle's `Orphan()` is a no-op (already popped).
4. `~Impl()` destroys `frame_protector_` in place (no `Unref`).
5. The in-flight callback runs `self->read_mu_.Lock()` → **use-after-free** (crash, or
   memory corruption if the freed block is reused by an attacker-influenced allocation).

## Exploitability assessment (honest)

- **This is a real UAF**, fixed by gRPC maintainers as a security change, but its
  practical exploitability is limited by a **narrow race** (AC:H): the reclaimer handle
  must be popped at exactly the moment `Shutdown()` runs, and the endpoint must be
  destroyed before the callback finishes.
- The **observable effect is a crash** (availability). Confidentiality/integrity impact is
  *theoretical* — it would require the freed `Impl` block to be reused by attacker-controlled
  data before the callback dereferences it — so the CVSS vector is scored crash-only
  (`C:N/I:N/A:H`, 5.9 MEDIUM) rather than claiming unproven C/I impact.
- The trigger needs the secure-endpoint memory owner (`ResourceQuota`) path, which is the
  default for gRPC TLS endpoints, but it is **not** reachable by a single crafted packet —
  it requires the reclamation/shutdown interleaving.

**Self-critique — three ways this trigger might not fire, and how each was checked:**

1. *The reclaimer might not actually be in-flight at `Reset()`* — modelled explicitly:
   `Handle::Orphan()` cancels only a *still-queued* callback; our driver pops the handle
   first, exactly the window the fix describes. Without the pop, `Reset()` cancels the
   callback and there is no UAF (verified: the callback never runs).
2. *`~Impl()` might go through `Unref()` after all* — checked against v1.85.4: the member
   is a plain `FrameProtector frame_protector_` (value), whose `~FrameProtector()` only
   tears down `tsi_frame_protector_destroy`/staging buffers and never touches the refcount.
3. *The read might not be observable without ASan* — handled by a deterministic bump arena
   that poisons freed blocks with `0xDE`; the callback's `read_mu_.magic` read returns the
   poison, giving a deterministic differential rather than a sanitizer-only signal.

## Run

```bash
bash run.sh            # builds with zig c++ and runs the vulnerable-vs-fixed differential
```

The driver reproduces the actual **reclamation-vs-shutdown race** with two real threads: the
reclamation thread pops the reclaimer handle (making the callback in-flight) and then runs
the callback on its own thread, while the shutdown thread calls `Shutdown()` (Reset ->
Orphan no-op) and destroys the `Impl`. Expected output (abridged):

```
[vulnerable] ...
  race completed: reclaimer thread ran the in-flight callback against the object freed by the shutdown thread
  callback read_mu_.magic = 0xDEDEDEDEDEDEDEDE (poison) != 0x0000000047525043 (GRPC)
  GRPCGHOST-UAF-CONFIRMED: reclaimer callback dereferenced a freed FrameProtector
[fixed] ...
  callback read_mu_.magic = 0x0000000047525043 (GRPC, intact) - object kept alive by the callback's Ref()
  GRPCGHOST-FIXED-NO-UAF: no use-after-free
VERDICT: use-after-free reproduced on the vulnerable path and absent on the fixed path
```

`poc.cc` is a faithful C++ transcription of the exact vulnerable/fixed lifetime graph
(`RefCounted` + embedded-by-value vs `InternallyRefCounted` + `OrphanablePtr`), compiled with
`zig c++` (0.14.0) and driven against a poisoned deterministic arena. It does **not** link
gRPC itself (a full gRPC build is out of scope here); the bug's presence in `v1.85.4` and its
absence in the unreleased fix `7f3d9778` are verified directly against the upstream source.
No AddressSanitizer is required.
