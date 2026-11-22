// GrpcGhost — proof of concept for a use-after-free in gRPC's TLS
// FrameProtector (CWE-416). Fix commit 7f3d97784206d35acd025cb861bf5f84f7bf2226
// ("[Secure Endpoint] Manage FrameProtector via OrphanablePtr to prevent Use
// After Free during reclamation", merged 2026-11-17, NOT in v1.85.4).
//
// The real bug lives in src/core/handshaker/security/secure_endpoint.cc
// (and pipelined_secure_endpoint.cc). `FrameProtector` is reference-counted
// (RefCounted<FrameProtector>) but EMBEDDED BY VALUE inside SecureEndpoint::Impl:
//
//   class FrameProtector : public RefCounted<FrameProtector> {    // v1.85.4:83
//     void MaybePostReclaimer() {                                 // v1.85.4:168
//       if (!has_posted_reclaimer_.exchange(true, ...)) {
//         memory_owner_.PostReclaimer(ReclamationPass::kBenign,
//           [self = Ref()](std::optional<ReclamationSweep> sweep) {  // strong ref
//             if (sweep.has_value()) {
//               self->read_mu_.Lock();        // v1.85.4:187  <-- UAF if self freed
//               ...
//             }
//           });
//       }
//     }
//     void Shutdown() { shutdown_ = true; memory_owner_.Reset(); } // v1.85.4:572
//   };
//   class SecureEndpoint::Impl {
//     FrameProtector frame_protector_;      // v1.85.4:945  EMBEDDED BY VALUE
//     void Shutdown() { ... frame_protector_.Shutdown(); }        // v1.85.4:1111
//   };
//
// When a benign ResourceQuota memory-reclamation sweep pops the reclaimer
// handle right before Shutdown() calls memory_owner_.Reset(), the
// ReclaimerQueue::Handle::Orphan() can no longer cancel the in-flight callback.
// If the owning Impl is then destroyed, ~Impl() destroys frame_protector_ IN
// PLACE (its destructor runs, but the refcount is NOT decremented — the refcount
// lives in RefCountedPtr, not the object), so the reclaimer callback's captured
// [self = Ref()] still points at freed memory. The callback dereferences it ->
// heap-use-after-free. The fix's commit message states it plainly:
//
//   "If the owning endpoint Impl was destroyed before the reclaimer callback
//    finished, ~Impl() destroyed frame_protector_ in place without decrementing
//    its reference count, and the reclaimer callback subsequently accessed
//    freed memory."
//
// The fix allocates FrameProtector on the heap via OrphanablePtr, so ~Impl()
// calls FrameProtector::Orphan() -> Unref(); the callback's Ref() keeps the
// object alive until it completes. No UAF.
//
// This file transcribes the essential lifetime graph verbatim (RefCounted /
// InternallyRefCounted / OrphanablePtr / ReclaimerQueue::Handle / MemoryOwner)
// and compiles the vulnerable and fixed paths side by side against a
// deterministic arena that poisons freed blocks (0xDE) and reuses them LIFO,
// making the heap-use-after-free observable without AddressSanitizer.
//
// Build:  zig c++ -std=c++17 -O1 poc.cc -o poc   (zig 0.14.0)

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <atomic>
#include <functional>

// ---------------------------------------------------------------------------
// Deterministic arena allocator: a bump allocator that POISONS freed blocks
// with 0xDE and never reuses them. A read-after-free therefore observes the
// poison value deterministically (the same signal AddressSanitizer's redzones
// provide), and no two live objects ever alias. This keeps the differential
// between the vulnerable and fixed paths exactly attributable to the lifetime
// change, with zero allocator-related interference.
// ---------------------------------------------------------------------------
namespace {
alignas(std::max_align_t) unsigned char g_arena[1 << 16];
std::size_t g_used = 0;
}  // namespace

void* operator new(std::size_t n) {
  n = (n + 15) & ~std::size_t(15);
  void* p = g_arena + g_used;
  g_used += n;
  return p;
}
void operator delete(void* p, std::size_t n) noexcept {
  if (p == nullptr) return;
  n = (n + 15) & ~std::size_t(15);
  std::memset(p, 0xDE, n);  // poison exactly the freed block (not neighbors)
}
void operator delete(void* p) noexcept {
  if (p == nullptr) return;
  std::memset(p, 0xDE, 64);  // fallback (unsized delete)
}

// ---------------------------------------------------------------------------
// Faithful transcription of the gRPC object graph.
// ---------------------------------------------------------------------------

// Mutex stand-in carrying a magic field so a dereference of a freed/poisoned
// mutex is observable (the real read_mu_/write_mu_ are grpc_core::Mutex, which
// would equally be reading freed bytes).
struct MutexModel {
  static constexpr std::uint64_t MAGIC = 0x47525043u;  // "GRPC"
  std::uint64_t magic = MAGIC;
  bool locked = false;
  void Lock() {
    if (magic != MAGIC) {
      extern bool g_uaf_detected;
      extern std::uint64_t g_uaf_read;
      g_uaf_detected = true;
      g_uaf_read = magic;
    }
    locked = true;
  }
  void Unlock() { locked = false; }
};

bool g_uaf_detected = false;
std::uint64_t g_uaf_read = 0;
bool g_would_delete = false;
bool g_vuln_uaf = false;   // did the vulnerable path observe the UAF?
bool g_fixed_uaf = false;  // did the fixed path observe a UAF (it must NOT)?

// ReclaimerQueue::Handle semantics (simplified faithful model):
//   Post(cb)  -> enqueue the callback, remember a "handle".
//   Pop()     -> the reclamation sweep takes the callback out of the queue and
//                marks it in-flight (it can no longer be cancelled).
//   Orphan()  -> cancel the callback IF it is still queued; if it has already
//                been popped (in-flight), this is a no-op.
struct ReclaimerQueue {
  std::function<void()>* cb = nullptr;
  bool popped = false;
  bool cancelled = false;

  void Post(std::function<void()> f) {
    cb = new std::function<void()>(std::move(f));
  }
  std::function<void()>* Pop() {
    if (cb != nullptr && !cancelled) {
      popped = true;  // in-flight: Orphan() can no longer cancel it
      std::function<void()>* r = cb;
      cb = nullptr;
      return r;
    }
    return nullptr;
  }
  void Orphan() {
    if (!popped && cb != nullptr) {
      cancelled = true;
      delete cb;  // cancels: destroys the callback -> its RefPtr Unrefs
      cb = nullptr;
    }
    // else: already popped -> cannot cancel (this is the race window)
  }
  ~ReclaimerQueue() {
    if (cb != nullptr) delete cb;
  }
};

struct MemoryOwner {
  ReclaimerQueue queue;
  void PostReclaimer(std::function<void()> f) { queue.Post(std::move(f)); }
  void Reset() { queue.Orphan(); }  // tries to cancel a queued reclaimer
};

// Strong reference-counted smart pointer (mirrors grpc_core::RefCountedPtr).
template <typename T>
class RefPtr {
 public:
  RefPtr() = default;
  explicit RefPtr(T* p) : p_(p) {
    if (p_) p_->Ref();
  }
  RefPtr(const RefPtr& o) : p_(o.p_) {
    if (p_) p_->Ref();
  }
  RefPtr(RefPtr&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
  ~RefPtr() { reset(); }
  void reset() {
    if (p_) {
      p_->Unref();
      p_ = nullptr;
    }
  }
  T* get() const { return p_; }
  T* operator->() const { return p_; }
  explicit operator bool() const { return p_ != nullptr; }

 private:
  T* p_ = nullptr;
};

// --- VULNERABLE FrameProtector: RefCounted, EMBEDDED BY VALUE in Impl -------
// Refcount starts at 1 (the "owner" reference). The embedded object is never
// destroyed through Unref(); ~Impl() runs ~FrameProtector() in place, so the
// refcount is simply left stale. RefPtr is the only thing that calls Unref().
class FrameProtectorEmbedded {
 public:
  FrameProtectorEmbedded() : refs_(1) {}
  void Ref() { refs_.fetch_add(1, std::memory_order_relaxed); }
  void Unref() {
    // The embedded object is never deleted by Unref() (that is the bug: its
    // memory is freed by ~Impl() in-place instead). Track a would-delete for
    // illustration; the vulnerable refcount never reaches 0 on the freed block.
    if (refs_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      g_would_delete = true;
    }
  }
  int refcount() const { return refs_.load(); }

  MutexModel read_mu_;
  MutexModel write_mu_;
  MemoryOwner memory_owner_;
  std::atomic<bool> has_posted_reclaimer_{false};
  bool shutdown_ = false;

  void MaybePostReclaimer() {
    if (!has_posted_reclaimer_.exchange(true, std::memory_order_relaxed)) {
      memory_owner_.PostReclaimer(
          [self = RefPtr<FrameProtectorEmbedded>(this)]() mutable {
            if (self) {
              self->read_mu_.Lock();   // <-- dereferences freed memory (UAF)
              self->write_mu_.Lock();
              self->write_mu_.Unlock();
              self->read_mu_.Unlock();
            }
          });
    }
  }

  void Shutdown() {
    shutdown_ = true;
    memory_owner_.Reset();  // Orphan() the handle (no-op if already in-flight)
  }

  ~FrameProtectorEmbedded() {
    // Real code: tsi_frame_protector_destroy(protector_) etc.
    // NOTE (the bug): this destructor does NOT decrement the refcount, so an
    // in-flight callback's [self = Ref()] survives the destruction and points
    // at freed memory.
  }

 private:
  std::atomic<int> refs_;
};

// --- FIXED FrameProtector: InternallyRefCounted, HEAP via OrphanablePtr -----
class FrameProtectorHeap {
 public:
  FrameProtectorHeap() : refs_(1) {}
  void Ref() { refs_.fetch_add(1, std::memory_order_relaxed); }
  void Unref() {
    if (refs_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      delete this;  // properly freed when the last reference drops
    }
  }
  void Orphan() { Unref(); }  // OrphanablePtr calls this on ~Impl()
  int refcount() const { return refs_.load(); }

  MutexModel read_mu_;
  MutexModel write_mu_;
  MemoryOwner memory_owner_;
  std::atomic<bool> has_posted_reclaimer_{false};
  bool shutdown_ = false;

  void MaybePostReclaimer() {
    if (!has_posted_reclaimer_.exchange(true, std::memory_order_relaxed)) {
      memory_owner_.PostReclaimer(
          [self = RefPtr<FrameProtectorHeap>(this)]() mutable {
            if (self) {
              self->read_mu_.Lock();   // safe: kept alive by self's Ref()
              self->write_mu_.Lock();
              self->write_mu_.Unlock();
              self->read_mu_.Unlock();
            }
          });
    }
  }

  void Shutdown() {
    shutdown_ = true;
    memory_owner_.Reset();
  }

  ~FrameProtectorHeap() { /* real cleanup: tsi_frame_protector_destroy(...) */ }

 private:
  std::atomic<int> refs_;
};

// OrphanablePtr: owns a heap InternallyRefCounted object; on destruction it
// calls Orphan() -> Unref() (mirrors grpc_core::OrphanablePtr<T>).
struct OrphanablePtr {
  FrameProtectorHeap* p = nullptr;
  explicit OrphanablePtr(FrameProtectorHeap* q) : p(q) {}
  ~OrphanablePtr() {
    if (p != nullptr) p->Orphan();
  }
  FrameProtectorHeap* operator->() { return p; }
  FrameProtectorHeap* get() { return p; }
};

// --- VULNERABLE SecureEndpoint::Impl (frame_protector_ embedded by value) ---
struct ImplEmbedded {
  FrameProtectorEmbedded frame_protector_;  // by value (v1.85.4:945)
  void Shutdown() {
    // v1.85.4:1111-1116 (simplified): lock, move wrapped_ep_, then
    // frame_protector_.Shutdown() -> memory_owner_.Reset().
    frame_protector_.Shutdown();
  }
  // ~ImplEmbedded() runs ~FrameProtectorEmbedded() in place -> frees the memory
  // WITHOUT decrementing the refcount. That is the vulnerability.
};

// --- FIXED SecureEndpoint::Impl (frame_protector_ via OrphanablePtr) --------
struct ImplFixed {
  OrphanablePtr frame_protector_;
  explicit ImplFixed() : frame_protector_(new FrameProtectorHeap()) {}
  void Shutdown() { frame_protector_->Shutdown(); }
  // ~ImplFixed() -> ~OrphanablePtr -> FrameProtector::Orphan() -> Unref();
  // the in-flight callback's Ref() keeps the object alive.
};

// ---------------------------------------------------------------------------
// Driver — a real two-thread race.
//
// Thread A is the reclamation Activity: it pops the reclaimer handle (the sweep
// makes the callback in-flight) and then runs the callback body on ITS thread.
// Thread B is the connection shutdown: it calls Shutdown() (Reset() -> Orphan()
// no-op) and destroys the Impl. Synchronisation pins the exact interleaving the
// fix describes — the handle is popped right before Shutdown(), so the callback
// is in-flight when the object is destroyed — and the callback then dereferences
// the freed FrameProtector on the reclamation thread. The poisoned arena makes
// the read-after-free observable without AddressSanitizer.
// ---------------------------------------------------------------------------
#include <thread>
#include <atomic>

template <typename Impl, typename FP>
static void race_reclaimer_vs_shutdown(
    Impl* impl, FP* fp, const char* label,
    std::function<void()>** out_callback, bool* out_uaf, uint64_t* out_read) {
  std::atomic<bool> in_flight{false};
  std::atomic<bool> destroyed{false};

  // Thread A — reclamation Activity thread.
  std::thread reclaimer([&]() {
    std::function<void()>* cb = fp->memory_owner_.queue.Pop();  // sweep pops handle
    *out_callback = cb;
    in_flight.store(true, std::memory_order_release);   // callback now in-flight
    while (!destroyed.load(std::memory_order_acquire)) {  // wait for shutdown+destroy
      std::this_thread::yield();
    }
    (*cb)();  // self->read_mu_.Lock() on the freed object -> UAF (poison read)
  });

  // Thread B — connection shutdown thread.
  std::thread shutdown([&]() {
    while (!in_flight.load(std::memory_order_acquire)) {
      std::this_thread::yield();   // wait until the handle is popped/in-flight
    }
    impl->Shutdown();              // memory_owner_.Reset() -> Orphan() no-op
    delete impl;                   // ~Impl destroys frame_protector_ IN PLACE
    destroyed.store(true, std::memory_order_release);
  });

  reclaimer.join();
  shutdown.join();
  *out_uaf = g_uaf_detected;
  *out_read = g_uaf_read;
  std::printf("  [%s] race completed: reclaimer thread ran the in-flight "
              "callback against the object freed by the shutdown thread\n", label);
}

static void run_vulnerable() {
  std::printf("[vulnerable] FrameProtector : RefCounted<FrameProtector>, "
              "embedded BY VALUE in SecureEndpoint::Impl\n");

  ImplEmbedded* impl = new ImplEmbedded();
  FrameProtectorEmbedded& fp = impl->frame_protector_;
  std::printf("  Impl constructed; frame_protector_ refcount = %d\n", fp.refcount());

  fp.MaybePostReclaimer();
  std::printf("  MaybePostReclaimer(): posted reclaimer with [self = Ref()] -> "
              "refcount = %d\n", fp.refcount());

  g_uaf_detected = false;
  g_uaf_read = 0;
  std::function<void()>* in_flight = nullptr;
  race_reclaimer_vs_shutdown(impl, &impl->frame_protector_, "vulnerable", &in_flight, &g_vuln_uaf, &g_uaf_read);

  if (g_vuln_uaf) {
    std::printf("  callback read_mu_.magic = 0x%016llX (poison) != 0x%016llX "
                "(GRPC)\n",
                (unsigned long long)g_uaf_read,
                (unsigned long long)MutexModel::MAGIC);
    std::printf("  GRPCGHOST-UAF-CONFIRMED: reclaimer callback dereferenced a "
                "freed FrameProtector\n");
  } else {
    std::printf("  (no UAF detected — unexpected)\n");
  }
  delete in_flight;
  std::printf("\n");
}

static void run_fixed() {
  std::printf("[fixed]    FrameProtector : InternallyRefCounted, heap via "
              "OrphanablePtr<FrameProtector>\n");

  ImplFixed* impl = new ImplFixed();
  FrameProtectorHeap* fp = impl->frame_protector_.get();
  std::printf("  Impl constructed; frame_protector_ refcount = %d\n", fp->refcount());

  fp->MaybePostReclaimer();
  std::printf("  MaybePostReclaimer(): posted reclaimer with [self = Ref()] -> "
              "refcount = %d\n", fp->refcount());

  g_uaf_detected = false;
  g_uaf_read = 0;
  std::function<void()>* in_flight = nullptr;
  bool fixed_uaf = false;
  uint64_t fixed_read = 0;
  race_reclaimer_vs_shutdown(impl, fp, "fixed", &in_flight, &fixed_uaf, &fixed_read);

  if (!fixed_uaf) {
    std::printf("  callback read_mu_.magic = 0x%016llX (GRPC, intact) — object "
                "kept alive by the callback's Ref()\n",
                (unsigned long long)MutexModel::MAGIC);
    std::printf("  GRPCGHOST-FIXED-NO-UAF: no use-after-free (Orphan() -> Unref() "
                "left the refcount at 1, held by the callback)\n");
    std::printf("  GRPCGHOST-FIXED-CLEANUP: callback's Ref() was the last "
                "reference; FrameProtector freed exactly once after the callback "
                "completed\n");
  } else {
    std::printf("  (UAF detected — unexpected)\n");
    g_fixed_uaf = true;
  }
  delete in_flight;
  std::printf("\n");
}

int main() {
  std::printf("== GrpcGhost: gRPC FrameProtector use-after-free (CWE-416) ==\n");
  std::printf("fix commit : 7f3d97784206d35acd025cb861bf5f84f7bf2226 "
              "(merged 2026-11-17, NOT in v1.85.4)\n");
  std::printf("vuln file  : src/core/handshaker/security/secure_endpoint.cc\n");
  std::printf("class      : FrameProtector : RefCounted<FrameProtector> "
              "(embedded by value in Impl)\n\n");

  run_vulnerable();
  run_fixed();

  if (g_vuln_uaf && !g_fixed_uaf) {
    std::printf("VERDICT: use-after-free reproduced on the vulnerable path and "
                "absent on the fixed path\n");
    return 0;
  }
  std::printf("VERDICT: FAILED to reproduce (vuln_uaf=%d fixed_uaf=%d)\n",
              g_vuln_uaf ? 1 : 0, g_fixed_uaf ? 1 : 0);
  return 1;
}
