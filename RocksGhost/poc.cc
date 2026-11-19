// RocksGhost — proof of concept for a use-after-free in RocksDB's
// ForwardIterator::RebuildIterators (CWE-416), fix #15704 (commit
// dec85e6516630101d2fa9549937bcd88ba7e6e0a, merged 2026-11-17, NOT in any
// release through v11.13.2).
//
// The real bug lives in db/forward_iterator.cc. A tailing iterator can outlive
// its column family: the user drops the column family and destroys its handle
// while the iterator is still open. Then the iterator's SuperVersion (sv_) can
// hold the *last* reference to the ColumnFamilyData (CFD).
//
//   void ForwardIterator::RebuildIterators(bool refresh_sv) {
//     Cleanup(refresh_sv);                         // (1) releases sv_
//     if (refresh_sv) {
//       sv_ = cfd_->GetReferencedSuperVersion(db_); // (2) reads freed cfd_ -> UAF
//     }
//     ReadRangeDelAggregator range_del_agg(&cfd_->internal_comparator(), ...);
//     ...
//   }
//
// Cleanup(true) -> SVCleanup() -> sv_->Unref(). When that SuperVersion was the
// CFD's current SuperVersion, destroying it releases the last CFD reference and
// frees the CFD. Step (2) then dereferences the dangling cfd_ pointer. The fix's
// commit message confirms: "ASAN reports a heap-use-after-free in
// ColumnFamilyData::GetThreadLocalSuperVersion()."
//
// This file transcribes the essential reference-counting semantics verbatim and
// compiles the vulnerable and fixed RebuildIterators side by side. A tiny
// deterministic arena (LIFO reuse + poison-on-free) makes the use-after-free
// observable without AddressSanitizer, exactly like a redzone canary.
//
// Build:  zig c++ -std=c++17 -O1 poc.cc -o poc   (zig 0.14.0)

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <new>

// ---------------------------------------------------------------------------
// Deterministic arena allocator: blocks are poisoned with 0xDE on free and
// reused LIFO, so (a) a read-after-free sees the poison value and (b) the next
// same-size allocation lands on the just-freed block (heap reuse / type
// confusion). This mirrors what AddressSanitizer would flag.
// ---------------------------------------------------------------------------
namespace {
alignas(std::max_align_t) unsigned char g_arena[1 << 16];
size_t g_used = 0;
struct Freelist {
  Freelist* next;
};
Freelist* g_freelist = nullptr;
}  // namespace

void* operator new(std::size_t n) {
  n = (n + 15) & ~std::size_t(15);
  if (g_freelist != nullptr) {
    Freelist* f = g_freelist;
    g_freelist = f->next;
    return f;  // reuse the most-recently-freed block
  }
  void* p = g_arena + g_used;
  g_used += n;
  return p;
}
void operator delete(void* p, std::size_t n) noexcept {
  if (p == nullptr) return;
  n = (n + 15) & ~std::size_t(15);
  std::memset(p, 0xDE, n);  // poison exactly the freed block (not neighbors)
  Freelist* f = static_cast<Freelist*>(p);
  f->next = g_freelist;
  g_freelist = f;
}
void operator delete(void* p) noexcept {
  if (p == nullptr) return;
  std::memset(p, 0xDE, 32);  // fallback (unsized delete); our types are <= 32 bytes
  Freelist* f = static_cast<Freelist*>(p);
  f->next = g_freelist;
  g_freelist = f;
}

// ---------------------------------------------------------------------------
// Faithful transcription of the RocksDB object graph.
// ---------------------------------------------------------------------------

// ColumnFamilyData: reference-counted; a SuperVersion holds one reference.
struct SuperVersion;  // fwd decl (GetReferencedSuperVersion returns one)

struct ColumnFamilyData {
  const char* name_;
  int refs_;
  uint64_t version_number_;

  ColumnFamilyData(const char* name, uint64_t v)
      : name_(name), refs_(0), version_number_(v) {}

  void Ref() { ++refs_; }
  // Returns true when the refcount reaches zero (caller frees the CFD).
  bool UnrefAndTryDelete() {
    --refs_;
    return refs_ == 0;
  }
  uint64_t GetSuperVersionNumber() const { return version_number_; }
  // Returns a new SuperVersion reference. Dereferences this CFD: reads
  // version_number_ and increments refs_. On a dangling CFD this is the
  // read-after-free that ASan flags. (Defined after SuperVersion.)
  SuperVersion* GetReferencedSuperVersion();
};

// SuperVersion: reference-counted; holds a reference to its ColumnFamilyData.
struct SuperVersion {
  ColumnFamilyData* cfd_;
  int refs_;
  uint64_t version_number_;

  explicit SuperVersion(ColumnFamilyData* cfd)
      : cfd_(cfd), refs_(1), version_number_(cfd->version_number_) {
    cfd_->Ref();  // the SuperVersion keeps the CFD alive
  }
  void Ref() { ++refs_; }
  // Returns true when the SuperVersion was destroyed.
  bool Unref() {
    --refs_;
    if (refs_ == 0) {
      Cleanup();
      return true;
    }
    return false;
  }
  void Cleanup() {
    // Releasing the SuperVersion releases its CFD reference; the CFD is freed
    // when that was the last reference.
    if (cfd_->UnrefAndTryDelete()) {
      delete cfd_;
    }
    delete this;
  }
};

// Out-of-line definition (needs the complete SuperVersion type).
SuperVersion* ColumnFamilyData::GetReferencedSuperVersion() {
  return new SuperVersion(this);  // refs_=1, cfd_->Ref() once in the ctor
}

// ForwardIterator: holds a raw (non-owning) pointer to the CFD, and an owning
// reference to a SuperVersion. This matches db/forward_iterator.cc.
struct ForwardIterator {
  ColumnFamilyData* cfd_;  // raw pointer, NOT reference-counted
  SuperVersion* sv_;       // owning SuperVersion reference

  ForwardIterator(ColumnFamilyData* cfd, SuperVersion* sv) : cfd_(cfd), sv_(sv) {
    // The iterator owns the sv_ reference (its refs_ is already 1).
  }

  void Cleanup(bool release_sv) {
    // ... delete child iterators (omitted; not relevant to the lifetime bug) ...
    if (release_sv) {
      SVCleanup();
    }
  }
  void SVCleanup() {
    if (sv_ == nullptr) return;
    if (sv_->Unref()) {
      // sv_ (and possibly cfd_) freed here
    }
  }

  // ---- VULNERABLE (db/forward_iterator.cc @ v11.13.2, before dec85e6) ----
  void RebuildIteratorsVulnerable(bool refresh_sv) {
    Cleanup(refresh_sv);  // releases sv_ -> may free cfd_
    if (refresh_sv) {
      sv_ = cfd_->GetReferencedSuperVersion();  // UAF: reads freed cfd_
    }
  }

  // ---- FIXED (db/forward_iterator.cc @ dec85e6) ----
  void RebuildIteratorsFixed(bool refresh_sv) {
    if (refresh_sv && sv_ != nullptr &&
        sv_->version_number_ == cfd_->GetSuperVersionNumber()) {
      refresh_sv = false;  // sv_ is still current: keep it, never free cfd_
    }
    SuperVersion* new_sv =
        refresh_sv ? cfd_->GetReferencedSuperVersion() : nullptr;
    Cleanup(refresh_sv);
    if (refresh_sv) {
      sv_ = new_sv;
    }
  }
};

// ---------------------------------------------------------------------------
// Scenario helper: build a tailing iterator whose column family is then dropped
// and its handle destroyed, leaving the iterator's SuperVersion as the *last*
// reference to the ColumnFamilyData (cfd refs == 1).
//
// This matches the fix's description: "Destroying the handle of a dropped
// column family leaves the CFD with only the reference of its current
// SuperVersion."
// ---------------------------------------------------------------------------
static ForwardIterator* MakeDroppedCFIterator(const char* cf_name,
                                              uint64_t version) {
  ColumnFamilyData* cfd = new ColumnFamilyData(cf_name, version);
  cfd->Ref();  // the DB handle holds a reference

  SuperVersion* sv = cfd->GetReferencedSuperVersion();  // current SuperVersion

  // User drops the column family and destroys its handle:
  // the handle's reference is released, leaving refs == 1 (held only by sv).
  cfd->UnrefAndTryDelete();  // refs 2 -> 1

  // sv (refs == 1) now holds the last reference to the CFD.
  return new ForwardIterator(cfd, sv);
}

int main() {
  setvbuf(stdout, nullptr, _IONBF, 0);  // unbuffered so output survives any crash
  std::printf("RocksGhost — RocksDB ForwardIterator use-after-free (fix #15704)\n");
  std::printf("vulnerable: db/forward_iterator.cc @ v11.13.2 (Cleanup before GetReferencedSuperVersion)\n");
  std::printf("fixed:      db/forward_iterator.cc @ dec85e6\n\n");

  // =========================================================================
  // 1. VULNERABLE path — Cleanup(true) frees the CFD, then cfd_ is read.
  // =========================================================================
  {
    std::printf("== [1] vulnerable RebuildIterators(true) ==\n");
    ForwardIterator* it = MakeDroppedCFIterator("victim_cf", /*version=*/7);
    std::printf("  before: sv_->version_number_ = %llu (cfd alive, refs=1)\n",
                (unsigned long long)it->sv_->version_number_);

    // RebuildIterators(true):
    //   Cleanup(true) -> SVCleanup -> sv_->Unref() -> SV destroyed ->
    //     cfd->UnrefAndTryDelete() -> refs 0 -> `delete cfd` (poisoned 0xDE).
    //   sv_ = cfd_->GetReferencedSuperVersion() -> reads the freed cfd_.
    it->RebuildIteratorsVulnerable(/*refresh_sv=*/true);

    // sv_ now holds a SuperVersion whose version_number_ was read out of the
    // poisoned (freed) CFD memory: 0xDEDEDEDEDEDEDEDE.
    std::printf("  after:  sv_->version_number_ = 0x%llx  <-- read from freed memory\n",
                (unsigned long long)it->sv_->version_number_);

    bool uaf = (it->sv_->version_number_ == 0xDEDEDEDEDEDEDEDEULL);
    std::printf("  => %s\n",
                uaf ? "ROCKSGHOST-UAF-CONFIRMED (dangling cfd_ dereferenced after free)"
                    : "unexpected: freed memory was not poisoned");

    // ---- heap-reuse / type-confusion consequence ----
    // The iterator's cfd_ still points into the freed block. The next
    // ColumnFamilyData allocation (LIFO reuse) lands on that exact block, so the
    // dangling cfd_ now reads the attacker-reused object.
    ColumnFamilyData* evil = new ColumnFamilyData("EVIL_CFD", /*version=*/0x7777);
    std::printf("  heap reuse: allocated new CFD (LIFO) into the freed block\n");
    std::printf("  dangling cfd_ now reads: name_=%s version_number_=0x%llx\n",
                it->cfd_->name_, (unsigned long long)it->cfd_->GetSuperVersionNumber());
    std::printf("  => %s\n",
                (it->cfd_ == evil && it->cfd_->version_number_ == 0x7777)
                    ? "ROCKSGHOST-TYPE-CONFUSION (iterator operates on a reused object)"
                    : "unexpected: reuse did not alias the dangling pointer");
    std::printf("\n");
  }

  // =========================================================================
  // 2. FIXED path — sv_ is still current, so refresh_sv becomes false, sv_ is
  //    kept, and the CFD is never freed during the rebuild.
  // =========================================================================
  {
    std::printf("== [2] fixed RebuildIterators(true) ==\n");
    ForwardIterator* it = MakeDroppedCFIterator("victim_cf", /*version=*/7);
    std::printf("  before: sv_->version_number_ = %llu (cfd alive, refs=1)\n",
                (unsigned long long)it->sv_->version_number_);

    // The dropped CF never installs a new SuperVersion, so sv_->version_number_
    // == cfd_->GetSuperVersionNumber(): refresh_sv is forced to false. Cleanup
    // (release_sv=false) keeps sv_, and the CFD is never freed.
    it->RebuildIteratorsFixed(/*refresh_sv=*/true);

    std::printf("  after:  sv_->version_number_ = %llu (sv_ kept, cfd_ alive)\n",
                (unsigned long long)it->sv_->version_number_);
    bool ok = (it->sv_->version_number_ == 7 && it->cfd_->GetSuperVersionNumber() == 7);
    std::printf("  => %s\n",
                ok ? "ROCKSGHOST-NO-UAF (fix keeps the column family alive)"
                   : "unexpected: fixed path corrupted state");
    std::printf("\n");
  }

  std::printf("Done.\n");
  return 0;
}
