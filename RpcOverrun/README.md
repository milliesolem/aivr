# RpcOverrun — gRPC RLS `EndpointsEqual()` out-of-bounds read (CWE-125)

| Field | Value |
| --- | --- |
| Product | [gRPC](https://github.com/grpc/grpc) (45k★ RPC framework — Kubernetes, etcd, Istio, …) |
| Affected versions | all releases through **v1.85.2** (fix on master only, unreleased) |
| CVSS 3.1 | **4.8 MEDIUM** `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L` |
| CWE | CWE-125 (out-of-bounds read) |
| Fix commit | [`686404ca`](https://github.com/grpc/grpc/commit/686404ca90192499b488ac6aace7b0095753afe2) (PR [#43732](https://github.com/grpc/grpc/pull/43732), 2026-11-02, master-only) |
| Vulnerable file | `src/core/load_balancing/rls/rls.cc` (line 1926) |

## Summary

In gRPC's **RLS (Route Lookup Service)** load-balancer,
`EndpointsEqual()` compares the previous and new endpoint lists on every
address update. It walks `endpoints2` and indexes `e1_list` (built from
`endpoints1`) with `e1_list[i++]`, but only checks `i` against
`e1_list.size()` **after** the loop:

```cpp
size_t i = 0;
bool different = false;
(*endpoints2)->ForEach([&](const EndpointAddresses& endpoint) {
  if (endpoint != e1_list[i++]) different = true;   // <-- OOB read
});
if (different) return false;
if (i != e1_list.size()) return false;              // checked too late
```

When `endpoints2` has **more** entries than `endpoints1`, `i` runs past the
end of `e1_list` and reads out of bounds. This runs on **every address update**
(old vs new), so a resolver/RLS update that returns more endpoints than the
previous one triggers it. The fix bounds-checks the index inside the loop
before dereferencing:

```cpp
if (i >= e1_list.size() || endpoint != e1_list[i]) different = true;
++i;
```

## Exploit chain

```
victim gRPC client  (rls_experimental LB policy)
   │  RLS lookup → routing response with N endpoints (e.g. 1)
   │  RLS lookup → routing response with >N endpoints (e.g. 2)
   ▼
   RlsLb::UpdateLocked()  →  EndpointsEqual(old=[1], new=[1,2])
        e1_list = [e0]
        ForEach(endpoints2):
            i=0: endpoint != e1_list[0]   (valid)
            i=1: endpoint != e1_list[1]   ← OOB read past the 1-element vector
```

An attacker who can influence the RLS routing decision (a malicious or
compromised RLS server, DNS rebinding of the lookup target, or a MITM on a
non-TLS RLS channel) forces the client to read past the end of the endpoint
vector.

## Reproduction

```bash
bash run.sh     # compiles poc.cc with zig c++ and runs it
```

The PoC reproduces the vulnerable loop verbatim and proves the OOB read by
placing a **canary** `EndpointAddresses` in the slot immediately after
`e1_list`'s single element. Expected output:

```
vulnerable loop: canary_hit=TRUE  <-- OOB read (different=true, i=2, e1_list.size()=1)
fixed loop:      canary_hit=false (different=true, i=2, e1_list.size()=1)
MARKER: RPC-OVERRUN-OOB-READ-CONFIRMED ...
```

## Exploitability assessment

- **Preconditions:** the victim uses gRPC's RLS load-balancer and the RLS
  lookup target is influenced by the attacker (malicious/compromised RLS
  server, or DNS rebinding). The RLS response must grow its endpoint list
  across two consecutive lookups.
- **Impact:** out-of-bounds read (CWE-125) of heap memory adjacent to the
  endpoint vector — an information-disclosure primitive (the OOB bytes are
  compared into the `different` flag) and a potential crash if the OOB read
  forms a `ChannelArgs` whose comparison dereferences a bad pointer. No write
  primitive.
- **Honest CVSS:** `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L` = **4.8 MEDIUM** —
  `AC:H` because the attacker must influence the RLS decision and win a
  two-step endpoint growth; `C:L/A:L` because the read is small and
  non-deterministic, and only crash is probabilistic. (gRPC is so widely
  deployed that even a MEDIUM memory-safety bug in core is notable.)
