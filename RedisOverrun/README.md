# RedisOverrun — Redis Cluster-bus out-of-bounds read (CWE-125), 0-day in stable

| Field | Value |
|-------|-------|
| Product | Redis (Redis Cluster) |
| Version | 8.10.3 (latest stable) and earlier; fix not backported |
| CVSS 3.1 | 6.5 MEDIUM `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| CWE | CWE-125 (out-of-bounds read) |

## Root cause

`src/cluster_legacy.c::clusterProcessPacket()` parses PING/PONG/MEET cluster-bus
packets. The gossip `count` (attacker-controlled 16-bit field) is used to compute
the expected packet length with **no check** that it fits within `totlen`:

```c
uint16_t count = ntohs(hdr->count);
explen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
explen += (sizeof(clusterMsgDataGossip)*count);   // <-- unchecked vs totlen

if (hdr->mflags[0] & CLUSTERMSG_FLAG0_EXT_DATA) {
    clusterMsgPingExt *ext = getInitialPingExt(hdr, count);  // hdr + 104*count
    while (extensions--) {
        uint16_t extlen = getPingExtLength(ext);   // <-- OOB read -> SIGSEGV
        ...
```

`getInitialPingExt` returns `hdr + explen`; with `count = 65535` that is ~6.8 MB
past the received packet, while the receive buffer (`RCVBUF_INIT_LEN = 1024`,
grown only to hold `totlen`) is a few KB. The dereference reads out of bounds and
crashes the node.

The fix (`9a5c6e9`, redis#16104, 2026-10-28) rejects the packet up front:

```c
if (totlen < explen) { serverLog(... "exceeds total packet length" ...); return 1; }
```

It has **not** been backported to any stable release (8.10.3 is still
vulnerable), so this is a 0-day in stable Redis Cluster.

## Exploit chain

1. Connect to the cluster-bus port (`base port + 10000`), which is
   unauthenticated (the cluster bus has no auth; the unstable branch added
   `cluster-bus-port-protected-mode` to warn that any host reaching the port can
   speak the cluster protocol).
2. Send a crafted `MEET` packet: `"RCmb"` magic, `totlen = 2256`,
   `count = 65535`, `extensions = 1`, `CLUSTERMSG_FLAG0_EXT_DATA` set.
3. The vulnerable parser computes `explen ≈ 6.8 MB` and reads
   `getPingExtLength()` past the buffer → **SIGSEGV** (remote crash of the node).

## Run

```bash
bash run.sh          # builds vuln (8.10.3) + fixed (9a5c6e9) redis-server, runs exploit.py
```

`build.sh` builds the real redis-server from source (musl toolchain,
`make MALLOC=libc`). `exploit.py` starts each binary in cluster mode and sends the
crafted packet to the bus port:

- **vulnerable 8.10.3**: `redis-server CRASHED (rc=-11, signal=11)` →
  `OOB-READ-CONFIRMED`.
- **fixed 9a5c6e9**: logs `Received invalid meet packet with gossip count 65535
  that exceeds total packet length (2256)` and keeps answering `PING` → `BLOCKED`.

## Exploitability

A remote attacker who can reach the cluster-bus port (same network/VPC, or a
misconfigured exposure) crashes a Redis Cluster node with a single packet — an
unauthenticated DoS against the database. The primitive is an out-of-bounds read;
the demonstrated, reliable effect is the SIGSEGV (availability), with no
exfiltration channel (the read value is not returned to the attacker), so impact
is honesty-scoped to `A:H` MEDIUM rather than an overstated info-leak/RCE.
