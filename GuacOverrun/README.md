# GuacOverrun — Apache Guacamole SSH agent sign-request heap out-of-bounds read (CWE-125)

| | |
|---|---|
| **Product + version** | Apache Guacamole `guacamole-server` @ `bb1ba8e` (current master) |
| **CVSS** | 3.7 LOW — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **CWE** | CWE-125 (Out-of-bounds Read) |

**Status:** wildcard / 0-day-style — present at HEAD, no public fix as of this run.

## Vulnerable code
`src/protocols/ssh/ssh_agent.c` — when the SSH server opens an agent channel and requests a
signature, guacamole-server parses the packet with an **unbounded** length-prefixed string
reader:

```c
/* SSH2_AGENT_SIGN_REQUEST handler */
char* pos = data;                                  // = auth_agent->buffer + 5
buffer_read_string(&pos, &key_blob_length);        // line 117
sign_data = buffer_read_string(&pos, &sign_data_length);   // line 118
ssh_auth_agent_sign(auth_agent, sign_data, sign_data_length);  // line 121
```

`src/common-ssh/buffer.c` — the reader reads a 32-bit length and advances the pointer by that
length with **no bounds check** against the remaining buffer:

```c
char* guac_common_ssh_buffer_read_string(char** buffer, int* length) {
    *length = guac_common_ssh_buffer_read_uint32(buffer);  // 4-byte attacker length
    value = *buffer;
    *buffer += *length;                                    // line 130: unchecked
    return value;
}
```

The enclosing `ssh_auth_agent_read()` check (`buffer_length >= length+4`, line 155) only
constrains the *outer* packet length (and wraps for `length` near `UINT32_MAX`); it never
constrains the inner `key_blob_length` / `sign_data_length` values.

## Exploit chain
1. A user connects to a malicious SSH server through Guacamole with SSH agent forwarding on.
2. The server opens an agent channel and sends an `SSH2_AGENT_SIGN_REQUEST` packet whose
   `key_blob_length` field is huge (e.g. `0x7FFFFFFF`).
3. `buffer_read_string` advances `pos` ~2 GB past the 4096-byte `auth_agent->buffer`; the next
   `buffer_read_string` and `ssh_key_sign` then read heap far out of bounds (attacker-chosen
   length, up to ~4 GB), eventually dereferencing an unmapped page and segfaulting.

## Exploitability assessment
- **Preconditions:** SSH agent forwarding enabled + a malicious/compromised SSH server. `AC:H`.
- **Threat model:** the remote SSH server (an untrusted network peer) triggers a server-side
  memory-safety defect in the gateway.
- **Impact (honest, LOW):** the out-of-bounds bytes are only fed through SHA-1 + a signature
  (the attacker cannot recover heap contents from the returned signature — **no confidentiality
  leak**), and `guacd` runs each connection in a **forked per-connection child process**, so the
  crash terminates only the attacker's own session, which it already controls (**no
  cross-session denial of service**). The defect is a real CWE-125 robustness bug worth fixing,
  but it confers no capability beyond what SSH agent forwarding already grants the server. Hence
  `C:N/I:N/A:L` (3.7 LOW), not the higher severity a raw OOB read might suggest.

## Run
```bash
bash run.sh
```
Compiles `guac_ssh_agent_oob.c` (zig cc or any C compiler) and runs it. It reproduces the
unbounded reader verbatim against a tracked 4096-byte agent buffer and drives the crafted
`SSH2_AGENT_SIGN_REQUEST` packet. Expected output ends with
`GUAC-SSH-AGENT-OOB: HEAP OUT-OF-BOUNDS READ CONFIRMED`.
