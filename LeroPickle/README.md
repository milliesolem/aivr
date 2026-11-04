# LeroPickle — LeRobot learner gRPC `SendInteractions` pickle deserialization RCE

| Product + version | CVSS | CWE |
| --- | --- | --- |
| HuggingFace **LeRobot** (`huggingface/lerobot`), `main` @ `6e3b67c5f0b77c93a5179d88d7c1d6a5f7ff7b27` (2026-11-04) — ~28.7k★ | **8.8 High** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **CWE-502** (deserialization of untrusted data) |

## What is broken

LeRobot is Hugging Face's end-to-end robotics framework. Its distributed RL mode
splits training into **actors** (run on robots) and a **learner** (runs on a central
training/GPU server). They talk over a gRPC service (`LearnerService`) defined in
`src/lerobot/transport/services.proto`.

The learner's `SendInteractions` RPC receives an actor's "interaction message" (a
small stats dict: episodic reward, interaction step, …), assembles the raw bytes, and
deserializes them with **`pickle.load`** — no `weights_only`, no allow-list, no auth.

```python
# src/lerobot/rl/learner_service.py:120   (gRPC entry — the network boundary)
def SendInteractions(self, request_iterator, _context):
    # TODO: authorize the request                 # <-- no auth
    receive_bytes_in_chunks(request_iterator, self.interaction_message_queue, ...)

# src/lerobot/rl/learner.py:950           (consumer, in the main training loop)
message = bytes_to_python_object(message)

# src/lerobot/transport/utils.py:136      (THE SINK)
def bytes_to_python_object(buffer: bytes) -> Any:
    bytes_buffer = io.BytesIO(buffer)
    bytes_buffer.seek(0)
    obj = pickle.load(bytes_buffer)  # nosec B301: Safe usage of pickle.load
    # Add validation checks here        # <-- the validation was never written
    return obj
```

The gRPC server itself is started **insecure and unauthenticated**:

```python
# src/lerobot/rl/learner.py:543
server.add_insecure_port(f"{host}:{port}")
```

The sibling tensor paths prove the developers already treat this channel as untrusted —
they use the *safe* loader — yet the interaction-message path uses raw `pickle.load`:

```python
# src/lerobot/transport/utils.py:144  (transitions — SAFE)
transitions = torch.load(bytes_buffer, weights_only=True)
# src/lerobot/transport/utils.py:126  (state dict — SAFE)
return torch.load(bytes_buffer, weights_only=True)
```

## Exploit chain

1. Attacker connects to the learner's gRPC `SendInteractions` stream (client-streaming
   RPC, no TLS, no auth).
2. Attacker frames a pickle via the real `send_bytes_in_chunks()` framing
   (`TRANSFER_BEGIN`/`MIDDLE`/`END` `InteractionMessage{transfer_state, data}` chunks).
3. `receive_bytes_in_chunks()` reassembles the bytes and puts them on
   `interaction_message_queue`.
4. The learner main loop calls `process_interaction_messages()` →
   `process_interaction_message()` → `bytes_to_python_object()` → **`pickle.load`**.
5. The pickle's `__reduce__` runs `os.system(...)` → **arbitrary code execution as the
   learner process**.

A message is supposed to be a flat dict of scalars; there is no reason it must be
pickle (it should be protobuf/JSON). `pickle.load` here is a gratuitous RCE primitive
reachable from an unauthenticated network socket.

## Threat model (honest)

- **Default config** (`learner_host = "127.0.0.1"`, `ActorLearnerConfig`): only a local
  process (or an attacker with local code execution) can reach the port. Still RCE, but
  local-only by default (AV:L).
- **Distributed deployment** — the purpose of this transport — sets `learner_host` to a
  LAN/adjacent interface so robots can reach the learner. That makes the unauth RPC
  reachable from the **adjacent network** (AV:A): any host on the training LAN, or any
  compromised robot, gets unauthenticated RCE on the central training server. The field
  is shared by actor-connect and learner-bind, so it is not a public/Internet (`0.0.0.0`)
  binding by design.
- There is no authentication/authorization anywhere: three `# TODO: authorize the
  request` markers, `add_insecure_port`, and no auth interceptor.

Because the network exposure requires a non-default (distributed) deployment and is
adjacent-network rather than Internet-reachable, the honest severity is **High 8.8
(AV:A)**, not Critical AV:N.

## Run it

```bash
cd poc/LeroPickle
bash run.sh        # needs: python3 + grpcio + protobuf (pip install --break-system-packages grpcio protobuf)
```

Expected output ends with:

```
[!] RCE CONFIRMED — arbitrary command executed on the learner:
    LeroPickle_RCE_1000
...
  vulnerable (raw pickle.load on gRPC bytes)  : RCE
  fixed     (restricted unpickler)            : BLOCKED
  RESULT: CONFIRMED — unauthenticated remote pickle.load RCE; fix blocks it.
```

`exploit.py` drives the **real** code: the real generated `services_pb2`/`_grpc`
(verbatim from the repo) over a real `grpc` server, and `vuln.py` contains the exact
vulnerable functions copied verbatim from the repo (`bytes_to_python_object`,
`receive_bytes_in_chunks`, `send_bytes_in_chunks`, `LearnerService`,
`process_interaction_message`) — the only omission is the torch-dependent
`weights_only=True` tensor helpers, which are *not* on the vulnerable path.

## Self-critique (three ways this might NOT work, and how each was checked)

1. **"The actor→learner channel is trusted / same-principal."** The actor runs on a
   robot (a physically distributed, lower-trust edge device); the learner is the central
   server. They are different principals, and the code *itself* flags the missing auth
   (`# TODO: authorize the request` ×3, `add_insecure_port`). The fact that tensor
   paths use `weights_only=True` proves the transport is not trusted for
   deserialization. Checked against `learner_service.py` and `utils.py` source.

2. **"The port is localhost by default, so it isn't remotely reachable."** True for the
   default, and disclosed above. The feature only exists to be deployed distributed
   (`learner_host` set to a network interface), which exposes the unauth RPC. Severity
   is anchored on that intended deployment; the localhost default is a mitigating
   precondition, not a control. Checked `ActorLearnerConfig.learner_host = "127.0.0.1"`.

3. **"A size/type guard blocks the malicious pickle."** `grpc.max_receive_message_length`
   is 4 MB (a pickle is ~100 B), and the message is a raw `bytes data` protobuf field
   with no schema validation before `pickle.load`. Checked `utils.py` (CHUNK_SIZE /
   MAX_MESSAGE_SIZE) and `services.proto` (`InteractionMessage{TransferState, bytes data}`).

## Fix

Serialize interaction messages as protobuf/JSON (they are scalar stats), or at minimum
use the same `torch.load(weights_only=True)` the sibling tensor paths already use, or a
restricted `pickle.Unpickler` with an allow-listed `find_class`. The PoC's "FIX check"
demonstrates a restricted unpickler rejecting the payload. This is a live 0-day — no
upstream fix commit exists yet (verified at `main` on 2026-11-04).
