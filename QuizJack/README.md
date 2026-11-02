# QuizJack — ClassQuiz game takeover via dead captcha gate + predictable PINs

| | |
|---|---|
| **Product / version** | ClassQuiz (mawoka-myblock/ClassQuiz) — `master`, deployed via `ghcr.io/mawoka-myblock/classquiz-backend:master`; bug live since `f3abe4d` (2025-10-25) |
| **CVSS** | 6.5 MEDIUM (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| **CWE** | CWE-804 (unconditionally accepted trust token / fail-open gate), CWE-338 (non-crypto PRNG for an access credential), CWE-307 (unthrottled brute force) |

ClassQuiz is a self-hosted classroom quiz platform (Kahoot alternative, ~735★, used
by schools; official public instance at classquiz.de). Every game session is guarded
by a 6-digit game PIN and — by default — an hCaptcha. This PoC demonstrates that
**the captcha verification never executes** and the **PIN is drawn from a predictable
PRNG and brute-forceable through an unthrottled, unauthenticated oracle**.

## Root cause 1 — the captcha gate is dead code (CWE-804)

`classquiz/socket_server/__init__.py` (master @ `49dca85`), `join_game()`:

```python
    # +++ START checking captcha +++
    if game_data.captcha_enabled:
        captcha_res = check_captcha(data.captcha)   # <-- ASYNC FUNCTION, NOT AWAITED
        if not captcha_res:
            return
    # --- END checking captcha ---
```

`check_captcha()` is `async def`. Calling it without `await` yields a **coroutine
object**, which is always truthy — so `if not captcha_res: return` never fires and
the join proceeds. (Python even prints
`RuntimeWarning: coroutine 'check_captcha_vuln' was never awaited` — reproduced in
the PoC output.) Any client that knows (or guesses) a live PIN joins the lobby with
an arbitrary garbage captcha token. The gate was introduced in the "Cleanup in
socket server" refactor (`f3abe4d2`, 2025-10-25) and is still unfixed on master.

Bonus fail-open in the same helper (`classquiz/socket_server/helpers.py`): when no
hCaptcha/reCAPTCHA keys are configured (typical self-hosting), `check_captcha`
falls through to `return True` — and the hcaptcha branch would raise
`AttributeError` (`resp.model_dump_json()` is not an aiohttp method) if it were ever
awaited.

## Root cause 2 — game PIN from Mersenne Twister + unthrottled oracle (CWE-338/307)

`classquiz/routers/quiz.py` (master @ `49dca85`):

```python
from random import randint          # line 11 — NOT `secrets`
...
    game_pin = randint(100000, 999999)      # line 98 — MT19937, 900k space
```

```python
@router.get("/join/{game_pin}", deprecated=True)   # line 162
async def get_game_id(game_pin: str):              # NO auth dependency, NO rate limit
    redis_res = await redis.get(f"game:{game_pin}")
    if redis_res is None:
        raise HTTPException(status_code=404, detail="game not found")
    else:
        return json.loads(redis_res)["game_id"]
```

`GET /join/<pin>` is an unauthenticated, unthrottled **existence oracle**: 404 vs
`game_id` discloses whether a pin is live (games persist for 5 hours,
`ex=18000`). The full 900k space is exhaustible in minutes with an async client.

## Exploit chain

1. **Enumerate** live PINs: `GET /join/100000` … `GET /join/999999` (no auth, no
   rate limit) — or, with ~1000 observed pins, recover the MT19937 state and
   predict the *next* PIN outright (same class as the ByteSeer/V8 recoveries).
2. **Join** the teacher's lobby over the socket.io endpoint
   (`join_game`) with any garbage captcha — the un-awaited coroutine is truthy,
   so the gate passes.
3. The attacker is a "player": receives the quiz questions as the host plays,
   submits answers, squats student usernames — hijacking/disrupting a live
   classroom session.

## PoC

```
$ python3 poc.py
[A] join_game with INVALID captcha — vulnerable (missing await)
  join accepted: True   (captcha token was INVALID!)
  events: ['joined_game']
[B] same join — fixed (await added) must REJECT the invalid captcha
  join accepted: False   events: []
[C] PIN oracle + brute-force feasibility
  ...
```

The vulnerable `check_captcha`/`join_game` gate and the `randint` PIN generator are
**copied verbatim** from ClassQuiz master (`49dca85`); only redis/socketio/aiohttp
are stubbed. Part [B] runs the same join against the one-token fix (`await`) and
shows it rejects. Part [C]/[D] drive the real oracle logic and the real stdlib
`random` module.

## Threat model (honest)

- Preconditions: none for the oracle; a live game (teacher created a PIN — 5h
  TTL) for the join. The join window is the lobby phase (game must not be
  started yet).
- The captcha bypass alone does not grant RCE or data-store access; impact is
  session hijacking/disruption, early access to quiz questions, and answer
  manipulation as fake students. That is why this is MEDIUM, not higher.
- MT state recovery (predicting the next PIN without brute force) is documented
  but not implemented here — it needs ~1000 observed pins + a GF(2)/z3 solve.

## Remediation

- `await check_captcha(...)` in `join_game` (one token) — and make the helper
  fail-closed when no captcha keys are configured, using the real aiohttp
  `.json()` method.
- Draw PINs from `secrets.randbelow(900000) + 100000`.
- Rate-limit `GET /join/{pin}` (or drop the endpoint — it is deprecated) and the
  socket join event per IP.

## References

- Vulnerable join gate: https://github.com/mawoka-myblock/ClassQuiz/blob/49dca85/classquiz/socket_server/__init__.py#L140-L148
- Vulnerable captcha helper: https://github.com/mawoka-myblock/ClassQuiz/blob/49dca85/classquiz/socket_server/helpers.py#L19-L49
- PIN generation: https://github.com/mawoka-myblock/ClassQuiz/blob/49dca85/classquiz/routers/quiz.py#L98
- PIN oracle: https://github.com/mawoka-myblock/ClassQuiz/blob/49dca85/classquiz/routers/quiz.py#L162-L168
- Introducing commit: https://github.com/mawoka-myblock/ClassQuiz/commit/f3abe4d2c4a638d58b8c0eb6256135acf0d36caa
- Deploy artifact: `docker-compose.yml` pins `ghcr.io/mawoka-myblock/classquiz-backend:master`
