# FumbleFactor — Streamlit-Authenticator weak email 2FA (brute-force bypass)

A proof-of-concept demonstrating that **Streamlit-Authenticator** (`mkhorasani/Streamlit-Authenticator`,
PyPI `streamlit-authenticator`, the de-facto authentication module for Streamlit apps) generates its
email **two-factor-authentication code as a 4-digit number with Python's non-cryptographic `random`
module, and verifies it with no rate limit, lockout, or expiry** — so an attacker who has a victim's
password can brute-force the second factor and take over the account.

| | |
|---|---|
| **Product / version** | Streamlit-Authenticator `<= 0.4.3` (master @ `078b8f6`, 2026-07-01) |
| **CVSS 3.1** | 6.8 **Medium** — `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-330 (insufficient entropy), CWE-338 (weak PRNG), CWE-307 (no lockout on auth attempts) |

## Root cause

Three independent weaknesses combine in the library's email-2FA path:

1. **CWE-330 — 4-digit code.** `AuthenticationModel.generate_two_factor_auth_code` requests a
   `length=4, letters=False, punctuation=False` random string, i.e. a 4-digit numeric code with a
   `10^4 = 10,000`-value keyspace.
2. **CWE-338 — non-cryptographic PRNG.** `Helpers.generate_random_string` uses the stdlib `random`
   module (CPython Mersenne Twister), not `secrets`. `import random` — no `secrets` anywhere in the
   code path.
3. **CWE-307 — no lockout / expiry.** `AuthenticationController.check_two_factor_auth_code` compares
   the submitted code against the stored one and simply returns `False` on mismatch; there is no
   attempt counter, no account lockout, and no time bound on the code.

## Vulnerable code (verbatim)

`streamlit_authenticator/models/authentication_model.py:224-238`

```python
def generate_two_factor_auth_code(self, email: str, widget: Optional[str] = None) -> str:
    two_factor_auth_code = Helpers.generate_random_string(length=4, letters=False,
                                                          punctuation=False)
    st.session_state[f'2FA_code_{widget}'] = self.encryptor.encrypt(two_factor_auth_code)
    self.send_email('2FA', email, two_factor_auth_code)
```

`streamlit_authenticator/utilities/helpers.py:16,76-100`

```python
import random                     # Mersenne Twister, NOT secrets
...
def generate_random_string(cls, length: int=16, letters: bool=True, digits: bool=True,
                           punctuation: bool=True) -> str:
    letters = (string.ascii_letters if letters else '') + \
              (string.digits if digits else '') + \
              (''.join(c for c in string.punctuation if c not in "<>") if punctuation else '')
    return ''.join(random.choice(letters) for i in range(length)).replace(' ','')
```

`streamlit_authenticator/controllers/authentication_controller.py:85-111`

```python
def check_two_factor_auth_code(self, code: str, content=None, widget=None) -> bool:
    if code == self.encryptor.decrypt(st.session_state[f'2FA_code_{widget}']):
        st.session_state[f'2FA_check_{widget}'] = True
        ...
        del st.session_state[f'2FA_code_{widget}']
        return True
    st.session_state[f'2FA_check_{widget}'] = False   # <- no lockout, no expiry, no counter
    return False
```

## Exploit chain

1. Attacker obtains the victim's password (credential-stuffing, phishing, breach reuse) — precisely
   the threat email 2FA is supposed to neutralise.
2. Attacker initiates login as the victim. The server generates a 4-digit code, stores it (encrypted)
   in the session, and emails it to the victim — the attacker cannot read the email.
3. Because `check_two_factor_auth_code` has no rate limit / lockout / expiry, the attacker submits
   `0000`…`9999` against the **same** stored code; success is guaranteed within ≤ 10,000 requests
   (expected ~5,000).
4. The 2FA gate is passed → full account takeover (confidentiality + integrity of the account).

## Exploitability assessment (honest)

- **Preconditions (real):** the attacker must already hold the victim's password; the account must
  have email 2FA enabled; the app must instantiate the widget with `two_factor_auth=True`.
- **What makes it work:** the 10,000-value keyspace is trivially enumerable, and the library ships
  *no* attempt limiting — Streamlit itself does not rate-limit form reruns, and the 2FA check has no
  counter of its own.
- **What this is NOT:** this is not a *remote* (password-less) account takeover, and the
  Mersenne-Twister state is *not* practically recovered from observed codes (each code only leaks a
  few bits). The dominant flaw is the tiny keyspace + absent lockout; the weak PRNG is an aggravating
  factor (CWE-338), not the primary exploit. Severity is capped at **Medium** because the primary
  credential (password) must already be compromised.

## Self-critique (3 ways this trigger might NOT work)

1. **"The app adds its own rate limiting / WAF."** Checked: the library provides no such control, and
   the documented widget path calls `check_two_factor_auth_code` directly. A deployment *could* add
   external rate limiting, but that is not in the library's threat model or code. → *residual risk
   acknowledged; not a library control.*
2. **"A 4-digit code is a deliberate product decision, not a bug."** Checked: the code is genuinely
   generated with a *non-cryptographic* PRNG and compared with no attempt bound — a 4-digit numeric
   second factor for *email* delivery (a channel the attacker does not read) is defensible only if
   brute force is blocked, which it is not. → *the keyspace is only 10^4 and unenforced.*
3. **"Fernet-encrypting the stored code prevents offline guessing."** Checked: the encryption is
   symmetric with a *default* `secret_key='some_key'`, and in any case the brute-force path goes
   through the online `check_two_factor_auth_code` API, which never locks out. → *encryption does not
   gate the online oracle.*

## Fix

- Generate the code with `secrets.choice(string.digits)` at 6+ digits (≥ 10^6 keyspace).
- Enforce an attempt counter + short expiry in `check_two_factor_auth_code` (e.g. 5 attempts, then
  invalidate the code).
- Never use a default/hardcoded `secret_key`.

## Run

```bash
bash run.sh            # or: python3 vuln_demo.py
```

Expected output (exit 0): the vulnerable generator produces a 10,000-value code and the no-lockout
check is brute-forced in ≤ 10,000 guesses; the fixed generator (6 digits + lockout) blocks the same
attack. `python3 drawing_board/poc_gate.py poc/FumbleFactor/ --expect "VULNERABILITY CONFIRMED \+ FIX VERIFIED"`
returns `CONFIRMED`.
