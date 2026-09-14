# Skill: Stubbed Privilege Checks (intent vs a disabled guard)

## Metadata
- **Category**: discovery
- **Language**: c/cpp go java python multi-language
- **Stacks**: any

## Doctrine
Comments, field names, and tests describe a check while the compiled body always
succeeds. `if (!(true)) { deny; }` is a disabled guard, not a review comment. The
gap between stated intent and actual control is the finding (technique T1).

## Discovery vectors (up to ten)
1. Grep always-true/always-false guards: `if (!(true))`, `if (false)`, `if (1)`, `return true` in a deny function.
2. Find privilege fields that are set and then never read before the action.
3. Grep statement/opcode tables for entries marked no-privilege-needed for a privileged action.
4. Find TODO/FIXME/placeholder auth: `// TODO check perms`, `return True  # allow for now`, `AllowAll()`.
5. Detect feature flags that hard-code the permissive branch (a kill switch stuck open).
6. Compare a guard comment ("only your own threads") against the code that ignores ownership.
7. Look for short-circuited checks: an early `return`/`continue` before the deny path executes.
8. Find checks gated on a debug/dev flag that is on in the shipped build.
9. Diff sibling handlers where one enforces and the paste-sibling stubbed it out.
10. Check asserts used as authorization that vanish under optimized builds.

## Cross-language and stack examples
- C/C++: `if (!(true)) return OB_ERR_..._DENIED;`, a `no_priv_needed` opcode for a DCL statement, an authorizer body reduced to `return 0;`.
- Go: `func canDo() bool { return true }`, an unused `role` field, middleware that logs but never returns `403`.
- Java: `@PreAuthorize("permitAll()")` on a privileged method, an `AccessDecisionVoter` returning granted, `isAdmin(){return true;}`.
- Python: `def has_permission(...): return True  # TODO`, `assert user.is_admin` stripped under `-O`, a DRF `AllowAny` on a sensitive view.
- Node/TS: an Express guard that calls `next()` unconditionally, a NestJS `canActivate(){return true;}`.
- Ruby: a `before_action` that returns early, a Pundit/CanCan policy `def admin?; true; end` stub.
- SQL/DB engines: a grant-check routine that early-returns success, or a role whose privilege bitmask is never consulted.

## Lab
Create a restricted principal (e.g. a user with only read privileges). From that
session, attempt the guarded privileged action with a benign, reversible marker.
Oracle: the action succeeds and the effect is observable. Negative control: the
same action must be denied when the guard is enforced. Require signed
target-bound proof.

## Counterexamples and limits
This is distinct from empty-default credentials: default or empty credentials are a
configuration issue (CWE-1188). A stubbed check is a missing authorization in code
(CWE-862) that matters only after a restricted login already exists. If a real
check runs on every path, the lead is closed.
