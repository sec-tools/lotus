# Skill: False-Positive Kill Criteria (FP-1..16)

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Gate hard and early. A lead that matches a kill criterion is dead until new
evidence revives it. This is a safety invariant: an AI or tool assertion never
becomes a finding without reachability and a demonstrated boundary crossing.

## Kill immediately
- Test, example, fixture, or docs-only hit with no production reachability.
- Vendored/third-party code without a reachable call from the app.
- Sanitizer or guard already present on all paths to the sink.
- Theoretical issue with no exploit path (LATENT, not confirmed).
- Mirror/reimplementation PoC only (not the shipped artifact).
- Admin-only self-DoS scored as critical.
- Hardcoded secret that exists only in unit-test fixtures.
- Dead code, unreachable branch, or feature disabled by config on the target build.

## Discovery vectors (up to ten)
1. Check the file path: `test/`, `spec/`, `examples/`, `docs/`, `vendor/`, `node_modules/`, `third_party/`.
2. Confirm a real caller from an attacker-reachable entry point exists (not just the sink).
3. Verify no guard/sanitizer sits on the path; if one does, the lead is closed.
4. Distinguish the shipped artifact from a mirror/analog used only to illustrate the class.
5. Ask whether the actor is already privileged (admin abusing admin is not a bypass).
6. Check whether the input is actually attacker-controlled versus operator-configured.
7. Confirm the branch is reachable on the target build (feature flags, compile options, asserts under -O).
8. Look for framework-level defenses (ORM escaping, template auto-escape, CSRF tokens) that neutralize the class.
9. De-duplicate: is this the same root cause as an existing finding under a new name?
10. Require a demonstrated effect; a tool match or model claim alone is a lead, not a finding.

## Qualification labels
QUALIFIED, LATENT, NO-BOUNDARY, MIRROR-ONLY, PRECONDITIONED. Track the
QUALIFIED-to-confirmed rate as the primary discovery-quality KPI.

## Cross-language and stack examples
- Auto-escaped templates (Jinja2, ERB, Razor, React JSX, Thymeleaf) killing a claimed reflected XSS.
- ORM parameterization (SQLAlchemy, ActiveRecord, GORM, Hibernate, Prisma) killing a claimed SQLi at a bound query.
- A fixed executable with validated inert argv arguments can refute shell-metacharacter injection. No-shell execution alone does not refute attacker-selected executables, option injection, or interpreter arguments such as `-c`; trace those boundaries separately.
- A `pickle.loads`/`Marshal.load` reachable only from a unit-test fixture.
- A `verify=False` in a test or dev config path, not the shipped runtime.
- A high-entropy string that is a hash or public key, not a live credential.

## How to validate and limits
Reviving a killed lead requires the specific missing evidence (a reachable path, a
bypassable guard, the shipped binary). Document the kill reason so it is auditable
and not silently re-promoted.

Evidence bar: a static dismissal may cite specific source, reachability, or enforced-guard evidence and must record its scope and reason. An unavailable lab is inconclusive. Promotion to a confirmed finding requires a bounded oracle, a passing negative control, and signed target-bound proof.
