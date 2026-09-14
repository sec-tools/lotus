# Skill: Logic and State Bug Classes

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: any

## Doctrine
Logic bugs live in the gap between intended workflow and actual state transitions.
No sanitizer catches them; they are found by modeling invariants and abusing order,
timing, and comparison.

## Categories
- Business logic: price/quantity/coupon manipulation, negative amounts, step-skipping workflows.
- Comparison: type juggling, `==` vs `===`, non-constant-time compares, truncated compares.
- Initialization: TOCTOU between check and use, partial construction, default-insecure state.
- Type confusion: array where scalar expected, union/tag mismatch, unchecked cast.
- Shared-state residue: cache poisoning, connection-pool credential leak, thread-local bleed.
- Workflow invariants: edit-after-approve, downgrade-then-use, replay, double-spend.

## Discovery vectors (up to ten)
1. Model the intended state machine and list transitions the code fails to forbid.
2. Replay a request/step out of order or twice and observe state.
3. Manipulate money/quantity fields with zero, negative, huge, and fractional values.
4. Race two requests against one resource (parallel checkout, concurrent redeem) for TOCTOU/double-spend.
5. Compare identity/permission fields for juggling and weak operators.
6. Poison a shared cache/session key and read it as another user.
7. Downgrade a resource (plan, role, status) then use a capability the prior state granted.
8. Edit an object after an approval/lock step to bypass review.
9. Inspect pool/thread-local reuse for cross-request credential or context bleed.
10. Look for check-then-act windows where the checked value can change before use.

## Cross-language and stack examples
- Type/comparison juggling: PHP `"0e1"=="0"`, JS `[]==false`/`==` coercion on auth or coupon checks, Python truthiness on empty containers.
- Concurrency/atomicity: Go/Java shared balance updated without a lock or transaction (double-spend); check-then-insert without a unique constraint.
- Broken state machine: skipping a required step (pay then ship) by calling the later endpoint directly; replay of a one-time token.
- Client-trusted fields: `if user.role == "admin"` on a spoofable field; mass-assignment setting `is_admin` or `price`.
- Multi-tenant isolation: cache-key or tenant-id collisions leaking another tenant's response.
- Numeric/rounding: integer overflow or float rounding in price/quota math; negative-quantity refunds.
- Ordering/idempotency: a webhook or retry processed twice; out-of-order events applied without a version check.

## How to validate and limits
Demonstrate the invariant break with a bounded oracle (a duplicated credit, a
skipped approval, a cross-user read) and a negative control where the correct order
is rejected. A single enforced transaction, constraint, or lock can refute the
lead. Require signed target-bound proof; cap self-only effects below critical.
