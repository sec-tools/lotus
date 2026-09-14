# Skill: Nine Mistake-Prediction Categories

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: METHODOLOGY section 9

## Doctrine
Classify every lead into a concrete mistake category. Naming the category replaces
vague "might be vulnerable" language with a testable prediction and points at the
oracle that would confirm it.

## Categories
1. Boundary (off-by-one, bounds, size math).
2. Initialization (use-before-init, partial construction, default-insecure).
3. Cleanup (leaked locks/handles, half-rollback, UAF on error).
4. Concurrency (TOCTOU, race, ABA, unsynchronized shared state).
5. Type (confusion, juggling, unchecked cast, tag mismatch).
6. Trust (untrusted input trusted, spoofable identity, unauthenticated source).
7. Ordering (check-after-use, wrong middleware order, deferred validation).
8. Comparison (`==` vs `===`, truncated/constant-time, wrong operator).
9. Resource (exhaustion, unbounded allocation, missing quota).

## Discovery vectors (up to ten)
1. For each lead, pick the single best-fitting category and state the prediction it implies.
2. Grep the language-specific tells for that category (see examples below).
3. Look for multiple categories stacking on one code path (Trust + Ordering is classic authz).
4. Use the category to choose the oracle: a Comparison bug wants a crafted equal-looking input; a Concurrency bug wants parallel requests.
5. Check initialization order in constructors, DI wiring, and module import side effects.
6. Walk cleanup/`finally`/`defer`/destructors for residue bugs.
7. Probe boundaries with min, max, zero, negative, empty, and oversized inputs.
8. Inspect comparison operators around auth, quotas, and financial math.
9. Map shared mutable state and its synchronization for concurrency mistakes.
10. Tie resource categories to rate limits, allocation sizes, and recursion depth.

## Cross-language and stack examples
- Type/comparison: PHP `==` juggling, JS `==`, Python truthiness on empty containers.
- Concurrency: Go unsynchronized map, Java double-checked locking, DB check-then-insert.
- Trust/ordering: Rails `skip_before_action`, Express middleware after the handler, client-supplied role fields.
- Resource: unbounded `readAll`, a recursive parser, a zip bomb, N+1 amplification.
- Crypto/identity: `verify=False`, a `none`-alg JWT, `math/rand` for secrets, a static IV or ECB mode.
- Encoding/parsing: double-decoding, canonicalization gaps, XXE and SSTI from just-rendering.

## How to validate and limits
The category is a hypothesis generator, not proof. Confirm with a bounded oracle
and a negative control matched to the category, and require signed target-bound
proof before scoring.
