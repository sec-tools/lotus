# Skill: Race Conditions and TOCTOU (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: concurrency, database, filesystem, payments, auth
- **Signals**: select_for_update, transaction, mutex, flock, idempotency, goroutine, threadpool, compare_and_swap, check-then-act
- **Unique vs**: logic-and-state (single-request logic flaws). This class needs concurrency to manifest.

## Doctrine
A race is a window between check and use where concurrent operations violate an
invariant the code assumes holds. Time-of-check to time-of-use turns a validated
state stale; missing atomicity turns check-balance-then-debit into double-spend. The
bug is the unsynchronized window, provable by concurrent requests.

## Discovery vectors (up to ten)
1. Find check-then-act on shared state: validate, then mutate without a lock or transaction.
2. Find balance, quota, limit, or coupon logic that reads then writes without atomicity (double-spend).
3. Find one-time actions (redeem, activate, withdraw) lacking a unique constraint or idempotency key.
4. Find file TOCTOU: stat or access then open, or a symlink swapped between check and use.
5. Find DB patterns missing `SELECT FOR UPDATE`, optimistic version columns, or serializable isolation.
6. Find in-memory shared maps or counters mutated across threads or goroutines without synchronization.
7. Find get-or-create and upsert paths that can create duplicates under concurrency.
8. Find auth or session races: token refresh, MFA enrollment, or password reset used twice.
9. Assess distributed races across replicas where a single-node lock is insufficient.
10. Look for cache and DB coherence windows leaking or reusing another request state.

## Cross-language and stack examples
- Go/Java: a shared map or balance updated across goroutines or threads without a mutex or transaction.
- Python/Ruby: check-then-debit in a web handler without `select_for_update`; a Sidekiq or Celery job running twice.
- Node: an async read-modify-write on a shared record without a DB constraint or lock.
- SQL: an `UPDATE` after a `SELECT` check without a unique constraint or serializable isolation.
- Filesystem: access then open, or extract then chmod, with a symlink swapped in the window.
- PHP: a session or wallet balance update without a lock; a coupon redeem without a unique constraint.
- Distributed: a Redis `INCR`/Redlock gap or a cross-replica check-then-act without a fencing token.

## How to validate
In the isolated local lab, use a bounded request count and concurrency to measure the
invariant; the oracle is an over-spend, a duplicate one-time action, or a state that
serial execution forbids. Negative control: the same requests run serially must
respect the invariant. Require signed target-bound proof.

## Counterexamples and limits
A DB unique constraint, `SELECT FOR UPDATE`, serializable isolation, an idempotency
key, or a correct lock refutes the race (LATENT). A theoretical window with no
demonstrated invariant violation under concurrency is a lead only.

Evidence bar: a suspected window is a lead, not a finding - confirm with a bounded oracle (a concurrency-only invariant violation such as double-spend or a duplicated one-time action), a passing negative control (serial execution holds the invariant), and signed target-bound proof on the shipped artifact.
