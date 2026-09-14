# Skill: Coverage Ledger (five exhaustion gates)

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: SYSTEM D33

## Doctrine
"Done" means either enough demonstrated criticals or a fully exhausted surface with
cited evidence, never an empty ledger. Track coverage per surface so honest exits
are defensible.

## Gates per P1/P2 surface
1. Forward taint mapped (sources to sinks enumerated).
2. Backward sink-first traced (sinks to sources enumerated).
3. Error paths walked (failure and cleanup behavior examined).
4. Dynamic trace exercised (the surface was actually run/observed).
5. Variant analysis complete (siblings and B1-B6 checked).

## Discovery vectors (up to ten)
1. List every P1/P2 surface first; a gate is meaningless without an inventory.
2. For each surface, mark which of the five gates has cited evidence and which is open.
3. Use forward taint and backward reachability as independent passes that should meet in the middle.
4. Drive the surface dynamically to catch behavior static reading missed (gate 4).
5. Walk error/cleanup paths deliberately; residue bugs hide there (gate 3).
6. Run variant analysis against every confirmed and near-miss lead (gate 5).
7. Track QUALIFIED-to-confirmed conversion per surface as a quality signal.
8. Flag surfaces with zero dynamic evidence as not-yet-exhausted regardless of static confidence.
9. Record explicit unreachable verdicts with the guard/constant that closes them.
10. Re-open gates after any code/config change invalidates prior evidence.

## Honest exits
- EXIT_A: at least ten findings with cvss_demonstrated >= 9.0.
- EXIT_B: every P1/P2 surface exhausted (all five gates satisfied with cited evidence).
- Never declare done with an empty ledger or an unset cvss_demonstrated.

## Cross-language and stack examples
- Go service: gates tracked per HTTP route group, gRPC method, and background worker.
- C/C++ broker: gates per protocol frame type and per admin command.
- Python/Django library: gates per public entry function and per parsed format.
- Node/Express API: gates per router and per mounted sub-router (watch unmounted routes).
- Java/Spring: gates per controller and per method-security annotation, plus direct-repository paths.
- Rails: gates per controller action and per `before_action` chain, including `skip_before_action` siblings.

## How to validate and limits
The ledger is evidence, not narration: each satisfied gate cites file:line or a lab
receipt. A surface without dynamic evidence or variant analysis is open, even if it
looks clean on read.

Evidence bar: a gate is closed only with signed target-bound proof or a recorded honest exit; an unproven gate stays open, never assumed.
