# Skill: T1-T11 Vulnerability Discovery Techniques

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any
- **Source**: audit-markdown-light/METHODOLOGY.md

## Doctrine
No bug found = this pass missed them, not that code is safe. State every lead as a
falsifiable hypothesis: `Developer INTENDED X; actual code does Y when Z`. A
technique that fires is a lead, not a finding; carry it to a bounded oracle with a
negative control before it earns a severity.

## Techniques
- **T1 Intent-vs-Actual**: Names, comments, tests, commits, docs vs behavior; sibling divergence; always/never/must claims.
- **T2 Variable-Domain Expansion**: Valid range is not actual range (signedness, sentinels, enum out-of-set, NaN, empty, huge).
- **T3 Invariant Breaking**: Pre/post/loop/inter-call/global invariants; compose two broken invariants A+B.
- **T4 Error-Path Residue**: Half-commits, bare except/pass, fail-open auth, leaked locks, use-after-free on cleanup.
- **T5 Unreachable Branch**: `assert(false)`, `default: abort()`, `if (false)`, `// can't happen`, dead deny-branch.
- **T6 Semantic Confusion**: Parser A (security) disagrees with parser B (action); PHP/JS type juggling; Unicode/normalization.
- **T7 Temporal/Concurrency**: TOCTOU, signals, async gaps, ABA, unlocked shared map, double-spend.
- **T8 Cross-Layer Gaps**: Compiler UB, short read/write, LD_* env, symlink, proxy-vs-app parsing, container boundary.
- **T9 Pre-Auth Surface**: Everything on the path to the gate; skip_before_action, missing decorator, health/debug route.
- **T10 Emergent Composition**: Individually safe steps compose into a critical primitive.
- **T11 OS-Interaction Boundary**: Syscall, file descriptor, env, privilege drop, IPC, signal, tmpfile.

## Discovery vectors (apply up to ten distinct lenses)
1. Read intent surfaces first: identifiers, comments, docstrings, changelog and commit messages, then diff intent against behavior (T1).
2. Enumerate the type/value domain each input can actually take and test the edges the code forgot (T2).
3. Write down the invariant a function assumes on entry and hunt callers that violate it (T3).
4. Walk every error and cleanup path; ask what state persists when step 2 of 3 fails (T4).
5. Grep dead deny-branches and unreachable guards; a disabled check is a live hole (T5, see stubbed-privilege-check).
6. Diff two parsers on the same bytes (WAF vs app, router vs handler, proxy vs origin) for confusion (T6).
7. Mark shared mutable state and every await/lock boundary around it for TOCTOU and races (T7).
8. Cross a layer boundary on purpose: symlink, env var, short I/O, encoding, container mount (T8).
9. Inventory the pre-auth reachable set: what runs before the gate, and every sibling that skips it (T9).
10. Chain two low-severity primitives into one high-severity one and test the composite (T10/T11).

## Cross-language and stack examples
- Python: bare `except: pass`, `assert` used for authz (stripped under -O), `pickle.loads` on request bytes.
- JavaScript/TypeScript: `==` vs `===` type juggling, prototype pollution via deep merge, unhandled promise rejection swallowing errors.
- Go: ignored `err` with `_`, `defer` on a nil resource, unsynchronized map access under goroutines.
- Java/Kotlin: swallowed `catch (Exception e) {}`, `ObjectInputStream` on untrusted bytes, integer overflow in size math.
- C/C++: signed/unsigned confusion, short `read()`, `if (!(true))` deny-branch, UAF on error unwind.
- Ruby/Rails: `rescue nil`, `skip_before_action`, `send` on a user string, `YAML.load` of a payload.
- PHP: `==` juggling (`"0e123" == "0"`), `unserialize` of a cookie, loose `in_array` without strict flag.

## How to validate
Turn the qualified hypothesis into a bounded, reversible oracle in an authorized
isolated lab, with a negative control that must fail (the guarded sibling, the
enforced config, the credentialed caller). Record target, revision, caller,
request, and observed state change; require signed target-bound proof before
publishing. A static match, a model assertion, or a crash alone is not impact.

## Counterexamples and limits
An unreachable sink, an enforced guard on every path, a sanitizer on the taint,
or documented intended behavior refutes the lead (mark LATENT or NO-BOUNDARY, not
confirmed). Iteration budget: at iter >= 8 with 0 confirmed, spend >= 50% on proof
work; at iter >= 12 with 0 confirmed, stop enumerating and attack the top-3
QUALIFIED leads now.
