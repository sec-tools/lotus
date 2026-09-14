"""
Rich seeded skills distilled from audit-markdown-light.

Kept separate from skills.py so seed content can grow without bloating the
runtime module. seed_audit_methodology_skills() in skills.py calls seed_all().

Authoring contract for SEED_FILES (keep every entry portable and honest):
- Start each value with `# Skill:` and keep `## Metadata` with `**Category**`
  and `**Language**` near the top so list_skills() and RAG parse them.
- Front-load the highest-signal content (doctrine + discovery vectors): the
  loader and the RAG indexer read the first slice of each file.
- Give up to ten *distinct* discovery vectors (different lenses, not restatements)
  and concrete cross-language/stack examples so one skill transfers everywhere.
- Preserve evidence discipline: a match is a lead, never a finding. Require a
  bounded oracle, a negative control, and signed target-bound proof. Keep
  deployment identification separate from vulnerability validation.
- Do not use markdown link syntax, horizontal-rule `---` lines in the body, or
  backslashes; describe detection with literal tokens in backticks instead.
"""

from pathlib import Path
from typing import Dict


SEED_FILES: Dict[str, str] = {
    "discovery/t1-t11-discovery-techniques.md": """# Skill: T1-T11 Vulnerability Discovery Techniques

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
""",

    "discovery/sink-first-reachability.md": """# Skill: Sink-First Backward Reachability

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any
- **Source**: Skill 76 / SYSTEM D44

## When it runs
After the initial sink inventory and before spending lab budget on shallow greps.
Working backward from a dangerous sink is higher yield than forward taint from
every input, because sinks are few and attacker inputs are many.

## Method
1. Enumerate crown-jewel sinks: command exec, deserialize, query build, path open, allocation size, privilege grant, template render, redirect/URL fetch.
2. BFS backward through callers up to N hops, recording each frame.
3. Stop when an untrusted source (HTTP body/query/header, CLI arg, env, file, queue message, RPC field) is reached: that is a QUALIFIED lead.
4. Record the full source-to-sink chain as lead_depth evidence with file:line at each hop.

## Discovery vectors (up to ten)
1. Token-grep the sink itself across the repo, then rank hits by proximity to request handlers.
2. Build a call graph (AST or an indexer) and query callers-of-sink transitively.
3. Reverse-taint: treat the sink argument as tainted and propagate backward through assignments and returns.
4. Interprocedural hop across module and package boundaries; sinks are often one wrapper away from the source.
5. Follow framework indirection: route table, dependency injection, event bus, middleware chain, ORM hooks.
6. Cross the process boundary: a sink reached by a queue consumer or RPC server whose producer is attacker-facing.
7. Mine tests that already call the sink with attacker-shaped data (see test-oracle-mining).
8. Check config/DI wiring where the sink argument is bound to a request-scoped value.
9. Diff sibling handlers: if one sanitizes before the sink and a sibling does not, the sibling is the lead.
10. Note reflection/dynamic dispatch (`getattr`, `send`, `Method.invoke`, `reflect`) that hides the edge from static callers.

## Cross-language and stack examples
- Python: `subprocess.run`/`os.system`, `pickle.loads`, `yaml.load`, `eval`, `Template().render`, `open(path)`.
- Node/TS: `child_process.exec`, `vm.runInNewContext`, `res.sendFile`, `db.query(string)`, `JSON` revivers.
- Go: `exec.Command`, `text/template` into shell, `filepath.Join` with `..`, `sql.DB.Query(fmt.Sprintf(...))`.
- Java: `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream.readObject`, `Statement.execute`, `Class.forName`.
- C/C++: `system`, `execve`, `sprintf` size math, `memcpy` length, `dlopen`.
- Ruby: backticks, `Kernel.system`, `Marshal.load`, `constantize`, `render inline:`.

## How to validate
For each P1 sink, either exhibit a concrete source path and prove it with a
bounded oracle plus a negative control, or mark it unreachable-with-evidence
(cite the guard, the constant argument, or the missing edge). Require signed
target-bound proof before a chain becomes a finding.

## Counterexamples and limits
A sink fed only by compile-time constants, a sink behind an enforced allowlist on
every path, or a sink in dead/test code is not reachable. Exit criteria: every P1
sink has either a source path or an evidence-backed unreachable verdict.
""",

    "discovery/guard-alternate-path.md": """# Skill: Guard Alternate Path (the #1 real finding shape)

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any
- **Source**: Skill 49

## Doctrine
The alternate path skips the guard. This is the shape of almost every real authz
and logic finding: the guard exists and is correct on the path you read first, and
a sibling path reaches the same sink without it. Completeness is the whole game.

## Method
1. Inventory every guard: auth middleware, `authorize!`, `@PreAuthorize`, `Gate::allows`, policy check, feature flag, tenant scope.
2. Inventory every path to each sensitive sink (write, delete, privilege change, money move, data read).
3. Classify each path GUARDED or UNGUARDED and record why.
4. Explicit skips (`skip_before_action`, `@public`, `PermitAll`, `csrf_exempt`, `AllowAnonymous`) are P0 leads.

## Discovery vectors (up to ten)
1. Diff sibling routes/controllers: same resource, one guarded, one not.
2. Grep the explicit-skip annotations and list every route they cover.
3. Compare HTTP verbs on one resource: GET guarded, POST/PUT/DELETE/PATCH forgotten.
4. Find second entry points to the same action: GraphQL resolver, gRPC method, CLI, cron, admin panel, batch import, webhook.
5. Check object-level vs route-level authz: login is required but ownership/tenant is not (IDOR; see django-object-authz-gap).
6. Look for guards attached by convention (naming, base class, decorator) that a new handler forgot to inherit.
7. Mine commits that added a guard and check whether every peer call site received the same fix (silent-fix siblings).
8. Inspect middleware ordering: a guard registered after the handler, or short-circuited by an earlier return/redirect.
9. Trace wildcard/catch-all routes and default handlers that bypass per-route guards.
10. Read negative tests: a `test_*_forbidden` that exists for one path and is missing for its sibling.

## Cross-language and stack examples
- Rails: `before_action :authorize` plus a controller that calls `skip_before_action`; `send`-based dispatch.
- Django/DRF: `permission_classes` on one view, `AllowAny` or a raw function view on the sibling.
- Spring: `@PreAuthorize` on the service but a controller that calls the repository directly.
- Express/Koa: auth middleware mounted on `/api` but a route registered on `/internal` or before the middleware.
- Go net/http: `authMiddleware(mux)` wrapping most routes while one handler is registered on the bare mux.
- ASP.NET: `[Authorize]` on the controller but `[AllowAnonymous]` on an action; minimal-API endpoint missing the filter.

## How to validate
Pick one UNGUARDED path to a real sink. In an authorized lab, exercise it without
credentials (or with a lower-privilege identity) and confirm the state change,
then run the guarded sibling as the negative control (it must be denied). Require
signed target-bound proof.

## Counterexamples and limits
If a second guard (gateway, service-layer policy, database RLS) enforces the same
rule on the "unguarded" path, it is defense-in-depth, not a bypass (LATENT).
Completeness is the exit criterion: every reachable path to every sink classified.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the guarded action succeeding when reached through the unguarded sibling route), a passing negative control (the primary guarded route still returns 401/403), and signed target-bound proof on the shipped artifact.
""",

    "discovery/silent-fix-and-variants.md": """# Skill: Silent-Fix Mining and Sibling Variants (B6)

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any, git
- **Signals**: cve, advisory
- **Source**: Skill 82 / Skill 39

## Doctrine
Pinned tags and release notes routinely miss post-tag security fixes. The patch
hands you the exact trigger and the guard that was added; the highest-yield move
is to check whether the same guard is missing on sibling code (variant B6).

## Method
1. Mine commits and PRs matching security keywords: fix, CVE, security, sanitize, escape, bypass, auth, overflow, traversal, injection, ssrf, deserialize.
2. Extract the guard/check that was added and the input it constrains.
3. Generate variants B1-B6: B1 encoding, B2 alternate path, B3 alternate trigger, B4 TOCTOU, B5 bug-in-the-fix, B6 siblings that never got the guard.
4. B6 is P0: a proven bug class in a peer function almost certainly needs the same guard here.

## Discovery vectors (up to ten)
1. `git log` and blame around the sink for security-keyword commits after the pinned tag.
2. Read the linked issue/advisory/CVE to recover the precise payload and preconditions.
3. Search the codebase for other call sites of the same vulnerable function that the fix did not touch.
4. Check whether the fix is complete: encoding, case, Unicode, and nested variants it may not cover (B1/B5).
5. Compare the patched file against its historical siblings copied before the fix (forks, vendored copies, backports).
6. Diff maintenance branches: a fix landed on main but not on the release branch the target ships.
7. Mine dependency changelogs for a bumped library and check whether the app still calls the old unsafe API.
8. Look for revert/re-fix churn indicating an incomplete first fix.
9. Grep tests added by the fix; the new negative test names the exact class to hunt elsewhere.
10. Inspect codegen/templates that emit the vulnerable pattern into many files at once.

## Cross-language and stack examples
- Ruby/Rails: a fix adding `html_escape` in one view; siblings still interpolate raw.
- Node: a patch switching to parameterized queries in one model; other models still template SQL.
- Go: a CVE fix adding `filepath.Clean` and a root check in one extractor; a second extractor unpatched.
- Java: a Jackson/Log4j-era fix disabling a feature in one config; a second `ObjectMapper` left default.
- Python: a fix moving from `yaml.load` to `safe_load` in one loader; another module still unsafe.
- C/C++: a bounds or overflow check added to one parser path in a security commit; a sibling parser left unpatched.
- PHP: a fix switching to a prepared statement in one model while another still concatenates SQL.

## How to validate
Reproduce the original class on the unpatched sibling with a bounded oracle, using
the fixed path as the negative control (it must resist the same payload). Require
signed target-bound proof; a matching diff alone is a lead.

## Counterexamples and limits
If every sibling shares the fixed helper, or a central gateway enforces the guard,
the variant is closed (LATENT). Do not report the already-patched path as a new
finding.
""",

    "discovery/weak-secrets-jwt-oauth.md": """# Skill: Weak Secrets, JWT Header Attacks, and OAuth Confusion

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: jwt, oauth, oidc
- **Signals**: pyjwt, jsonwebtoken, jjwt, jose, authlib, oauthlib, golang-jwt, ruby-jwt, python-jose
- **Source**: Skills 88 / bug-class 117 / 121

## Doctrine
Identity primitives fail in predictable ways: non-cryptographic randomness for
secrets, JWT verification that trusts attacker-controlled headers, and OAuth flows
that validate redirect targets by prefix. Each is a boundary crossing, not a
theoretical weakness, once you show a forged or accepted token.

## Discovery vectors (up to ten)
1. Grep insecure RNG near tokens/secrets/sessions: `random.random`, `Math.random`, `mt_rand`, `srand(time)`, `rand()`.
2. Find JWT `alg` handling that accepts `none` or lets the token pick the algorithm.
3. Detect HS/RS confusion: a public key used as an HMAC secret because verify accepts both families.
4. Trace `kid`, `jku`, `x5u` header use: path/SQL injection via `kid`, SSRF via `jku`/`x5u` fetching keys.
5. Check `redirect_uri` validation for `startsWith`/prefix/substring instead of exact allowlist match.
6. Look for missing PKCE on public clients and unbound/nonrandom `state` (CSRF and code interception).
7. Find hardcoded or defaulted signing secrets in source, config, or test fixtures reused in prod.
8. Check session lifecycle: session id not regenerated on login (fixation), weak remember-me entropy, no rotation.
9. Inspect token audience/issuer/expiry checks; missing `aud`/`iss`/`exp` lets tokens from one service be replayed at another.
10. Diff verification between services: gateway verifies, backend trusts a forwarded identity header without re-verifying.

## Cross-language and stack examples
- Python: `PyJWT` `decode(..., options={'verify_signature': False})` or `algorithms` allowing `none`; `random` for reset tokens.
- Node: `jsonwebtoken.verify` with `algorithms` unset, or `decode()` used as if it verified; `Math.random()` session ids.
- Go: `jwt.ParseUnverified` on a dashboard token; `math/rand` instead of `crypto/rand`.
- Java: `io.jsonwebtoken`/`nimbus` accepting `none`; `new Random()` for CSRF tokens.
- Ruby: `JWT.decode(token, nil, false)`; `SecureRandom` absent where `rand` is used for secrets.
- OAuth (any): `redirect_uri` compared with `starts_with`, wildcard subdomains, or open `state`.

## How to validate
Forge or replay a token in an authorized lab: `alg:none` or an HMAC signed with the
public key, and confirm it is accepted on a protected route; use a correctly signed
token that should be rejected (wrong `aud`/expired) as the negative control. For
OAuth, show a redirect to an attacker origin is accepted. Require signed
target-bound proof.

## Counterexamples and limits
Exact-match redirect allowlists, verification pinned to a single algorithm and key,
`crypto`-grade RNG, and audience/issuer/expiry enforcement refute the lead. A short
secret without a demonstrated forgery is hardening, not a confirmed bypass.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (a token you forged or a secret you predicted accepted at a protected action), a passing negative control (the same forgery is rejected when signature and claim verification are enforced, while a valid authorized token succeeds), and signed target-bound proof on the shipped artifact.
""",

    "methodology/rwx-primitive-coverage-matrix.md": """# Skill: R/W/X Primitive Coverage Matrix

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: TAXONOMIES-AND-ONTOLOGIES.md

## Doctrine
Score by the primitive you can demonstrate (Read, Write, eXecute), not by the
label of the bug. A coverage matrix keeps an audit from over-investing in one
class while a whole primitive family goes unexamined.

## Execute (X)
X-1 OS command, X-3 server-side template injection, X-4 eval/dynamic load,
X-5 deserialization, X-9 SQL-to-OS, X-10 reflection/dynamic dispatch.

## Write (W)
W-1 arbitrary file write, W-3 path-traversal write, W-7 cache/session poisoning,
W-9 prototype pollution, W-11 config/rule write that later executes.

## Read (R)
R-1 arbitrary file read, R-2 SQLi read, R-3 path-traversal read, R-4 SSRF,
R-6 memory disclosure, R-8 cross-tenant object read (IDOR).

## Discovery vectors (up to ten)
1. For each matrix cell, grep the canonical sinks and mark cells with at least one reachable candidate.
2. Convert each candidate to a conviction level (L0 hypothesis to L3 impact) and record the gap to the next level.
3. Look for cross-primitive escalation: a Write that becomes eXecute (drop a webshell, cron, .so, systemd unit, key).
4. Look for Read that enables Write or Execute (leak a secret, then authenticate to an admin sink).
5. Check SSRF (R-4) as a pivot into internal Write/Execute planes (cloud metadata, admin APIs).
6. Map SQLi to both R (dump) and X (stacked queries, `INTO OUTFILE`, UDF) cells.
7. Enumerate deserialization (X-5) across every format the app parses, not just the obvious one.
8. Find template/expression engines (X-3) reachable from request data for SSTI.
9. Audit cache and session stores (W-7) for poisoning that alters another user's execution.
10. Track which cells have zero candidates and say so honestly rather than implying they are safe.

## Cross-language and stack examples
- Execute (X): Python `eval`/`pickle`, Node `vm`/`child_process`, Java `ObjectInputStream`/`ScriptEngine`, Go `exec.Command`/`plugin.Open`, C/C++ `system`/`dlopen`, Ruby `Marshal`/`eval`.
- Write (W): prototype pollution in JS merges, `os.WriteFile`/`filepath.Join` traversal in Go, arbitrary `File.write` in Ruby, Zip Slip in Java, `INTO OUTFILE` in SQL.
- Read (R): `open(user_path)` in Python, `res.sendFile` in Node, `filepath.Join` traversal in Go, `pg_read_file` in SQL, XXE file read in Java, SSRF via any HTTP client.
- Bridges: R-to-X via config-that-executes, W-to-X via a writable plugin/hook path, X-to-RW via a shell.
- End-to-end chains: Node prototype-pollution (W) to a gadget (X); Python LFI (R) to config-exec (X); Go tar traversal (W) to a writable unit/hook (X); SQLi to `INTO OUTFILE` (W) to a web shell (X).

## Conviction ladder
L0 Hypothesis, L1 Reachable, L2 Triggerable (lab effect observed), L3 Impactful
(report-eligible). Memory and write primitives require conviction bridges before
scoring critical: a crash is not control, a write is not execution.

## How to validate and limits
Each claimed cell needs a bounded oracle and a negative control at L2+, and signed
target-bound proof at L3. An empty cell is "not examined / no candidate", never a
guarantee of safety.
""",

    "methodology/severity-honesty.md": """# Skill: Severity Honesty (SH-1..SH-9)

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: SCORING-AND-CALIBRATION.md

## Doctrine
Score the impact you demonstrated, not the ceiling you can imagine. A false
critical costs more trust than a missed medium. Only demonstrated impact counts
for completion.

## Rules
- **SH-1**: Score demonstrated impact, not theoretical ceiling.
- **SH-2**: Mirror/reimplementation PoCs are leads, never ready_to_report.
- **SH-3**: Auth bypass requires an action without credentials AND control with credentials.
- **SH-4**: RCE requires `id`/`uname`/`pwd` (or equivalent) in the actual output of the real target binary.
- **SH-5**: A false critical is worse than a missed bug.
- **SH-6**: Reject inflation mechanisms M1-M5.
- **SH-9**: Only `cvss_demonstrated` counts toward completion, never `cvss_ceiling`.

## Inflation mechanisms to detect (discovery vectors)
1. M1 Scope creep: a local-only effect described with network attack vector.
2. M2 Chained fantasy: assumes a second unproven bug to reach impact.
3. M3 Admin-only as critical: a privileged actor abusing their own privilege.
4. M4 Local-only scored as remote: no network path shown.
5. M5 Unreachable preconditions: requires an attacker position that does not exist.
6. Confidence laundering: an AI/tool assertion restated as a proven fact.
7. Ceiling-as-actual: CVSS computed from worst-case sub-scores never observed.
8. Self-DoS inflation: an authenticated user crashing only their own session/tenant.
9. Duplicate stacking: the same root cause reported as several criticals.
10. PoC-on-mirror: exploited on a reimplementation, not the shipped artifact (SH-2).

## Cross-language and stack examples
- C/C++: a `panic`/segfault in a fuzz harness reported as RCE without a control-flow-hijack bridge.
- Web (any): a SQL error message read as SQLi-confirmed without data exfil or a write demonstrated.
- Java/Go: an admin-only endpoint that runs commands, scored critical when only an admin can reach it (SH-3/M3).
- Python/Node: a `verify=False`/`rejectUnauthorized:false` flagged as MITM without a demonstrated intercept.
- Mirror/reimplementation: a PoC that works on a rewritten harness, not the shipped binary (SH-2).
- Local-only: a config an operator already controls reaching a local command, scored as remote (M4/M5).

## How to validate and limits
Before marking report-eligible, require the demonstrated primitive, the network
path, and signed target-bound proof on the shipped artifact. If any sub-claim is
inferred rather than observed, lower the score to what was shown and record the
gap.
""",

    "methodology/conviction-ladder.md": """# Skill: Conviction Ladder and Bridges

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Impact is earned one rung at a time. Name the current rung, name the next, and name
the bridge that gets you there. Skipping rungs is how theoretical criticals get
published.

## Logic-bug ladder
L0 anomaly, L1 check bypass, L2 privilege/state change, L3 account takeover or
critical business impact.

## Memory-bug ladder
R0 crash, R1 controlled crash, R2 read/write primitive, R3 relative overwrite,
R4 controlled pointer/PC, R5 RCE. Walk each rung against the real mitigations
(ASLR, stack cookies, NX, CFI, allocator hardening).

## Bridges (mandatory before a critical score)
- Memory bridge (Skill 87): a crash is not control; show influence over PC or a write-what-where.
- Write bridge (Skill 104): a write is not RCE until a webshell, cron entry, `.so`, key, or config-that-executes is demonstrated.
- Auth bridge: a missing check is not takeover until an action without creds and control with creds are both shown.

## Discovery vectors (up to ten)
1. For each lead, write its current rung and the single next observation needed.
2. Look for the missing bridge explicitly: which artifact would turn write into execute here?
3. Probe mitigations to know which rungs are even reachable on this target build.
4. Search for a second primitive that shortens the ladder (info leak to defeat ASLR).
5. Check whether a state change persists across requests (L2 durability) versus a one-shot effect.
6. Ask whether the privilege gained crosses a tenant/user boundary (L3) or stays within the actor.
7. For crashes, inspect the faulting instruction and whether attacker data reaches a pointer.
8. For writes, enumerate attacker-writable, later-executed locations on the target OS.
9. For logic bugs, chase downstream trust: does the changed state authorize a later action?
10. Record the negative control for each rung: the input that should NOT advance the ladder.

## Cross-language and stack examples
- C/C++ memory: heap overflow (R0) to tcache/allocator control (R2) to hijacked control flow (R4), with proof at each rung.
- Web authz: IDOR read (L1) to cross-tenant write (L2) to account or role takeover (L3).
- Deserialization: gadget presence (L0) to instantiated object (L1) to command execution (L3) via a real chain.
- Injection: reflected marker (L1) to out-of-band callback (L2) to command output on the target (L3).
- SSRF: internal reachability (L1) to metadata credential read (L2) to an authenticated internal action (L3).
- Race: an observed window (L1) to one invariant violation (L2) to a reliable double-spend (L3).

## How to validate and limits
Advance a rung only with a bounded oracle and a passing negative control; claim
critical only after the relevant bridge is demonstrated with signed target-bound
proof. An unbridged crash or write caps the score below critical.
""",

    "methodology/coverage-ledger.md": """# Skill: Coverage Ledger (five exhaustion gates)

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
""",

    "methodology/mistake-categories.md": """# Skill: Nine Mistake-Prediction Categories

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
""",

    "gating/false-positive-patterns.md": """# Skill: False-Positive Kill Criteria (FP-1..16)

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
""",

    "gating/triage-prioritization.md": """# Skill: Triage Prioritization and Devil's Advocate

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Spend attention where impact and reachability are highest, and make every
report-eligible lead survive an adversarial review first. Priority ordering is a
budgeting tool; the Devil's-Advocate test is a publication gate.

## Priority
- **P0**: pre-auth RCE or auth bypass, silent-fix siblings, keystone guard bypass.
- **P1**: authenticated high-impact, sink-first QUALIFIED chains.
- **P2**: defense-in-depth or medium impact.
- **P3**: informational and hardening.

## Devil's Advocate (eight tests before report-eligible)
1. Is the binary/build the real shipped artifact?
2. Is the path reachable without fantasy preconditions?
3. Does the actual output show the security effect?
4. Would a peer path with the guard have blocked this?
5. Is CVSS demonstrated, not a ceiling?
6. Is it a duplicate or variant of an existing finding?
7. Does the fix scope match the root cause?
8. Could this be intended behavior with documented risk acceptance?

## Discovery vectors (up to ten)
1. Rank the lead inventory by (impact x reachability x confidence) before deep work.
2. Pull pre-auth and silent-fix-sibling leads to the front (P0).
3. For each P0/P1, run all eight Devil's-Advocate tests and record answers.
4. Attack the strongest lead first to fail fast on false criticals.
5. Cross-check reachability against the actual deployment, not the repo default.
6. Confirm the effect in actual output, not inferred from a stack trace or log line.
7. De-duplicate by root cause, not by symptom or file.
8. Verify the proposed fix would actually close the demonstrated path.
9. Consider documented risk acceptance and intended behavior before escalating.
10. Downgrade or defer anything that fails a test, with the reason recorded.

## Cross-language and stack examples
- P0: a pre-auth Java deserialization endpoint or a Go dashboard auth bypass outranks a P2 verbose-error leak.
- P0: a silent-fix sibling in a Go/Python extractor outranks a generic DoS lead.
- P1: an authenticated sink-first QUALIFIED chain (e.g., Python `subprocess(shell=True)`) over a P2 hardening gap.
- Cross-language dedup: the same root cause in Ruby and its Rails view is one finding, not two.
- Reachability first: a C/C++ overflow reachable only by an admin ranks below a pre-auth Node prototype-pollution RCE.

## How to validate and limits
A lead passes only when all eight tests pass with cited evidence and signed
target-bound proof. Any failed test blocks publication until resolved.
""",

    "gating/hypothesis-qualification.md": """# Skill: Hypothesis Qualification Before Lab Spend

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: Skill 75

## Doctrine
Lab time is scarce; qualify before you spend it. A hypothesis earns lab budget only
when it has a clear source-to-sink path, a missing or skippable guard, and a
testable oracle. Everything else is deepened or deferred, not probed.

## Labels
- **QUALIFIED**: clear source to sink, missing/skippable guard, lab-testable oracle.
- **LATENT**: needs more hops or preconditions before it is testable.
- **NO-BOUNDARY**: no security boundary is actually crossed.
- **MIRROR-ONLY**: proven only in a reimplementation, not the shipped artifact.
- **PRECONDITIONED**: requires an unrealistic attacker position.

## Discovery vectors (up to ten)
1. State the source, the sink, and every hop between them; a gap means LATENT.
2. Identify the guard on the path and whether it is missing, skippable, or enforced.
3. Define the oracle now: the exact observation that would confirm impact.
4. Define the negative control now: the input that must NOT trigger it.
5. Check that the input is attacker-controlled on the real deployment, not operator-set.
6. Confirm the boundary being crossed (privilege, tenant, trust zone); none means NO-BOUNDARY.
7. Verify you are targeting the shipped artifact, not a mirror (else MIRROR-ONLY).
8. Assess attacker position realism (network location, credentials, timing) for PRECONDITIONED.
9. Estimate cost-to-confirm and expected impact to rank lab spend.
10. For LATENT, name the single next hop that would qualify it, then pursue that first.

## Cross-language and stack examples
- QUALIFIED: an unauthenticated route reaching `exec.Command` with a request field in Go.
- QUALIFIED: a pre-auth `pickle.loads` on request bytes in a Python webhook.
- LATENT: a deserialization sink reachable only after an unproven auth step.
- LATENT: a Java `ObjectInputStream` gadget with no confirmed source path.
- NO-BOUNDARY: a config value an operator already controls reaching a local command.

## How to validate and limits
Never spend lab budget on MIRROR-ONLY or NO-BOUNDARY. Deepen LATENT by exactly one
hop before probing. Confirmation still requires a bounded oracle, a passing
negative control, and signed target-bound proof.
""",

    "bug-classes/guard-authorization-bypass.md": """# Skill: Guard / Authorization Bypass Classes

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: any

## Doctrine
Authorization fails at the edges: a sibling that skips the guard, an object
reference without an ownership check, a guard that protects many sinks but not one,
or a long-lived session that never re-validates. Enumerate the classes so no edge
is missed.

## Patterns
1. Missing middleware/decorator on a sibling route.
2. Explicit skip: `skip_before_action`, `@public`, `PermitAll`, `AllowAnonymous`, `csrf_exempt`.
3. IDOR: object reference used without an ownership or tenant check.
4. Keystone-guard dominance: one guard protects many sinks and a new sink forgot it.
5. Lifecycle/revocation: long-lived channel/token never re-checks authorization.
6. Mass assignment / over-posting into privileged fields.
7. Confused deputy: a trusted internal caller relays an untrusted request unchecked.
8. Vertical vs horizontal: role check present, tenant/owner check absent (or vice versa).

## Discovery vectors (up to ten)
1. Inventory guards and sinks separately, then compute the unguarded intersection.
2. Grep explicit-skip annotations and list every route they cover.
3. Test object access with another user's id (horizontal IDOR) and with a lower role (vertical).
4. Compare all HTTP verbs on one resource for verb-specific gaps.
5. Enumerate alternate entry points (GraphQL, gRPC, CLI, webhook, batch) to the same action.
6. Check mass-assignment allowlists on model binding for privileged fields.
7. Inspect internal service-to-service calls that forward user intent without re-authorizing.
8. Review session/token revocation and re-validation on privilege-relevant actions.
9. Mine commits that added an ownership check and look for peer call sites without it.
10. Read negative authz tests and note which sibling paths lack one.

## Cross-language and stack examples
- Rails: `before_action`/`skip_before_action`, `params.permit` gaps, `find(params[:id])` without scoping to `current_user`.
- Django/DRF: `permission_classes`, object-level `has_object_permission` missing, `AllowAny`.
- Spring: `@PreAuthorize`/`@PostAuthorize`, method-security not applied to a controller-direct repo call.
- Express/NestJS: guards/middleware order, `req.user` trusted without a per-object check.
- Go: handler-level checks vs a bare mux route; context identity not scoped to the resource.
- PHP/Laravel: a route without `middleware('auth')` or a `Gate`/policy check missing on one action.
- ASP.NET: `[Authorize]` on the controller but `[AllowAnonymous]` on an action, or a minimal-API endpoint missing the filter.

## How to validate and limits
Exercise the unguarded path with the wrong identity in an authorized lab and
confirm the state change; the guarded sibling is the negative control. A
second-layer enforcement (gateway, DB RLS) makes it defense-in-depth (LATENT).
Require signed target-bound proof.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the protected action succeeding through the missing-check path), a passing negative control (the properly-scoped path denies it), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/injection-by-language.md": """# Skill: Injection Patterns by Language

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: any

## Doctrine
Injection is one class with many dialects: untrusted data reaches an interpreter
(shell, SQL, template, HTML, expression, deserializer) without safe separation of
code and data. Learn the per-language sinks so the same lens transfers everywhere.

## Discovery vectors (up to ten)
1. Grep the language-native command/eval/deserialize sinks (below) and reverse-trace to a source.
2. Find string-built SQL (concatenation, format, f-strings) instead of parameters.
3. Find HTML/JS emitted without context-aware escaping (raw output, `|safe`, `dangerouslySetInnerHTML`).
4. Find template render of a user-controlled template string (SSTI) versus user data into a fixed template.
5. Find expression-language evaluation (SpEL, OGNL, MVEL, JEXL) of request data.
6. Find deserializers reading untrusted bytes (pickle, Marshal, `ObjectInputStream`, unserialize, YAML full-load).
7. Find OS command construction from request fields, including indirect via env or config-that-executes.
8. Find NoSQL/LDAP/XPath query building from raw input.
9. Find header/CRLF and log injection where input reaches protocol or log framing.
10. Check for second-order injection: stored input rendered/executed later in a different context.

## Cross-language and stack examples
- Python: `os.system`, `subprocess(..., shell=True)`, `eval`/`exec`, `pickle.loads`, `yaml.load`, `render_template_string`, SQL via f-strings.
- JavaScript/Node: `child_process.exec`, `eval`, `new Function`, `vm`, deserialize libs, `innerHTML`, prototype pollution via deep merge.
- Ruby: `system`/`exec`/backticks, `eval`, `YAML.load`, `Marshal.load`, `constantize`, `render inline:`, `send`.
- Go: `exec.Command` with a shell, `text/template` into HTML/shell, `fmt.Sprintf` into SQL, `template.HTML` on user data.
- Java: `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream`, `Statement.execute`, `Class.forName`, XXE-enabled parsers.
- PHP: `system`/`exec`/`passthru`, `eval`, `unserialize`, `include` of a user path, string-built `mysqli_query`.

## How to validate and limits
Demonstrate code/data confusion with a bounded oracle (a benign marker command, a
sentinel row/file, a reflected script that runs) and a negative control that a
correctly escaped input produces no effect. Parameterized queries, auto-escaping
templates, safe-loaders, and argv-list exec refute the lead. Require signed
target-bound proof.
""",

    "bug-classes/logic-and-state.md": """# Skill: Logic and State Bug Classes

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
""",

    "discovery/fail-open-native-auth.md": """# Skill: Fail-Open Native Authn/Authz (brokers and databases)

## Metadata
- **Category**: discovery
- **Language**: c/cpp ruby java go multi-protocol
- **Stacks**: broker, database, kafka, nats, amqp, mqtt, activemq, rabbitmq, mysql, postgres, mongodb
- **Signals**: sasl, anonymousauthenticator, shouldpass, allowall, librdkafka, amqplib, pika, sarama
- **Unique vs**: envoy-ext-authz-fail-open (xDS HTTP filters) and go-reverse-proxy-dashboard-auth (frp-style token). This skill is a server that ships an authenticator plugin and defaults it off, or an authorizer that returns allow.

## Doctrine
Message queues and databases often ship an authenticator AND default it off.
Enabling a basic authenticator without disallowing the anonymous credential is not
"auth on". An authorizer that returns allow while ignoring the authentication
result is a fail-open control plane, not defense-in-depth.

## Discovery vectors (up to ten)
1. Grep default-allow sentinels: `shouldPass = true`, `return true` in an `authorize`/`authenticate`, `AllowAll`, `AnonymousAuthenticator`.
2. Find anonymous mechanisms enabled by default and not explicitly disallowed.
3. Read authorizer bodies that ignore the authentication result and always permit.
4. Distinguish the admin plane from the data plane (a separate session type, SUPER/GRANT, admin command channel).
5. Mine tests named for anonymous/default access; they are ready-made PoCs (see test-oracle-mining).
6. Trace config keys that toggle auth and check the shipped default value, not the documented one.
7. Follow empty-credential handling: an empty password or missing auth packet that skips the auth switch.
8. Check protocol handshakes for an auth-optional path (a client that never sends an authenticate frame).
9. Inspect plugin registration: an auth plugin present but not wired into the request path.
10. Compare per-listener config: an internal listener with auth off that is actually reachable.

## Cross-language and stack examples
- C/C++ brokers/DBs: an anonymous authenticator default-on; `authorize()` returning true; empty-password accounts skipping the handshake.
- Java (Kafka-like/JMS): a `PLAINTEXT` listener with no SASL; an `Authorizer` returning ALLOWED on error.
- Go (NATS/etcd-like): auth disabled by default; a token check that treats empty as valid.
- Python (brokers/agents): a control endpoint on the native port with no auth; a SASL callback that returns true on exception.
- Node (queue/IoT gateways): an MQTT/AMQP bridge accepting anonymous connect; a management port without a token.
- Ruby (Sidekiq/AMQP tooling): a control endpoint with no Rack auth on the native port.
- Databases (MySQL/Postgres/Mongo-family): default accounts with empty passwords, `trust` auth, or an open bind.

## How to validate
Speak the native protocol (not an HTTP admin shim). Connect with empty identity or
no auth frame and run a privileged action (admin help, CREATE USER, GRANT, queue
delete) with a benign marker. Oracle: the privileged success body. Negative
control: the same action with auth enforced must be denied. Measure time-to-
privileged-action with vs without credentials; they must be equal if fail-open.
Require signed target-bound proof.

## Counterexamples and limits
A documented "auth disabled" on a loopback-only bind with no reachable admin verbs
is LATENT. Enforced authentication, disallowed anonymous credential, and an
authorizer that honors the authentication result refute the claim.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an unauthenticated client completing a privileged broker/DB operation), a passing negative control (the same operation is refused when the authenticator is enforced), and signed target-bound proof on the shipped artifact.
""",

    "discovery/protocol-control-plane.md": """# Skill: Native Protocol Control Plane

## Metadata
- **Category**: discovery
- **Language**: c/cpp go java multi-protocol
- **Stacks**: grpc, redis, memcached, amqp, kafka, mysql, postgres, mongodb, broker
- **Signals**: grpcio, redis, protobuf, thrift, resp

## Doctrine
Binary and text wire protocols hide their admin surface from HTTP-only probes. If
you probe a binary protocol with HTTP requests you will miss every bug and wrongly
conclude "no admin surface". Map the real framing and hand Phase 2 a trace.

## Method
1. Map every listen/bind, config `port`, and docker-compose published port.
2. Distinguish data plane from admin plane (a distinct session type, an admin command channel, a privileged verb).
3. Produce a trace JSON for Phase 2: ports, framing, handshake, and the oracle for each privileged action.
4. Never conclude "no admin surface" from HTTP probes against a binary protocol.

## Discovery vectors (up to ten)
1. Enumerate listeners from bind/listen calls, config, and compose/k8s service ports.
2. Identify the framing: length-prefix, magic bytes, protobuf, JSON-over-TCP, MySQL/Postgres greeting.
3. Separate admin verbs from data verbs in the command table or opcode enum.
4. Read the client SDK/tests to learn the exact handshake and admin call sequence.
5. Capture a real session with a packet dump to recover byte layout and auth steps.
6. Check for an auth-optional or admin-optional path in the handshake state machine.
7. Look for a debug/monitoring port (pprof, JMX, metrics, replication) exposed without auth.
8. Map replication/cluster protocols that trust peers and are reachable by attackers.
9. Note text protocols (Redis RESP, memcached) where commands are trivially forgeable.
10. Cross-reference the admin plane with fail-open-native-auth for default-allow behavior.

## Cross-language and stack examples
- BlazingMQ-style: a length prefix plus event header plus JSON; an admin client type distinct from data.
- MySQL/OceanBase-style: greeting then handshake; empty-password accounts skip the auth switch.
- gRPC: reflection enabled exposing methods; server interceptors as the only auth.
- AMQP/Kafka: management vs data listeners; RESP or memcached text commands with no auth.
- Redis: `CONFIG SET dir`/`SAVE`/module load as a control-plane-to-write/execute pivot.
- etcd/Consul/ZooKeeper: an unauthenticated client API or a peer port exposing cluster mutation.
- Custom TCP/UDP daemons: a binary opcode dispatcher where an admin opcode skips the auth check.

## How to validate
Build a minimal client that speaks the framing, complete the handshake (or skip it
if optional), and invoke one admin verb with a benign marker; the negative control
is the same verb under enforced auth. Record the exact bytes and the observed state
change; require signed target-bound proof.

## Counterexamples and limits
An admin plane bound to loopback only, or one that enforces auth on every verb, is
LATENT. A listening socket or successful handshake is not impact by itself.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an unauthenticated admin/control frame causing a privileged state change or disclosing protected data), a passing negative control (the same frame is rejected once auth is required), and signed target-bound proof on the shipped artifact.
""",

    "discovery/document-library-untrusted-input.md": """# Skill: Untrusted Document and Parser Libraries

## Metadata
- **Category**: discovery
- **Language**: ruby python java c/cpp multi-format
- **Stacks**: pdf, office, xml, image, parser
- **Signals**: pyyaml, pypdf, pdf-reader, prawn, nokogiri, pdfbox, poi, pillow, lxml, jackson-dataformat-xml

## Doctrine
Document and media parsers ingest fully attacker-controlled bytes. The crown jewels
are code-execution and file primitives (deserialize, dynamic dispatch, file open/
write, external entity), not hang/recursion DoS. Prefer CVSS >= 7 leads.

## Discovery vectors (up to ten)
1. Find deserializers invoked on parser state: `Marshal.load`, `YAML.load`/`unsafe_load`, `pickle.loads`, `ObjectInputStream`.
2. Find dynamic dispatch of a name taken from the document (`send`, `getattr`, reflection) and check the allowlist.
3. Trace file operations whose path comes from a filespec, launch action, or embedded-file entry.
4. Look for external-entity and remote-reference features (XXE, `!include`, remote images, URLs) reaching a fetcher (SSRF).
5. Check whether encryption/permission bits are honored while decrypting (document-level authz).
6. Inspect embedded scripting (PDF JavaScript, Office macros, SVG scripts) and whether it executes.
7. Follow font/codec/decompression paths in native parsers for memory-corruption primitives.
8. Enumerate every format branch; the unsafe path is often a rarely used feature.
9. Mine the library's own tests and fuzz corpus for inputs that reach the dangerous branch.
10. Check version and known CVEs of the parser and whether the app calls the still-unsafe API.

## Cross-language and stack examples
- Ruby: `PDF::Reader` clone_state via `Marshal.load`; `Psych`/`YAML.load`; `Nokogiri` with entity loading; `send` on an operator name.
- Python: `PyYAML` full load, `Pillow`/image decoders, `lxml` with external-entity resolution enabled, or `pickle` in a loader. Trace the actual configured parser; an `xml.etree` import or a DOCTYPE alone does not demonstrate external file/network access.
- Java: XXE in `DocumentBuilder`/`SAXParser`/XSLT, Apache POI/PDFBox on untrusted docs, `ObjectInputStream` gadget chains.
- C/C++: font/image/codec parsers (memory safety), libxml2 entity expansion, archive members reaching path writes.
- Node: `libxmljs` when external-entity resolution is enabled, native `sharp` codecs, or a version-specific `pdf-parse`/`xlsx` parser issue. A package name such as `xml2js` alone is not evidence that external entities are resolved.
- PHP: `simplexml_load_string`/`DOMDocument` entity loading, `imagick`/GD decoders, `unserialize` of embedded metadata.
- Go: image decoders, custom resolvers that fetch document references, and parsed fields flowing into `text/template`. Do not infer external-resource resolution from `encoding/xml` alone; identify the actual resolver and its settings.

## How to validate
Feed one crafted document in an authorized lab. Oracles: `uid=` from a gadget or
embedded script; a sentinel file appearing under a lab-only write path; an
outbound request to a lab-controlled host for XXE/SSRF. Negative control: a safe
loader or disabled feature must reject the same payload. DISPROVE is mandatory
where an allowlist gates dispatch. Require signed target-bound proof.

## Counterexamples and limits
Safe-loaders, an enforced operator allowlist, disabled external entities, and
`extractall(filter='data')`-style hardening refute the RCE/file claims. A pure
hang or decompression bomb is DoS; cap it low and do not let it block P0/P1 work.
""",

    "discovery/plugin-dlopen-rce.md": """# Skill: Native Plugin / Dynamic-Load RCE

## Metadata
- **Category**: discovery
- **Language**: c/cpp go python java multi-runtime
- **Stacks**: plugin, native, extension
- **Signals**: ctypes, cffi, jna, jni, dlopen, loadlibrary
- **Unique vs**: java-gateway-plugin-script-rce (Groovy/SpEL scripts) and plugin-script-engine-rce (embedded interpreters). This skill is loading a native/module artifact from disk.

## Doctrine
Loading code from a path is RCE if the path or its contents are attacker-influenced.
Trace every dynamic-load argument to its origin: compile-time constant, config
file, environment, or an admin/unauthenticated command. Config-only origin is
PRECONDITIONED unless an attacker can change that config.

## Discovery vectors (up to ten)
1. Grep dynamic-load sinks: `dlopen`/`LoadLibrary`, Go `plugin.Open`, Python `ctypes.CDLL`/`imp`/`importlib` of a path, Java `System.load`/`URLClassLoader`, Node `require(userVar)`.
2. Trace each load argument backward to constant, config, env, or request.
3. Check whether the loaded path or directory is attacker-writable (permissions, upload dir, tmp).
4. Look for search-path hijacks: `LD_LIBRARY_PATH`, `PATH`, `DYLD_*`, RPATH, current-directory load.
5. Find plugin registries/manifests where an entry names a module to load.
6. Check admin or unauthenticated endpoints that set the plugin path or trigger a reload.
7. Inspect auto-load of modules from a directory the app scans at startup or on demand.
8. Follow package/extension install flows that fetch and load code.
9. Check integrity: is the artifact signature/hash verified before load?
10. Note version pinning bypasses where a user controls which module version loads.

## Cross-language and stack examples
- C/C++: `dlopen(config_path)`; RPATH or `LD_LIBRARY_PATH` pointing at a writable dir.
- Go: `plugin.Open(userPath)`; a module path from an HTTP handler.
- Python: `ctypes.CDLL(name)`, `importlib.import_module(user)`, `__import__` of a request value.
- Java: `URLClassLoader` over an attacker URL; `System.load` of an uploaded `.so`.
- Node: `require(variable)` resolving into an attacker-writable path; a native addon load.
- Rust: `libloading::Library::new(user_path)` and a dynamically-resolved symbol.
- .NET: `Assembly.LoadFrom`/`LoadFile` of an attacker path; `Activator.CreateInstance`.

## How to validate
Only if the load path is attacker-writable or attacker-named: drop a sentinel
module that writes a lab-only marker (or prints `uid=`) and confirm it loads.
Negative control: with a constant, verified path the sentinel must not load.
Require signed target-bound proof.

## Counterexamples and limits
A compile-time-constant path, a signature/hash-verified artifact, or a load
directory writable only by root refutes the RCE claim (LATENT/PRECONDITIONED).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (your planted library's constructor or a unique marker executing), a passing negative control (a path outside the trusted plugin directory is refused), and signed target-bound proof on the shipped artifact.
""",

    "gating/high-severity-priority.md": """# Skill: High-Severity Priority Gate

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Protect lab budget for the leads that can be critical. DoS and hangs may be real
but must never block a protocol, auth, or RCE proof-of-concept. Order work by
demonstrable impact.

## Priority
- **P0**: pre-auth RCE, fail-open authz, unauthenticated admin, unsafe deserialization on request bytes.
- **P1**: authenticated RCE, sibling auth miss, file read/write primitive (LOAD DATA / arbitrary write).
- **P2**: medium-impact issues with a real boundary crossing.
- **P3**: DoS, hang, infinite recursion, decompression bombs; never consume lab budget until every P0/P1 lead is proven or disproven.

## Discovery vectors (up to ten)
1. Tag each lead P0-P3 by demonstrated primitive and reachability, not by how interesting it looks.
2. Pull pre-auth and unauthenticated-admin leads to the front.
3. Separate a crash from a control primitive before scoring (see conviction-ladder).
4. Identify read/write primitives that bridge to execution and prioritize the bridge.
5. Defer pure DoS behind all P0/P1 work and cap its CVSS.
6. Check whether a "DoS" is actually a memory-safety bug with an exploit path (then it is not P3).
7. Confirm the actor for each lead (unauth vs authed vs admin) to place it correctly.
8. Re-rank after each confirmation; a proven primitive can promote adjacent leads.
9. Record why a lead is deprioritized so it is not silently dropped.
10. Ensure at least one P0/P1 has a running oracle before touching P3.

## Cross-language and stack examples
- A Go regex or parser DoS is P3 and must not delay a Go dashboard auth-bypass PoC.
- A C/C++ decompression bomb is P3; a C/C++ pre-auth deserialization or overflow is P0/P1.
- A verbose error or missing security header is P3 next to a Python pre-auth RCE.
- A self-DoS an authenticated user inflicts on their own tenant is low; a cross-tenant write is high.
- Prefer one proven pre-auth critical over five unproven criticals from a scanner.

## Rule and limits
A DoS lead may exist but must not block protocol/auth/RCE PoCs. Cap DoS CVSS at
5.3 unless a bridged, higher-impact primitive is demonstrated with signed
target-bound proof.
""",

    "methodology/library-lab-poc.md": """# Skill: Library and Native-Protocol Lab PoCs

## Metadata
- **Category**: methodology
- **Language**: ruby python go java c/cpp multi-runtime
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Prove the class with the cheapest faithful harness. Prefer published images and
package installs over multi-hour source builds so the audit is never starved by a
compile. Always emit PROVEN or DISPROVEN; never leave a high-severity lead
untested.

## Frictionless lab
- Package install over source build: `gem build && gem install` then `require`; `pip install`; `npm i`; `go run`; a published container image.
- Prefer README-documented images (an official published image on its default port) over compiling C/C++ toolchains (CMake/Ninja/Bazel) that take hours.
- The native-protocol health gate is a TCP connection, not an HTTP 200.
- For a native admin plane, complete the real handshake, then send one admin command.

## Discovery vectors (up to ten)
1. Read the project README/CONTRIBUTING for the fastest supported run path.
2. Check for an official published image and use it before building from source.
3. Use the language package manager to install just the library under test.
4. Copy the exact client sequence from the project's own tests into the lab (test-oracle-mining).
5. Health-gate native services on TCP/handshake, not HTTP.
6. Keep the harness minimal: one entry, one sink, one oracle, one negative control.
7. Pin the target revision/digest so the receipt is reproducible.
8. Isolate the lab (no network egress except to lab-controlled hosts).
9. Emit a PROVEN or DISPROVEN receipt for every high-severity lead.
10. Prefer reversible, benign oracles (a marker file, a printed `uid=`) over destructive actions.

## Cross-language and stack examples
- Ruby gem: a bundler harness calling the vulnerable API on a crafted input.
- Python lib: a `pytest` driver or `python -c` invoking the parser or loader directly.
- Go module: `go test`/`go run` a tiny driver against the vulnerable function.
- Java lib: a JUnit or `jshell` snippet exercising the sink with a gadget input.
- C/C++ library: a libFuzzer or `main` harness linking the library and feeding the crafted buffer.

## How to validate and limits
A green smoke test proves the harness runs, not that a bug exists. Confirmation
requires the oracle firing with a passing negative control and signed target-bound
proof. If the lab cannot be stood up, record inconclusive honestly rather than
inferring impact.
""",

    "discovery/test-oracle-mining.md": """# Skill: Mine Integration Tests as Oracles

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any

## Doctrine
The project's own tests often encode the exact client sequence, fixtures, and
success assertion you need. A test named for anonymous or default access IS the
proof of concept; copy it into the lab instead of reinventing probes.

## Discovery vectors (up to ten)
1. Grep test names for `anonymous`, `default`, `allows`, `bypass`, `insecure`, `no_auth`, `public`, `admin`.
2. Find assertions that a privileged call succeeds without a prior authenticate step.
3. Extract fixtures with empty or default credentials (`IDENTIFIED BY ''`, `password=""`, `token=""`).
4. Reuse test client helpers that build the exact protocol frames or requests.
5. Mine the fuzz corpus and regression inputs for payloads that reach dangerous branches.
6. Read negative tests to learn what the developer believes is forbidden, then test the sibling that lacks one.
7. Use snapshot/golden files to learn expected privileged responses (the oracle body).
8. Follow test setup/teardown to reproduce the vulnerable configuration quickly.
9. Check CI configs for how the service is started with auth off for tests.
10. Diff test expectations against production config to find test-only guarantees that prod lacks.

## Cross-language and stack examples
- xUnit families (JUnit, pytest, RSpec, Go `testing`, Jest, PHPUnit): reuse fixtures, helper clients, and assert helpers verbatim as ready-made oracles.
- Broker/queue tests: a client that connects without `authenticate()` and asserts `result.code == 0` (fail-open oracle).
- Database tests: users created with empty passwords and admin operations expected to succeed (privilege oracle).
- Web/API tests: a client that hits an admin route and asserts `200` with no login step (authz oracle).
- Integration/e2e (Cypress, Playwright, Testcontainers, docker-compose rigs): a full lab already wired with seeded creds and endpoints.
- Fuzz/property tests (libFuzzer, go-fuzz, Hypothesis): existing harnesses that already reach the parser or sink.
- Snapshot/golden files and VCR cassettes: recorded payloads that reveal expected inputs and secret formats.

## How to validate and limits
A passing upstream test is a recipe, not proof about the target: re-run the copied
sequence against the shipped artifact with a negative control (auth enforced) and
require signed target-bound proof. A test that asserts denial is itself a negative
control you can reuse.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the repo's own test client observing a protected action succeed on the target without credentials), a passing negative control (the same unauthenticated request is denied when the intended authorization check is enforced, while an authorized request succeeds), and signed target-bound proof on the shipped artifact.
""",

    "discovery/default-insecure-deploy.md": """# Skill: Validate authentication boundaries in quick-start deployments

## Metadata
- **Category**: discovery
- **Language**: any
- **Stacks**: docker, compose, helm, kubernetes
- **Signals**: docker-compose.yml, docker-compose.yaml, dockerfile, values.yaml, .env
- **Scope**: deployment configuration; no repository-specific result is implied

## When to use
Review a project's documented quick-start when it exposes a service outside the
intended trust boundary. A published port or missing configuration key is a lead,
not a confirmed authentication bypass or an automatic CWE assignment.

## Prerequisites
- Pin the repository revision, image digest and exact documented configuration.
- Establish listener addresses, network reachability, credential initialization
  and the operations available to each role in that deployment.
- Separate a local test-only setup from a supported deployment reachable by an
  untrusted actor. Read the project's intended security boundary.

## Discovery vectors (up to ten)
- Read the quick-start README, compose file, Helm values and Dockerfile for a
  published port paired with a missing or empty credential.
- Check for default or empty admin passwords, `trust`-style auth, and accounts
  created without a secret.
- Compare the bind address (loopback vs `0.0.0.0`) against the documented
  intended reachability.
- Trace whether the documented setup enables an authenticator but leaves an
  anonymous or default path open.
- Diff the "getting started" configuration against the "production" or
  "hardening" guide to see what the quick-start omits.
- Inspect environment-variable defaults that disable auth for convenience.
- Look for management, metrics, or debug endpoints exposed by the default
  configuration.
- Check whether TLS or client verification is disabled by default.
- Distinguish a per-target protocol and its own access checks; evidence from a
  database does not establish the behavior of a message broker.
- Confirm the actor: is the exposed operation reachable by an untrusted network
  caller, or only by a local operator who already owns the host?

## Cross-language and stack examples
- Databases: an image documented with an empty root password on a published port (MySQL/Mongo/Redis quick-starts).
- Message brokers: a default config that sets a port and omits an authentication block (Kafka/RabbitMQ/MQTT).
- Web dashboards and admin UIs: bound to all interfaces with a default or blank admin password.
- Key-value, search, and analytics services: a quick-start that disables auth for convenience (Elastic/OpenSearch/etcd).
- Orchestration/compose: docker-compose or Helm values exposing an internal admin port or a `0.0.0.0` bind.
- IaC defaults: a Terraform/Ansible module whose default security group or auth toggle is permissive.
- Contrast (safe): a shipped default that requires a password and binds to loopback - the negative control.

## How to validate
Use an authorized isolated lab and a harmless, reversible operation that measures
the claimed privilege. Compare no credentials, invalid credentials and the
intended authorized role. Record the exact target, configuration, caller,
request and observed state change; require signed target-bound proof before
publishing a finding. Startup success or a listening socket is not impact.

## Counterexamples and limits
Loopback-only binding, enforced authentication, a lower-privilege operation or
an explicitly trusted local setup can refute the claimed remote boundary.
An unavailable lab is inconclusive. Classify only the proven configuration
failure; do not describe it as a code authentication bypass without separate
evidence that a protected code path accepts an unauthorized caller.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the shipped default accepting an unauthenticated privileged action), a passing negative control (the hardened, non-default config refuses the same action), and signed target-bound proof on the shipped artifact.
""",

    "discovery/stubbed-privilege-check.md": """# Skill: Stubbed Privilege Checks (intent vs a disabled guard)

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
""",

    "discovery/sql-file-privilege.md": """# Skill: SQL FILE / LOAD DATA Privilege Boundaries

## Metadata
- **Category**: discovery
- **Language**: sql c/cpp multi-engine
- **Stacks**: mysql, mariadb, postgres, oceanbase, sqlite, database
- **Signals**: load_data_infile, into_outfile, copy_from, pg_read_file, load_file

## Doctrine
File-access SQL verbs (`LOAD DATA INFILE`, `INTO OUTFILE`, `COPY ... FROM/TO`,
`pg_read_file`, `LOAD_FILE`) must require a dedicated file privilege, not merely
table INSERT/SELECT. A missing file-privilege gate turns a low-privilege account
into arbitrary file read or write.

## Discovery vectors (up to ten)
1. Map every file-access verb the engine supports and the privilege each should require.
2. Confirm the privilege-check function demands the file privilege, not just table rights.
3. Diff read vs write file verbs; one may be gated while its sibling is not.
4. Check server-side file paths for traversal and for reachability of sensitive files.
5. Look for functions and extensions that read/write files (UDFs, `COPY PROGRAM`, `pg_read_file`).
6. Inspect stacked-query and prepared-statement paths that reach the same verb.
7. Check secure-file-priv-style settings and whether the shipped default constrains paths.
8. Trace how a low-privilege role is created and whether it inherits file access implicitly.
9. Mine engine tests for file-verb permission cases as oracles.
10. Consider a chain: SQLi to a file verb where the app account holds the file privilege.

## Cross-language and stack examples
- MySQL/MariaDB: `LOAD DATA [LOCAL] INFILE`, `SELECT ... INTO OUTFILE/DUMPFILE`, `LOAD_FILE()` gated by the `FILE` privilege and `secure_file_priv`.
- PostgreSQL: `COPY ... FROM/TO`, `COPY ... PROGRAM` (superuser), `pg_read_file`/`pg_read_binary_file`, `lo_import`/`lo_export`, the `pg_read_server_files` role.
- OceanBase/TiDB and MySQL-compatible engines: the same `INFILE`/`OUTFILE` verbs, often with a weaker or stubbed privilege check.
- Microsoft SQL Server: `BULK INSERT`, `OPENROWSET(BULK ...)`, `xp_cmdshell`, `sp_OACreate` file access.
- Oracle: `UTL_FILE`, `DBMS_LOB` file ops, external tables, and directory objects.
- SQLite: `ATTACH DATABASE` to a chosen path, and application-defined file UDFs.
- Any engine: a UDF or extension that opens a path from a low-privilege session (SQLi-to-file-read/write chain).

## Lab
Create a SELECT-only (or otherwise restricted) user and attempt `LOAD DATA INFILE`
of a lab-only sentinel file, or write a sentinel via `INTO OUTFILE`/`COPY TO`.
Oracle for bypass: the file bytes appear in the table, or the sentinel file is
written. Negative control: the same statement must fail with a file-privilege
error when the gate is enforced. Require signed target-bound proof.

## Counterexamples and limits
If the file privilege is required and enforced, or paths are constrained to a
harmless directory, the lead is closed. A statement error is inconclusive, not a
finding.
""",

    "bug-classes/ruby-command-injection.md": """# Skill: Ruby Command and Subprocess Injection

## Metadata
- **Category**: bug-classes
- **Language**: ruby ruby/rails
- **Stacks**: rails, sinatra
- **Signals**: open3, kernel.system, backticks, shellwords

## Doctrine
Ruby offers many ways to reach a shell, and several are easy to miss because they
do not look like `system`. Any of them with an attacker-influenced argument, or
with a shell interpreting the string, is command injection.

## Sinks
`Kernel.system`, `exec`, backticks, `%x{}`, `Open3.*` (popen3/capture2/capture3),
`IO.popen`, `Kernel.open("|...")`, `URI.open` of a pipe/URL, `Process.spawn`,
`` `#{...}` ``, and `Shellwords` misuse.

## Discovery vectors (up to ten)
1. Grep each sink token above and reverse-trace its argument to a request/CLI/env source.
2. Flag string-interpolated commands (`"cmd #{x}"`) passed to any exec sink.
3. Distinguish the safe argv form (`system("cmd", arg)`) from the shell form (`system("cmd #{arg}")`).
4. Check `IO.popen`/`Kernel.open` where a value may begin with `|` (pipe injection).
5. Look for `Open3.capture2/3` and `spawn` with a single interpolated string.
6. Find library wrappers (e.g. a `shell_out` helper) that hide the sink one call away.
7. Check Rake tasks, generators, and deploy scripts that build shell strings from input.
8. Inspect gems known to shell out (image/video/pdf tooling) called with user data.
9. Look for `send`/`public_send` reaching an exec method by dynamic name.
10. Mine tests and fixtures for command strings built from parameters.

## Cross-language and stack examples
- Kernel sinks: `system`, `exec`, backticks, `%x[...]`, `IO.popen`, `Open3.capture2/3`/`popen3`, `Process.spawn` with a shell string.
- Rails: a controller building `system("convert #{params[:file]} out.png")`; `Kernel.spawn` from a job argument.
- Background jobs: `Open3.capture3("git clone #{repo_url}")` in a Sidekiq/Resque worker.
- Gem wrappers: `shell_out!`/`shell_out` (mixlib-shellout), Terrapin/Cocaine line builders interpolating input.
- Indirect: `send`/`public_send`/`constantize` on a user string reaching a command method; `eval`/`instance_eval` of input.
- Safe contrast: argv-array `system("convert", file, "out.png")` and `Shellwords.escape` - the negative control.
- Adjacent languages (same class): Python `subprocess(..., shell=True)`, Node `child_process.exec`, Go `exec.Command("sh","-c",...)`, PHP `shell_exec`.

## How to validate
In an authorized lab, send an input whose benign marker (a lab-only `echo` or a
sentinel file) would only appear if a shell interpreted it; the negative control is
the same input through the argv form, which must not execute. Prefer `uid=` from a
harmless `id` where safe. Require signed target-bound proof.

## Counterexamples and limits
The argv form with a constant command, strict `Shellwords.escape`, or an allowlist
of fixed subcommands refutes the injection. A sink reached only by trusted operator
config is LATENT/NO-BOUNDARY.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (your injected shell command running (a marker in output)), a passing negative control (a list-arg or escaped invocation runs nothing extra), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/ruby-unsafe-deserialization.md": """# Skill: Ruby Unsafe Deserialization

## Metadata
- **Category**: bug-classes
- **Language**: ruby ruby/rails
- **Stacks**: rails
- **Signals**: marshal.load, psych, yaml.load, oj

## Doctrine
Ruby object deserialization instantiates arbitrary classes and can reach code
execution through gadget chains. `Marshal.load` and full YAML loading on
attacker-influenced bytes are the crown jewels; safe-loaders close them.

## Sinks
`Marshal.load`/`Marshal.restore`, `YAML.load` (pre-3.1 unsafe default),
`Psych.load`/`Psych.unsafe_load`, `Oj.load` in an unsafe mode, and any wrapper
that clones state via Marshal.

## Discovery vectors (up to ten)
1. Grep the sinks above and trace their argument to a request body, cookie, cache, file, or queue message.
2. Distinguish `YAML.safe_load`/`Psych.safe_load` (safe) from `YAML.load`/`unsafe_load` (unsafe).
3. Find `Marshal.load` used for caching, sessions, or inter-process state on untrusted data.
4. Check libraries that deep-clone via `Marshal.load(Marshal.dump(x))` on parser-built structures.
5. Look for `Oj`/`MessagePack`/`BSON` loads configured to instantiate arbitrary classes.
6. Trace second-order paths: data stored now, deserialized later by a privileged worker.
7. Check whether a permitted-classes allowlist is passed to the loader.
8. Inspect Rails cookie/session stores and cache backends for the serializer in use.
9. Assess gadget availability in the loaded gem set (Rails, common gems ship known chains).
10. Mine tests/fixtures that serialize objects for reuse as payload templates.

## Cross-language and stack examples
- `Marshal.load`/`Marshal.restore` of a cookie, cache value, or uploaded blob (the universal Ruby gadget surface).
- `YAML.load`/`Psych.load`/`Psych.unsafe_load` instantiating `!!ruby/object` tags (pre-safe-load defaults).
- `Oj.load` in object mode (`:object`/`:custom`) on untrusted JSON.
- `JSON.load(create_additions: true)` and `PSON.parse` reconstructing arbitrary classes.
- `PStore`, MessagePack with type extensions, and `MessageVerifier`/`MessageEncryptor` with a leaked or weak secret.
- Library-specific: `PDF::Reader` clone_state via `Marshal.load`; parsers caching state hashes.
- Safe contrast: `YAML.safe_load` with permitted classes, `Oj.load(..., mode: :strict)`, `JSON.parse` - the negative control.

## How to validate
In an authorized lab, deliver a benign gadget payload and confirm execution
(`uid=`) or object instantiation with a lab-only side effect. Negative control: a
safe-loader or permitted-classes allowlist must reject the same payload. Require
signed target-bound proof.

## Counterexamples and limits
`safe_load` with an allowlist, deserialization of only trusted internal data, or
absence of a usable gadget chain refutes the RCE claim. Instantiation without a
demonstrated harmful effect is a lead, not a confirmed critical.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted serialized input causing unauthorized code execution or a specific unauthorized file operation, observed with a harmless lab marker), a passing negative control (a safe loader or permitted-classes list rejects it), and signed target-bound proof on the shipped artifact.
""",

    "discovery/envoy-ext-authz-fail-open.md": """# Skill: Envoy / Sidecar ext_authz Fail-Open, Admin Bind, and Lua RCE

## Metadata
- **Category**: discovery
- **Language**: c/cpp yaml lua envoy multi-proxy
- **Stacks**: envoy, nginx, traefik, haproxy, xds, lua, service-mesh, istio
- **Signals**: failure_mode_allow, ext_authz, envoyproxy, auth_request, forwardauth
- **Unique vs**: fail-open-native-auth (a C++ broker anonymous credential, not xDS HTTP filters) and waf-management-plane-bypass (a WAF management API).

## Doctrine
An external-authorization filter is a data-plane gate. `failure_mode_allow: true`
(or the C++ `failure_mode_allow_` / `FailureModeAllow`) means: if the authorization
service is unreachable, every request is allowed. That is a pre-auth data-plane
bypass, not DoS. An admin interface bound to all interfaces exposes config and
lifecycle endpoints. Inline scripting that shells out is RCE when request data
reaches the argument.

## Discovery vectors (up to ten)
1. Grep `failure_mode_allow: true` in YAML and `failure_mode_allow_`/`FailureModeAllow` in C++.
2. Find the admin block bound to `0.0.0.0` and which endpoints it exposes (config dump, lifecycle, stats).
3. Grep inline scripting sinks (`os.execute`, `io.popen` in Lua filters) and trace request data into them.
4. Check what happens when the authz cluster is down: fail-open vs fail-closed, per-route overrides.
5. Compare routes: a filter chain applied to most virtual hosts but skipped on one.
6. Inspect timeout/error handling in the authz call for an implicit allow on error.
7. Look for trusted-header injection where the authz decision is carried in a spoofable header.
8. Review RBAC/JWT filters ordering relative to the authz filter.
9. Check for a management/xDS control plane reachable without auth.
10. Map the sibling stack (nginx `auth_request`, HAProxy, Traefik ForwardAuth, API gateways) for the same fail-open toggle.

## Cross-language and stack examples
- Envoy: `ext_authz` with `failure_mode_allow`, admin on `0.0.0.0`, a Lua filter calling `os.execute`.
- nginx: `auth_request` where a `500` from the auth subrequest is mishandled into allow.
- Traefik/HAProxy: ForwardAuth/`http-request auth` misconfigured to pass on error.
- API gateways: a custom authorizer whose error path defaults to allow.
- Kong/APISIX: an auth plugin whose error path defaults to allow on the data path.
- Istio: compare the effective `AuthorizationPolicy` action, workload/port scope, and rules with the intended boundary; a nonmatching rule or permitted request alone is not a bypass.

## Phase-2 PoC
1. Start the proxy (or the lab gateway analog) with the authz service reachable.
2. BEFORE: authz up, an unauthenticated request to a privileged path is denied (403).
3. AFTER: stop the authz cluster; the same request returns 200 with a privileged body or a marker (`LOTUS_AUTHZ_BYPASS`, admin config dump).
4. Oracle: a privileged body (`uid=`, `LOTUS_ADMIN`, config-dump clusters), not merely HTTP 200.
5. Measure: status_before must differ from status_after; body_after must contain the oracle. Require signed target-bound proof.

## Counterexamples and limits
`failure_mode_allow: false` with the admin interface on loopback only is LATENT.
Compile-only Lua in tests with no request-reachable path is not a finding.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the request passing to the upstream while the authz backend errors or denies), a passing negative control (a healthy authz backend blocks the same request), and signed target-bound proof on the shipped artifact.
""",

    "discovery/java-gateway-plugin-script-rce.md": """# Skill: JVM Gateway Plugin / Expression-Engine RCE

## Metadata
- **Category**: discovery
- **Language**: java kotlin shenyu spring multi-engine
- **Stacks**: shenyu, spring, spring-cloud-gateway, struts, groovy, spel, ognl, mvel, jexl, freemarker, velocity, hessian, fastjson
- **Signals**: groovyshell, spelexpressionparser, hessian2input, fastjson, ognl, scriptenginemanager
- **Unique vs**: plugin-dlopen-rce (native .so load) and plugin-script-engine-rce (the generic bug class). This skill is JVM gateways storing handle/config that is later evaluated as an expression or script.

## Doctrine
API gateways and rule engines store plugin handle JSON or rules that are later
evaluated as Groovy, SpEL, OGNL, MVEL, JEXL, or JSR-223 scripts. An admin write, or
an unauthenticated selector/rule API, becomes RCE without a classic gadget. Hessian
and Fastjson autoType on the same control plane are the sibling deserialization
class.

## Discovery vectors (up to ten)
1. Grep script/expression evaluators: `GroovyShell`/`GroovyClassLoader`, `SpelExpressionParser.parseExpression`, `Ognl.getValue`, `MVEL.eval`, `ScriptEngineManager`.
2. Trace whether the expression string comes from stored config, an admin API, or a request field.
3. Find the write path: an admin or unauthenticated selector/rule/plugin endpoint that persists the script.
4. Check anonymous-access annotations and sign-skip flags on those endpoints.
5. Grep deserialization siblings: `Hessian2Input`, `HessianProxyFactory`, Fastjson `autoTypeSupport`, `ObjectInputStream`.
6. Inspect template engines used for responses (Freemarker, Velocity, Thymeleaf) for SSTI.
7. Look for OGNL in web frameworks (Struts-style) reachable from parameters.
8. Check whether evaluated scripts run with the gateway's privileges and network position.
9. Mine tests that compile/evaluate scripts to learn the exact API shape.
10. Verify version and known CVEs of the gateway and expression libraries.

## Cross-language and stack examples
- Apache ShenYu / Spring Cloud Gateway: plugin handle JSON evaluated as Groovy/SpEL.
- Struts-style OGNL from a request parameter.
- Freemarker/Velocity SSTI in an admin-editable template.
- Fastjson/Hessian autoType on a rule-sync channel.
- Node: a rule engine running `eval`/`new Function`/`vm` on an admin-supplied expression.
- Python: a plugin or rule path calling `eval`/`exec` on stored rule text.

## Phase-2 PoC
1. PUT/POST a plugin script or rule that runs `Runtime.getRuntime().exec("id")` (or the analog `/plugin/run`).
2. Send a request that hits the selector/rule so the script evaluates.
3. Oracle: `uid=` or `GROOVY_RCE` in the response or lab log.
4. BEFORE: a script returning a constant produces no `uid=`. AFTER: the payload produces `uid=`.
5. Deserialization sibling: a canary file or `uid=` from a benign gadget analog; DISPROVE on 400/deny. Require signed target-bound proof.

## Counterexamples and limits
Compile-only expressions in unit tests with no admin/runtime path are not findings.
A sandboxed engine with a strict allowlist, or an admin API behind enforced auth
with no privilege escalation, is LATENT.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-controlled Groovy/SpEL/OGNL expression crossing the intended boundary and causing unauthorized code execution, observed with a harmless lab marker), a passing negative control (a non-expression value is treated as inert data), and signed target-bound proof on the shipped artifact.
""",

    "discovery/go-reverse-proxy-dashboard-auth.md": """# Skill: Go Reverse-Proxy Dashboard and Empty-Token Fail-Open

## Metadata
- **Category**: discovery
- **Language**: go multi-proxy
- **Stacks**: frp, reverse-proxy, dashboard, tunnel
- **Signals**: parseunverified, plugin.open, dashboard_pwd, golang-jwt
- **Unique vs**: protocol-control-plane (binary MQ/DB framing) and fail-open-native-auth (native brokers). This skill is a Go tunneling/proxy server with a shared-token control connection and an HTTP dashboard.

## Doctrine
frp-style servers authenticate the control connection with a shared token and
expose an HTTP dashboard. An empty token that returns success fail-opens the
control plane. An empty or default dashboard password exposes proxy inventory and
often lets an attacker add a proxy to loopback. A dynamic plugin loader is the RCE
sibling.

## Discovery vectors (up to ten)
1. Grep token checks that treat empty as valid: a comparison where an empty token returns nil/allow.
2. Find dashboard credential defaults: an empty password or a hard-coded default user.
3. Grep `jwt.ParseUnverified`/`ParseUnverified` on dashboard or API tokens.
4. Locate the management API routes and confirm they share (or skip) the dashboard auth.
5. Check `plugin.Open` and HTTP-plugin registration reachable from config or an API.
6. Inspect the bind address of the dashboard/admin listener (loopback vs all interfaces).
7. Compare the shipped default config against the hardening guide for auth toggles.
8. Trace whether a control client with an empty token can register a proxy target.
9. Look for SSRF via a proxy that can be pointed at internal addresses.
10. Check version and changelog for auth fixes not present on the pinned tag.

## Cross-language and stack examples
- frp-class Go tunneler: empty control token accepted; dashboard `admin`/blank; `plugin.Open` RCE.
- Generic Go admin dashboard: a mux route registered outside the auth middleware.
- A Go API using `ParseUnverified` and trusting the token claims.
- nginx/OpenResty: an admin `location` without `auth_basic`, or a Lua dashboard trusting an internal header as identity.
- Node/Python admin UIs (http-proxy, mitmproxy-style): a control panel bound to all interfaces with a default or blank token.
- Traefik/Caddy: an admin API or dashboard exposed without the middleware auth.
- Rust/Java tunnelers: a control channel accepting an empty or default token.

## Phase-2 PoC
1. BEFORE: with a non-empty dashboard token, an unauthenticated GET of a management route is 401.
2. AFTER: with the shipped empty-token default, the same request is 200 with a proxy list or `LOTUS_DASHBOARD`.
3. Empty control token: a client with `token=""` joins; the oracle is a new proxy appearing in the dump.
4. Measure HTTP status and body length before/after; the after body must include admin JSON. Require signed target-bound proof.

## Counterexamples and limits
A dashboard bound to loopback with a required password in the shipped default is
LATENT. A token check that rejects empty and verifies signatures refutes the
fail-open claim.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an empty-token client registering a proxy or reading the dashboard inventory), a passing negative control (a non-empty required token rejects the same client), and signed target-bound proof on the shipped artifact.
""",

    "discovery/waf-management-plane-bypass.md": """# Skill: WAF/Proxy Management-Plane vs Data-Plane Bypass

## Metadata
- **Category**: discovery
- **Language**: go python multi-proxy
- **Stacks**: safeline, nginx, waf, reverse-proxy
- **Signals**: x-forwarded-for, trustedproxies, exec.command
- **Unique vs**: guard-alternate-path (generic sibling skip) and envoy-ext-authz-fail-open (data-plane authz). This skill is the management API plus trusted-forwarding-header trust next to a reverse proxy.

## Doctrine
Security proxies split detection (data plane) from management (rule compile,
reload, process control). Bugs cluster where management routes lack the UI's auth,
where a client-supplied forwarding header is trusted as identity, or where user
rules are compiled and executed. Prefer RCE/authz (CVSS >= 7); a parser DoS from a
bad rule is P3.

## Discovery vectors (up to ten)
1. Enumerate management/open API routes and compare their auth to the UI routes.
2. Grep trusted-proxy handling: `X-Forwarded-For`/`X-Real-IP` used for ACL, `TrustedProxies`, allowlists.
3. Find where a client can set the forwarding header directly (no stripping at the edge).
4. Grep process-control sinks: `exec.Command("nginx", "-s", "reload")`, `iptables`, `subprocess` of a service binary.
5. Trace user-supplied rule text into a compiler or `eval`/exec path.
6. Check internal service ports that skip auth because "only the proxy calls them".
7. Inspect default credentials or setup tokens for the management console.
8. Look for SSRF from a rule-test/preview feature that fetches a URL.
9. Compare the management bind address against intended reachability.
10. Review version/changelog for management-auth fixes missing on the pinned build.

## Cross-language and stack examples
- SafeLine-class WAF: `/api/open/` or `/manage/` routes without the UI auth; XFF trusted as identity.
- nginx-fronted admin: an internal API assuming the proxy already authenticated.
- Go/Python management daemon: `exec.Command` of a reload/rule-compile step with a tainted argument.
- Coraza/ModSecurity-fronted apps (Go/C): a management or rule-reload endpoint reachable without the edge authentication.
- Java/Spring management: an actuator or admin API assuming the proxy already authenticated the caller.
- Cloud/edge WAF: an origin reachable directly, bypassing the edge via a host-header or IP-allowlist gap.
- Any: a management API trusting `X-Forwarded-For`/`X-Real-IP` as identity or as an allowlist key.

## Phase-2 PoC
1. BEFORE: GET a management route without a trusted forwarding header returns 403.
2. AFTER: `X-Forwarded-For: 127.0.0.1` returns 200 with a rule dump or `LOTUS_XFF`.
3. If reload interpolates a rule name, the oracle is `uid=` from a benign `id`.
4. Measure: status_before=403, status_after=200, body contains admin JSON. Require signed target-bound proof.

## Counterexamples and limits
A forwarding header used only for logging (never for ACL), management routes behind
enforced auth, and rule compilation without exec refute the bypass. A rule-parser
DoS is P3 and must not consume lab budget ahead of P0/P1.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (a management or API route acting without the UI authentication), a passing negative control (the same route requires auth when reached through the front door), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/plugin-script-engine-rce.md": """# Skill: Plugin / Script-Engine RCE (embedded interpreters)

## Metadata
- **Category**: bug-classes
- **Language**: java go lua python multi-runtime
- **Stacks**: groovy, spel, ognl, lua, plugin
- **Signals**: groovyshell, spelexpressionparser, plugin.open, scriptenginemanager

## Doctrine
Embedding an interpreter or dynamic loader turns configuration into code. If plugin
handle JSON, a selector predicate, a request header, or a config path reaches an
evaluator or module loader, that is remote code execution, not a feature.

## Crown jewels
- `GroovyShell.evaluate` / `GroovyClassLoader` of plugin handle JSON.
- `SpelExpressionParser.parseExpression` / OGNL / MVEL / JEXL of selector predicates.
- Lua `os.execute` / `io.popen` of a request-derived value in a proxy filter.
- Go `plugin.Open` of a config or HTTP-supplied path.
- Python `eval`/`exec`/`importlib` of a request or config value; Node `vm`/`require(var)`.

## Discovery vectors (up to ten)
1. Grep each evaluator/loader sink and trace its input to config, admin API, or request.
2. Separate a sandboxed engine (allowlisted) from an unsandboxed one.
3. Find the write path that persists the script (admin/unauthenticated API, config file, DB row).
4. Check the trigger path that later evaluates it (a request hitting the selector/rule).
5. Confirm the engine runs with the host's privileges and network position.
6. Look for autoType/gadget deserialization on the same control plane.
7. Inspect template engines for SSTI adjacent to the plugin system.
8. Check integrity/signature verification before load or evaluation.
9. Mine tests for the exact evaluate/compile API and payload shape.
10. Review versions and known CVEs of the embedded engine.

## Cross-language and stack examples
- Java: ShenYu/Spring Cloud Gateway Groovy or SpEL; Struts OGNL; Nashorn/GraalJS/JSR-223 `ScriptEngineManager`; MVEL/JEXL.
- Go: `plugin.Open` from an admin path; a rule engine using `text/template` or an embedded interpreter (yaegi, expr, gopher-lua).
- Lua: an Envoy/OpenResty filter calling `os.execute`/`loadstring` on a header or rule.
- Python: `eval`/`exec`/`compile` behind a rule or automation engine; a plugin importing a request-named module.
- Node/JS: `vm`/`vm2` escapes, `new Function`, `eval` of a stored rule expression.
- .NET: `CSharpScript`/Roslyn eval, `DataTable.Compute`, or a Razor template from input.
- Ruby: `eval`/`instance_eval` or ERB rendering of a stored plugin expression.

## How to validate
In an authorized lab, store a benign script that runs `id` and trigger it; oracle is
`uid=` in the response or lab log. Negative control: a script that returns a
constant, and a sandboxed/allowlisted configuration, must not execute. Do not
report "an engine is present" without a trigger that prints the oracle. Require
signed target-bound proof.

## Counterexamples and limits
A strict sandbox/allowlist, admin-only reach with no escalation, or compile-only
test usage refutes the RCE claim (LATENT).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-controlled rule/plugin expression crossing the intended boundary and causing unauthorized code execution, observed with a harmless lab marker), a passing negative control (a plain-data rule is not evaluated), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/jwt-dashboard-auth-bypass.md": """# Skill: JWT / Dashboard Auth Bypass

## Metadata
- **Category**: bug-classes
- **Language**: go java node multi-language
- **Stacks**: jwt, dashboard, gateway
- **Signals**: parseunverified, jsonwebtoken, jjwt, jwtsecret

## Doctrine
Dashboards and admin APIs fail authentication through unverified tokens,
hard-coded secrets, sign-skip annotations on sibling routes, and empty default
passwords. Each becomes a bypass once you forge or replay a token that a protected
route accepts.

## Crown jewels
- `jwt.ParseUnverified` / `decode` used as if it verified.
- A hard-coded `jwtSecret` / `secretKey = "..."` in gateway or admin code.
- `@AnonymousAccess` / `skipSign=true` / `AllowAnonymous` on a sibling of an authenticated route.
- An empty or default dashboard password.
- `alg:none` accepted, or HS/RS algorithm confusion.

## Discovery vectors (up to ten)
1. Grep `ParseUnverified`/`decode(...verify=false)` and confirm no later verification.
2. Grep hard-coded secret assignments near token signing/verification.
3. Grep sign-skip and anonymous-access annotations and list the routes they cover.
4. Check default credentials in shipped config for the dashboard/admin console.
5. Test `alg:none` and HS-signed-with-public-key against a protected route.
6. Compare sibling routes: one verifies, one trusts claims directly.
7. Inspect token claim trust (role/admin) without signature or audience checks.
8. Check whether a gateway verifies but a backend trusts a forwarded identity header.
9. Look for session/token non-rotation and long-lived admin tokens.
10. Review changelog/CVEs for auth fixes missing on the pinned build.

## Cross-language and stack examples
- Go: `jwt.ParseUnverified` on a dashboard token; empty `dashboard_pwd` default.
- Java: `io.jsonwebtoken` accepting `none`; `@AnonymousAccess` on a privileged sibling.
- Node: `jwt.decode` treated as verification; `Math.random` session ids.
- Python: `PyJWT` `decode(..., options={'verify_signature': False})` or `algorithms` allowing `none` on a dashboard token.
- Ruby: `JWT.decode(token, nil, false)` trusting unverified claims for admin access.
- PHP: firebase/php-jwt used with verification disabled, or the algorithm taken from the token header.

## How to validate
Forge an HS256 token with the recovered/guessed secret (or `alg:none`) and confirm a
user/admin JSON body on a protected route; replay without a valid signature on a
route whose sibling requires it. Negative control: a correctly rejected token
(wrong signature, expired, wrong audience). Require signed target-bound proof.

## Counterexamples and limits
Verification pinned to one algorithm and key, exact audience/issuer/expiry checks,
and a required non-default password refute the bypass. A decode without a
demonstrated accepted forgery is a lead.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (a forged or none-alg token accepted at the dashboard/API), a passing negative control (the same forgery is rejected by the enforced verifier, while a valid authorized token succeeds), and signed target-bound proof on the shipped artifact.
""",

    "methodology/gateway-lab-poc.md": """# Skill: Frictionless Gateway Lab PoCs

## Metadata
- **Category**: methodology
- **Language**: multi envoy shenyu frp safeline nginx
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Prove the gateway bug class with a stdlib analog first; do not compile a full proxy
to demonstrate a class. Product images are optional extras, so an audit never
blocks on Bazel/Maven builds.

## Frictionless lab
- Use the lab gateway analog (a stdlib HTTP app, no third-party install) to model authz fail-open, trusted-header trust, and script/plugin evaluation.
- Emit generated PoCs under the target `.lotus/pocs/` directory with a README.
- Record BEFORE/AFTER status codes and body snippets; QUALIFIED is not CONFIRMED until the oracle hits.
- Standard oracles: `uid=`, `LOTUS_AUTHZ_BYPASS`, `LOTUS_ADMIN`, `LOTUS_DASHBOARD`, `LOTUS_XFF`, `GROOVY_RCE`.

## Discovery vectors (up to ten)
1. Reproduce the class against the analog before touching the real product image.
2. Model both states: enforced (negative control) and bypassed (the lead).
3. Toggle exactly one variable (authz up/down, header present/absent, token empty/non-empty) between BEFORE and AFTER.
4. Assert on a privileged body marker, not merely HTTP 200.
5. Keep the analog stdlib-only so it runs anywhere the audit runs.
6. Pin the target revision so the receipt is reproducible.
7. Isolate egress to lab-controlled hosts to make SSRF oracles trustworthy.
8. Use the product image only to confirm a class already proven on the analog.
9. Store the PoC and README with the target for re-run.
10. Emit PROVEN or DISPROVEN for every gateway lead.

## Cross-language and stack examples
- Envoy/nginx/Traefik authz fail-open modeled by an analog that flips deny to allow when the authz backend is down.
- ShenYu/Spring Cloud Gateway script RCE modeled by an analog `/plugin/run` evaluating a stored expression.
- frp dashboard/token fail-open modeled by an analog whose empty token returns admin JSON.
- Kong/APISIX plugin error-path allow modeled by an analog whose plugin exception passes the request.
- HAProxy/Caddy forward-auth modeled by an analog that trusts a spoofable identity header.

## How to validate and limits
The analog proves the class is real and testable; the shipped product still needs
its own BEFORE/AFTER oracle and signed target-bound proof before a finding is
published. A green analog alone is not a target finding.
""",

    "discovery/puppet-agent-catalog-rce.md": """# Skill: Config-Management Agent Catalog Deserialization and Execution RCE

## Metadata
- **Category**: discovery
- **Language**: ruby puppet multi-agent
- **Stacks**: puppet, chef, salt, ansible, config-management
- **Signals**: psych, pson, create_additions, shell_out
- **Unique vs**: ruby-command-injection (generic Kernel.system) and ruby-unsafe-deserialization (Marshal/PDF). This skill is catalog-shaped: full YAML/PSON of facts and catalogs plus execution of interpolated resource parameters plus an over-broad REST allow.

## Doctrine
A configuration-management agent treats the catalog it fetches as trusted code.
Full YAML/PSON loading of a network catalog instantiates arbitrary objects; an
execution helper that interpolates resource parameters is RCE as the agent user
(often root); an over-broad REST allow makes it pre-auth.

## Discovery vectors (up to ten)
1. Grep full-load deserializers on network data: `YAML.load`/`Psych.load`/`unsafe_load`, `PSON.parse`, `create_additions: true`.
2. Trace catalog/fact ingestion from the wire into those loaders.
3. Grep execution helpers that interpolate parameters into a command (`Execution.execute`, `shell_out`, backticks).
4. Inspect the agent's REST/auth config for wildcard allows (`allow '*'`) versus a named-cert allowlist.
5. Check whether the agent runs as root and what the interpolated command touches.
6. Follow report/inventory upload paths that also deserialize.
7. Look for a fetch-then-apply flow where a spoofed master or MITM supplies the catalog.
8. Compare safe vs unsafe loader usage across the codebase (safe_load elsewhere but not here).
9. Mine tests/fixtures for catalog payloads to reuse as templates.
10. Check version/CVEs for catalog-handling fixes missing on the pinned build.

## Cross-language and stack examples
- Puppet-style Ruby agent: `YAML.load`/`PSON.parse` of catalogs; `Puppet::Util::Execution.execute` interpolation; `auth.conf` `allow '*'`.
- Chef-style Ruby agent: `shell_out` of interpolated node attributes; unsafe node-data load; an `execute` resource built from attributes.
- Salt (Python): a master/minion accepting unauthenticated commands; templated `cmd.run` from pillar or grains.
- Ansible-adjacent: a playbook templating a shell task from untrusted inventory/vars; a dynamic-inventory script running input.
- MCollective/Bolt: a task or agent action executing an interpolated command from an orchestration request.
- Generic config-management: any agent that fetches a catalog/manifest over the network and full-loads or templates it into execution.
- Safe contrast: a signed catalog with `safe_load` and no attribute interpolation into a shell - the negative control.

## Phase-2 PoC
1. Start the agent-app analog (do not compile the real product).
2. BEFORE: with the enforced analog, a catalog fetch is denied (403).
3. AFTER: with the fail-open analog, the same fetch is 200 and emits `LOTUS_PUPPET_AUTH`.
4. YAML gadget analog: POST a catalog with an object payload; oracle is `uid=` and `PUPPET_YAML_RCE`.
5. Measure status_before vs status_after; uid_after true, uid_before false. Require signed target-bound proof.

## Counterexamples and limits
`safe_load`/`safe_load` with permitted classes, execution of a constant argv, and a
REST allow limited to a named certificate are LATENT.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted catalog/fact input causing an unintended privileged action or code execution, observed with a harmless lab marker), a passing negative control (a safe loader with permitted classes rejects the same payload), and signed target-bound proof on the shipped artifact.
""",

    "discovery/sinatra-unauth-control-ui.md": """# Skill: Unauthenticated Debug / Control UI

## Metadata
- **Category**: discovery
- **Language**: ruby python java multi-framework
- **Stacks**: sinatra, flask, werkzeug, spring-actuator, rails, thin, rack
- **Signals**: mailcatcher, rack-auth, actuator, web-console, sidekiq
- **Unique vs**: jwt-dashboard-auth-bypass (JWT/HS256) and fail-open-native-auth (native brokers). This skill is a debug/mail/admin UI with no authentication layer, often bound to all interfaces.

## Doctrine
Catch-all debug, mail, and control UIs frequently ship with no authentication. "No
password" is not a feature; a GET that dumps captured messages, environment, or
internal state is pre-auth data exfiltration, and some expose code execution.

## Discovery vectors (up to ten)
1. Find debug/admin apps with no auth layer (no basic-auth wrapper, no login filter, no middleware).
2. Check the bind address (all interfaces vs loopback) against intended reachability.
3. Grep for routes that dump captured data, config, env, or internal objects.
4. Look for framework debug consoles that allow code execution (interactive evaluator, PIN-gated debugger).
5. Inspect actuator/management endpoints exposed without auth.
6. Check search/observability dashboards left open (cluster, logs, metrics with query power).
7. Find mail/webhook capture tools that store and serve message bodies.
8. Verify whether a documented "dev only" tool is actually running in the deployment.
9. Look for a reverse proxy that forwards the debug UI publicly.
10. Confirm sensitive content (password-reset mail, tokens, secrets) is retrievable.

## Cross-language and stack examples
- Ruby (Sinatra/Thin): a mail-catcher UI on all interfaces with no Rack auth serving `/messages`.
- Python (Flask/Werkzeug): the interactive debugger enabled in production; an unauthenticated admin blueprint.
- Java (Spring Boot): actuator `/env`, `/heapdump`, `/jolokia` exposed without security.
- Rails: `web-console` or `/rails/info` reachable; an open Sidekiq web UI.
- Node: an Express admin router or a Bull/Arena queue dashboard mounted without auth.
- Go: a `net/http/pprof` or an admin mux registered outside the auth middleware.
- Search/infra: an open cluster, log, or metrics dashboard with query and mutate power.

## Phase-2 PoC
BEFORE: with the enforced analog (auth on), a GET of the control route is 401.
AFTER: with auth off, the same GET is 200 and emits `LOTUS_MAIL_UNAUTH` (or the
relevant marker) plus the sensitive body. The oracle is the marker plus real
content, not merely HTTP 200. Require signed target-bound proof.

## Counterexamples and limits
A UI bound to loopback and wrapped in basic auth, or a debug console disabled in
the deployment build, is LATENT. A reachable route returning only static, non-
sensitive content is not impact.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the debug/control UI performing a privileged action for an unauthorized caller), a passing negative control (the same action requires credentials when auth is enabled), and signed target-bound proof on the shipped artifact.
""",

    "discovery/rails-node-ssr-exec.md": """# Skill: Server-Side Rendering Exec / Prerender RCE

## Metadata
- **Category**: discovery
- **Language**: ruby rails node python multi-stack
- **Stacks**: rails, react_on_rails, node, ssr, next, nuxt
- **Signals**: execjs, open3, prerender, mini_racer, server_render
- **Unique vs**: ruby-command-injection (generic shell_out). This skill is server-side JS execution (ExecJS / a spawned Node) at request time with attacker-influenced props, bundle path, or argv.

## Doctrine
Prerendering executes JavaScript on the server during the HTTP request. If props,
the bundle path, or the process argv are influenced by the client, that is RCE in
the server's user, not XSS.

## Discovery vectors (up to ten)
1. Grep server-render sinks: `ExecJS.eval`/`compile`/`exec`, a server-rendering helper, `Open3`/`spawn` of `node`.
2. Trace props passed into the render call back to request data.
3. Check whether the bundle path or node argv can be influenced by the client.
4. Look for `prerender: true` / `server_render` flags on components that take user input.
5. Inspect any place the server evaluates a JS/template string built from input (SSTI-adjacent).
6. Follow file paths for the bundle that a request could redirect (upload, param, header).
7. Check subprocess construction for shell interpretation of interpolated values.
8. Review caching of rendered output that might execute stored attacker props later.
9. Mine tests for the render API and payload shape.
10. Verify the render runtime's privileges and egress.

## Cross-language and stack examples
- Rails + react_on_rails: `ExecJS`/`Open3` running a Node bundle with client props (`prerender: true`).
- Node SSR (Next/Nuxt/custom): `vm`/`eval` of a template or a spawned render worker fed user data.
- Python: a view that spawns `node` to render, interpolating request fields into argv.
- Java: Nashorn/GraalJS server-side rendering evaluating a template built from request fields.
- PHP: V8Js or a spawned `node` renderer interpolating user input into the script.
- .NET: a Node-services JS SSR bridge (`INodeServices`) evaluating a template built from input.
- Any: a headless-browser or `wkhtmltopdf` render fed user HTML/JS (SSR-adjacent to XSS and SSRF).

## Phase-2 PoC
BEFORE: POST a benign script or props (`1+1`) and confirm no `uid=`.
AFTER: props that reach `child_process.execSync('id')` (or the analog) produce
`uid=` and `ROR_EXECJS`. Negative control: a static, integrity-checked bundle with
no user props must not execute. Require signed target-bound proof.

## Counterexamples and limits
Rendering a static, integrity-hashed bundle with no user-controlled props, path, or
argv is LATENT. Output that is escaped and never executed server-side is XSS at
most, not RCE.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (injected JavaScript executing in the SSR/render worker), a passing negative control (static props render without evaluating the payload), and signed target-bound proof on the shipped artifact.
""",

    "discovery/ai-proxy-ssrf-identity.md": """# Skill: Reverse-Proxy Caller-Supplied Upstream + Identity Spoofing (AI-proxy class)

## Metadata
- **Category**: discovery
- **Language**: python go node multi-stack
- **Stacks**: llm, proxy, litellm, openai, httpx, requests, gateway
- **Signals**: verify_false, 169.254.169.254, extractall, x-forwarded, base_url
- **Unique vs**: fail-open-native-auth and envoy-ext-authz-fail-open. This skill is a proxy that lets the caller pick the upstream URL and spoof an identity header, often with an optional (bypassable) proxy token.

## Doctrine
A proxy that reads the upstream base URL from the caller is SSRF to internal
services and cloud metadata. Identity headers accepted without a binding token are
authorization bypass. Disabled TLS verification plus a broad bind is credential
theft. Extracting a model/artifact bundle is overwrite/RCE-adjacent.

## Discovery vectors (up to ten)
1. Grep for a base-URL/upstream value read from a request header, query, or body.
2. Grep identity headers trusted without verification (a user-id header, a tenant header).
3. Check whether the proxy token is optional or defaults to empty.
4. Grep `verify=False`/`InsecureSkipVerify`/`rejectUnauthorized:false` on the upstream client.
5. Test SSRF to cloud metadata and to internal-only addresses.
6. Look for archive extraction of a fetched bundle (`extractall`, tar/zip) without path checks.
7. Inspect bind address and whether credentials are reachable off-host.
8. Trace whether the spoofable identity grants access to another tenant's data or quota.
9. Check redirect following that turns an allowlisted host into an internal fetch.
10. Review logging that may capture and expose forwarded secrets.

## Cross-language and stack examples
- Python LLM proxy: a base-URL header reaching `requests`/`httpx` with `verify=False`; a user-id header without a token; `tarfile.extractall` of a model bundle.
- Go proxy: an upstream from a header dialed with `InsecureSkipVerify`; a trusted identity header.
- Node proxy: `fetch(userUpstream)` with `rejectUnauthorized:false`; a spoofable auth header.
- Java/Spring AI gateway: an upstream base-URL from a header dialed with TLS verification disabled; a trusted `X-User` header.
- Ruby proxy: `Net::HTTP` to a caller-supplied upstream; an identity header accepted without a signed token.
- PHP: a proxy using `curl`/`file_get_contents` on a caller upstream; an identity header trusted without a token.
- Any: a model or tool download-URL reaching `tarfile.extractall` or a fetch with TLS verification disabled.

## Phase-2 PoC
BEFORE: with the enforced analog (allowlist + required token), a metadata-URL header
is denied (403). AFTER: with enforcement off, the same request is 200 and returns
`LOTUS_SSRF` (a metadata value). Optional-token analog: a request without
authorization returns `LOTUS_AI_UNAUTH`. Require signed target-bound proof.

## Counterexamples and limits
An upstream host allowlist, a required binding token, TLS verification on, and
extraction with a safe filter refute the claims (LATENT). A configurable upstream
that only an operator sets is NO-BOUNDARY.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the proxy fetching an attacker-chosen upstream or trusting a spoofed identity header), a passing negative control (the same disallowed upstream or forged identity is rejected by the enforced allowlist or identity binding), and signed target-bound proof on the shipped artifact.
""",

    "discovery/privileged-cli-hook-rce.md": """# Skill: Privileged Hook / Lifecycle-Script RCE (Certbot class)

## Metadata
- **Category**: discovery
- **Language**: python go multi-runtime
- **Stacks**: certbot, acme, systemd, cron, git-hooks, ci
- **Signals**: pre_hook, post_hook, deploy_hook, renew_hook, yaml.load, chmod
- **Unique vs**: injection-by-language os.system. This skill is a privileged (often root) tool that runs deploy/pre/post/renew hooks, loads config unsafely, or loosens permissions on secrets.

## Doctrine
Tools that run hooks as root after a privileged operation are RCE if the hook path
or its contents are writable by a lower-privilege user. Unsafe config loading is
deserialization RCE; over-permissive modes on private keys are key theft.

## Discovery vectors (up to ten)
1. Grep hook runners: `pre_hook`/`post_hook`/`deploy_hook`/`renew_hook`, lifecycle scripts run by a privileged process.
2. Check the ownership and writability of hook paths and hook directories.
3. Grep unsafe config loaders (`yaml.load` without SafeLoader) on the tool's config.
4. Grep `subprocess`/`os.system` that runs a hook value or an interpolated path.
5. Grep permission changes on secrets (`chmod 0777`/`0666` on a private key).
6. Follow other privileged lifecycle runners: git hooks, systemd units, cron entries, package post-install scripts, CI runners.
7. Check whether a lower-privilege user can influence the hook path via config, env, or a writable file.
8. Inspect PATH and environment inheritance in the privileged context.
9. Look for symlink/TOCTOU on files the privileged tool writes or reads.
10. Review setuid/sudo wrappers that pass through user-controlled arguments.

## Cross-language and stack examples
- Certbot-class Python: root-run `deploy_hook`; `yaml.load` of `cli.ini`; `chmod 0777` on `privkey.pem`.
- Git: a repository-supplied hook executed by a privileged automation user.
- systemd/cron/package managers: a post-install or unit script whose command is attacker-influenced.
- CI runners: a pipeline step that runs a repo-supplied script as a privileged agent.
- Node: a `postinstall` or lifecycle script from a dependency run by a privileged CI or deploy user.
- Ruby: a gem native-extension or Rake hook executed during a privileged install.

## Phase-2 PoC
BEFORE: invoke the hook path with a benign value (`true`) and confirm no `uid=`.
AFTER: a value of `id` (or a writable hook that runs `id`) produces `uid=` and
`CERTBOT_HOOK`. Negative control: a root-owned hook directory with a SafeLoader and
`0600` keys must not execute attacker content. Require signed target-bound proof.

## Counterexamples and limits
Hooks loaded only from a root-owned path, SafeLoader config parsing, and `0600`
key modes refute the RCE/theft claims (LATENT/PRECONDITIONED).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-influenced hook command running as the privileged user), a passing negative control (a pinned or validated hook path runs nothing extra), and signed target-bound proof on the shipped artifact.
""",

    "discovery/django-object-authz-gap.md": """# Skill: Object-Level Authorization Sibling Skip (IDOR)

## Metadata
- **Category**: discovery
- **Language**: python django multi-framework
- **Stacks**: django, drf, rails, express, spring, flask
- **Signals**: has_message_access, csrf_exempt, urlopen, pickle.loads, objects.get
- **Unique vs**: guard-alternate-path (generic decorator skip). This skill is a view that loads an object by id but skips the per-object access helper, plus webhook csrf-exempt and link-preview SSRF neighbors.

## Doctrine
Real authorization is often per-object, not merely login-required. A sibling view
that accepts an object id and loads it without the ownership/access helper is an
IDOR of private data. Link-preview fetchers are SSRF; csrf-exempt webhooks with
deserialization are RCE/authz.

## Discovery vectors (up to ten)
1. Grep the per-object access helper (an ownership/tenant check) and list views that load the object without it.
2. Grep object loads by id (`.objects.get`/`.filter`, `find(params[:id])`, `findById`) near request handlers.
3. Test horizontal IDOR: request another user's object id with your session.
4. Test vertical gaps: a role check present, an object-scope check absent.
5. Find `csrf_exempt`/`AllowAny` webhook endpoints and what they deserialize.
6. Grep link/preview fetchers (`urlopen(url)`, an image/preview fetch) for SSRF.
7. Check batch/list endpoints that leak objects across tenants without scoping.
8. Inspect GraphQL resolvers and API viewsets for missing object-level permissions.
9. Compare sibling views: one calls the access helper in the same function, one does not.
10. Mine tests for a `test_*_forbidden` that exists for one view and is missing for its sibling.

## Cross-language and stack examples
- Django/DRF: `Model.objects.get(id)` without `has_object_permission`/owner filter; `get_object_or_404(Model, pk=...)` not scoped to `request.user`.
- Rails: `Model.find(params[:id])` not scoped to `current_user`; a Pundit/CanCan policy missing on one action.
- Node/Express: `Model.findById(req.params.id)` without an ownership check; a Prisma/Sequelize query not filtered by tenant.
- Java/Spring: a repository `findById` in a controller behind only a role check, not a per-object owner check.
- Go: a handler loading a record by path id and trusting context identity without scoping to the resource.
- PHP/Laravel: `Model::find($id)` without a policy/gate; a route-model binding not constrained to the user.
- Any: sequential or guessable ids (IDOR) plus mass-assignment updating another tenant's row.

## Phase-2 PoC
BEFORE: with the enforced analog, GET another user's object as a different user is
denied (403). AFTER: with the gap, the same GET is 200 and returns the private body
(`LOTUS_IDOR`). Link preview: a request for an internal/metadata URL returns
`LOTUS_SSRF`. Require signed target-bound proof.

## Counterexamples and limits
If every object fetch calls the access helper in the same function, or a second
layer enforces tenancy (DB RLS), the lead is LATENT. A preview fetcher with an
allowlist refutes the SSRF.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (another tenant's object returned or mutated without the ownership check), a passing negative control (the access helper denies the cross-tenant id), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/ruby-yaml-pson-catalog-deser.md": """# Skill: Ruby YAML/PSON Catalog Deserialization (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: ruby puppet
- **Stacks**: puppet
- **Signals**: psych, pson, create_additions

## Doctrine
Distinct from Marshal-of-parser-state: this class is YAML/PSON catalogs and facts
loaded from the wire, where a full loader instantiates arbitrary Ruby objects. The
loader choice (full vs safe) is the whole bug.

## Unique vs
`ruby-unsafe-deserialization.md` covers `Marshal.load` of parser hashes (e.g. PDF).
This class is YAML/PSON catalogs and facts: object tags, `json_class`,
`create_additions: true`, and full loads of a catalog from the network.

## Sinks
`YAML.load` / `Psych.load` / `Psych.unsafe_load`, `PSON.parse`,
`JSON.load(create_additions: true)`, and `Marshal.load` of reports (adjacent).

## Discovery vectors (up to ten)
1. Grep each full-load sink and confirm the bytes come from the network (catalog/fact/report).
2. Distinguish `safe_load`/permitted-classes from full loads.
3. Grep `create_additions: true` and object-tag handling.
4. Trace fact submission and catalog fetch into the loader.
5. Check report/inventory upload paths for adjacent Marshal loads.
6. Assess gadget availability in the loaded gem set.
7. Look for a spoofable master or MITM that supplies the catalog.
8. Compare safe usage elsewhere against the unsafe call here (silent-fix sibling).
9. Mine tests/fixtures for catalog payloads.
10. Review version/CVEs for loader-hardening fixes.

## Cross-language and stack examples
- Puppet-style: `YAML.load`/`PSON.parse` of a network catalog or facts instantiating a Ruby object.
- `Psych.unsafe_load`/`YAML.load` of an uploaded document or report on older defaults.
- `JSON.load(create_additions: true)` reconstructing tagged objects from the wire.
- Chef/Salt-adjacent Ruby tooling: node data or report payloads full-loaded server-side.
- Any Ruby service accepting YAML/PSON uploads and full-loading them (config import, backup restore).
- Safe contrast: `YAML.safe_load(..., permitted_classes: [...])` or SafeYAML - the negative control.

## How to validate
Deliver a benign object payload to the loader in an authorized lab; oracle is
`uid=` and `PUPPET_YAML_RCE` or a lab-only side effect. Negative control: a
safe-loader with permitted classes must reject the same payload. Require signed
target-bound proof.

## Counterexamples and limits
`YAML.safe_load` with permitted classes, or loading only trusted internal data,
refutes the RCE claim (LATENT).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted YAML/PSON input causing an unintended privileged action or code execution, observed with a harmless lab marker), a passing negative control (safe_load with permitted classes rejects the same catalog), and signed target-bound proof on the shipped artifact.
""",

    "methodology/agent-app-lab-poc.md": """# Skill: Frictionless Agent/App Lab PoCs

## Metadata
- **Category**: methodology
- **Language**: ruby python go node multi-stack
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Prove agent and web-app bug classes with a stdlib analog rather than compiling the
real product. Skip the analog entirely when Phase 1 found no leads; a green
hello-world is not a finding.

## Frictionless lab
- Use the agent-app analog (a stdlib HTTP app, no third-party install) to model authz fail-open, unsafe deserialization, SSRF, identity spoofing, IDOR, and privileged hooks.
- Emit generated PoCs under the target `.lotus/pocs/` directory with a README.
- Record BEFORE/AFTER status codes and body snippets; QUALIFIED is not CONFIRMED until the oracle hits.
- Standard oracles: `uid=`, `LOTUS_MAIL_UNAUTH`, `LOTUS_PUPPET_AUTH`, `LOTUS_SSRF`, `LOTUS_AI_UNAUTH`, `LOTUS_IDENTITY_SPOOF`, `LOTUS_IDOR`, `PUPPET_YAML_RCE`, `ROR_EXECJS`, `CERTBOT_HOOK`.

## Discovery vectors (up to ten)
1. Choose the analog that matches the lead class (authz, deser, SSRF, IDOR, hook).
2. Model both the enforced state (negative control) and the vulnerable state (lead).
3. Toggle exactly one variable between BEFORE and AFTER.
4. Assert on a privileged body marker, not merely HTTP 200.
5. Keep the analog stdlib-only for portability.
6. Pin the target revision for a reproducible receipt.
7. Isolate egress so SSRF oracles are trustworthy.
8. Reuse the project's own test client sequence where possible (test-oracle-mining).
9. Store the PoC and README with the target.
10. Skip the analog when Phase 1 produced no leads; emit PROVEN or DISPROVEN otherwise.

## Cross-language and stack examples
- Config-agent catalog RCE modeled by an analog that fail-opens auth and full-loads a catalog.
- LLM-proxy SSRF/identity modeled by an analog honoring a caller upstream and identity header.
- Object-authz IDOR modeled by an analog that loads an object by id without the access helper.
- Tool-using agent modeled by an analog whose tool call runs an unvalidated shell or command argument.
- Prompt-injection modeled by an analog that lets retrieved content override the system instruction.

## How to validate and limits
The analog proves the class is real and testable; the shipped target still needs
its own BEFORE/AFTER oracle and signed target-bound proof. Do not fabricate
CONFIRMED from a passing analog.
""",

    "discovery/ci-cd-pipeline-step-parser-command-injection.md": """# Skill: CI/CD Pipeline and Step-Parser Command Injection

## Metadata
- **Category**: discovery
- **Language**: multi-language yaml
- **Stacks**: github-actions, gitlab-ci, jenkins, drone, tekton, argo, circleci, ci
- **Signals**: .github/workflows, .gitlab-ci.yml, jenkinsfile, azure-pipelines.yml
- **Scope**: build runners and CI services; a concatenation is a lead, not a finding

## Doctrine
CI systems interpolate untrusted fields (branch names, PR titles, commit messages,
webhook payloads, config values) into shell strings, process arguments, container
commands, and template renderers. A concatenation is a lead; require a signed
target-bound receipt showing the default trust-boundary crossing before calling it
a finding.

## Discovery vectors (up to ten)
1. Grep where pipeline/step definitions are parsed and fields are interpolated into a command.
2. Identify untrusted inputs: branch/tag/PR title, commit message, author, webhook body, external config.
3. Grep expression contexts injected into `run:`/script blocks (e.g. a templating expression placed into a shell line).
4. Trace fields into container `docker run`/args, `exec`, and template renderers.
5. Check whether PR-triggered pipelines run with write tokens or on privileged runners.
6. Look for `eval`/shell of a config value in the runner itself.
7. Inspect matrix/parameter expansion that concatenates user values into commands.
8. Find plugin/step marketplaces where a step evaluates its inputs.
9. Check artifact/cache keys built from untrusted fields reaching a shell.
10. Review self-hosted runner isolation and secret exposure to injected steps.

## Cross-language and stack examples
- GitHub Actions: an expression interpolating `github.event.*` (PR title/branch) directly into a `run:` shell step.
- GitLab CI: a `script:` line concatenating `CI_COMMIT_*` or a webhook variable.
- Jenkins: a Groovy pipeline building a `sh` string from a build parameter.
- Drone/Tekton/Argo: a step template rendering an untrusted field into args.
- C/C++ build runners: a step parser interpolating configuration into compiler flags or process arguments.
- CircleCI/Azure Pipelines: an untrusted PR field interpolated into a `run`/`bash` step.
- Bitbucket/Buildkite: a pipeline step rendering a webhook variable into a shell command.

## How to validate
In an authorized lab, supply an untrusted field whose benign marker (a lab-only
`echo`/sentinel) only appears if a shell interpreted it; the negative control is
the same field passed as a quoted argument or through an allowlist, which must not
execute. Require signed target-bound proof; prefer `uid=` from a harmless `id`
where safe.

## Counterexamples and limits
Quoted argv, an input allowlist, and untrusted fields never reaching a shell refute
the injection. A pipeline that only trusted maintainers can trigger is a reduced
boundary; classify accordingly rather than as pre-auth.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an interpolated untrusted field executing in the runner shell (a marker)), a passing negative control (a quoted or parameterized field is treated as literal), and signed target-bound proof on the shipped artifact.
""",

    "discovery/cpp-inja-template-script-rendering.md": """# Skill: Template / Expression Rendering to Scripts and Args (SSTI)

## Metadata
- **Category**: discovery
- **Language**: c/cpp multi-language
- **Stacks**: inja, jinja2, freemarker, velocity, thymeleaf, mustache, handlebars, template
- **Signals**: render_template_string, jinja2, freemarker, inja

## Doctrine
Template and expression engines are interpreters. When untrusted step or
configuration fields flow into a rendered script, compiler flag, process argument,
or file path, separate intended template capability from a vulnerability and
require a signed lab oracle for the shipped target.

## Discovery vectors (up to ten)
1. Identify the template/expression engine and whether it can call functions or execute.
2. Distinguish user-data-into-a-fixed-template from a user-controlled-template string (SSTI).
3. Trace rendered output into a shell, compiler invocation, process argv, or file path.
4. Grep engine render/eval calls and their inputs.
5. Check for engine features that expose the host (function calls, includes, filesystem access).
6. Look for path fields rendered into `open`/write locations (traversal).
7. Inspect config-driven rendering where an operator value is actually attacker-influenced.
8. Check sandbox settings and whether they are enabled in the shipped build.
9. Mine tests for template payloads and expected output.
10. Review adjacency to command injection and file write primitives.

## Cross-language and stack examples
- C/C++: an Inja/Mustache-style engine rendering step fields into a script or compiler flags.
- Python: Jinja2 `render_template_string` on user input; Mako/Tornado from a string; format-string expression abuse.
- Java: Freemarker/Velocity/Thymeleaf SSTI; SpEL/OGNL evaluation of a request field.
- Node: Handlebars/Pug/EJS or `lodash.template` compiling a user template; `vm` rendering.
- Go: `text/template`/`html/template` output flowing into a shell or HTML sink.
- Ruby: `ERB.new(user).result`, Slim, or Liquid rendering a user-supplied template string.
- PHP: Twig/Blade/Smarty with a user-controlled template string or expression.

## How to validate
Render a benign probe that would only evaluate if the engine executes it (a marker
computed by the engine, or a lab-only side effect); the negative control is the
same input treated as literal data. For argv/flag/path sinks, use a sentinel file
oracle. Require signed target-bound proof.

## Counterexamples and limits
A sandboxed engine with no host access, user data confined to a fixed template, and
rendered output never reaching a shell/compiler/path refute the lead (LATENT).
""",

    "discovery/fastapi-authentication-and-dependency.md": """# Skill: Web-Framework Authentication and Dependency Wiring

## Metadata
- **Category**: discovery
- **Language**: python multi-framework
- **Stacks**: fastapi, starlette, flask, django, drf, express, nestjs
- **Signals**: fastapi, starlette, flask, djangorestframework

## Doctrine
Modern frameworks attach authentication and authorization through dependencies,
decorators, and middleware. A missing dependency, an overridden one, or a sibling
route wired without it is a boundary gap. A missing dependency is a lead until an
unsafe operation is reached in the default deployment with a signed receipt.

## Discovery vectors (up to ten)
1. Inventory every route and router include, and the auth dependency each declares.
2. Find routes that omit the auth dependency while siblings require it.
3. Check dependency overrides (test overrides leaking to prod, an override that disables auth).
4. Inspect middleware order and whether it actually covers all mounted routers.
5. Compare authentication on WebSocket and streaming endpoints against HTTP siblings.
6. Check background tasks and startup hooks that perform privileged actions without a caller check.
7. Trace object-level authorization beyond route-level auth (IDOR neighbor).
8. Look for global dependencies assumed but not applied to a sub-app or mounted router.
9. Probe no-credential, invalid-credential, and lower-privilege requests on each route.
10. Review docs/OpenAPI for routes marked public that reach privileged logic.

## Cross-language and stack examples
- FastAPI/Starlette: `Depends(get_current_user)` on most routes but missing on one; an `include_router` without the dependency; `app.dependency_overrides` left set from tests.
- Flask: a blueprint without the `before_request` auth; `@login_required` missing on a sibling; `app.debug=True` in production.
- Django/DRF: `permission_classes` gaps, `AllowAny` on a privileged viewset, `@csrf_exempt` on a mutating view.
- Express/NestJS: a guard/middleware not applied to a mounted sub-router; `app.use(auth)` registered after a route.
- Spring: `@PreAuthorize` on the service but a controller calling the repository directly; a `permitAll` on a broad matcher.
- Go (chi/gin/echo): an auth middleware wrapping one router group while a handler is registered on the bare mux.
- Rails: a controller inheriting a `skip_before_action :authenticate`; a route outside the authenticated namespace.

## How to validate
Send no-credential, invalid-credential, and lower-privilege requests to each
candidate route and confirm a privileged effect on the unprotected one; the
protected sibling is the negative control (must deny). Require signed target-bound
proof and confirm reachability in the default deployment.

## Counterexamples and limits
A global dependency that genuinely covers the router, a second-layer check, or a
route that reaches no privileged operation refutes the lead (LATENT/NO-BOUNDARY).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the unguarded route performing a protected action for an unauthorized caller), a passing negative control (the guarded sibling denies the same unauthorized action), and signed target-bound proof on the shipped artifact.
""",

    "discovery/python-mlops-artifact-deserialization.md": """# Skill: ML/Artifact Deserialization and Model Loading

## Metadata
- **Category**: discovery
- **Language**: python multi-runtime
- **Stacks**: mlflow, huggingface, pytorch, sklearn, joblib, ray, kubeflow, ml
- **Signals**: torch, cloudpickle, joblib, numpy, mlflow, transformers, scikit-learn

## Doctrine
ML artifact ingestion is a high-value trust boundary: model and pipeline files
routinely execute code on load. Trace uploads, registries, and object-store
references into deserializers, and distinguish trusted operator artifacts from
attacker-controlled or cross-tenant input.

## Discovery vectors (up to ten)
1. Grep artifact loaders: `pickle`/`cloudpickle`/`joblib.load`, `torch.load`, `numpy.load(allow_pickle=True)`, `yaml.load`, custom `__reduce__` paths.
2. Trace the artifact source: user upload, model registry, object store URL, cross-tenant bucket.
3. Check whether a loader executes code on deserialize (pickle-backed formats do).
4. Distinguish safe formats (safetensors, ONNX-as-data) from code-executing ones.
5. Inspect model-server endpoints that load a user-named artifact by path or URL.
6. Follow pipeline/config files (`conda`/`requirements`/entrypoints) that run on load.
7. Check registry/experiment tooling that auto-loads artifacts.
8. Look for tar/zip model bundles extracted without path checks (traversal-to-overwrite).
9. Verify signature/hash checks before load.
10. Assess multi-tenant isolation of artifact stores and caches.

## Cross-language and stack examples
- PyTorch: `torch.load(user_file)` (pickle-backed) running a `__reduce__` gadget on load; `weights_only=False`.
- scikit-learn/joblib: `joblib.load`/`pickle.load` of an uploaded `.pkl`/`.joblib` model.
- TensorFlow/Keras: custom objects or `Lambda` layers only where the exact loader version, artifact format, and configuration permit executable deserialization. HDF5 or SavedModel filenames alone do not establish code execution.
- NumPy: `numpy.load(..., allow_pickle=True)` on an untrusted `.npy`/`.npz`.
- MLflow/Hugging Face registries: loading a request-referenced artifact into a pickle-backed loader.
- cloudpickle/dill/PyYAML: `cloudpickle.load`, `dill.load`, `yaml.load` of a params or config file.
- Negative-control candidates: a data-only format or a restricted `weights_only=True` loader must reject the same unsafe artifact under the captured loader version and configuration. Format names and flags alone do not establish safety; check custom operators, allowlisted objects, extraction, and downstream code paths.

## How to validate
In an authorized, isolated lab, load a benign artifact whose `__reduce__` writes a
lab-only marker (or prints `uid=`) and confirm execution. The negative control must
reject that same unsafe artifact under an enforced trust or loader restriction,
while a valid authorized artifact still loads. Merely loading a different harmless
file is not a negative control. Require signed target-bound proof.

## Counterexamples and limits
An RCE claim is refuted only for the observed path when the captured loader rejects
the unsafe artifact or enforced provenance excludes attacker-controlled artifacts.
A hash alone establishes identity, not authorization; assess who supplies it.
An extraction filter is relevant only to the traversal behavior it actually blocks.
Other parser, custom-operator, and downstream execution paths remain separate leads.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (a pickle-backed load executing a gadget marker), a passing negative control (a safetensors or allowlisted load rejects the same artifact), and signed target-bound proof on the shipped artifact.
""",

    "discovery/archive-extraction-and-tar-path-traversal.md": """# Skill: Archive Extraction Path Traversal and Symlink Escape

## Metadata
- **Category**: discovery
- **Language**: c/cpp python go java multi-runtime
- **Stacks**: tar, zip, archive, unzip
- **Signals**: tarfile, zipfile, archive/tar, libarchive, extractall, adm-zip

## Doctrine
Archive extraction must canonicalize member names and symlink targets and confirm
every write stays below the intended root. A member named with `..` or an absolute
path, or a symlink member pointing outside the root, is arbitrary write (zip-slip),
and a symlink-then-follow is arbitrary read.

## Discovery vectors (up to ten)
1. Grep extractors: `tarfile.extractall`/`extract`, `ZipFile.extractall`, Go `archive/tar`/`zip` loops, Java `ZipInputStream`, C/C++ libarchive/unzip.
2. Check for a join-without-canonicalize of the member name onto the destination.
3. Check whether `..`, absolute paths, and drive/UNC prefixes are rejected.
4. Inspect symlink and hardlink member handling (created then written through).
5. Verify the final resolved path is confirmed to be within the root before write.
6. Look for TOCTOU between path check and write (a symlink swapped in mid-extraction).
7. Check nested archives and recursive extraction for the same flaws.
8. Follow file-mode/exec-bit preservation that could drop an executable into a run path.
9. Trace who supplies the archive (upload, dependency, model bundle, backup restore).
10. Compare against a safe helper (`filter='data'`, a root-containment check) used elsewhere but not here.

## Cross-language and stack examples
- Python: `tarfile.extractall`/`extract` without `filter='data'`; `zipfile.ZipFile.extractall` trusting member names; `shutil.unpack_archive`.
- Go: `archive/tar`/`archive/zip` loops calling `filepath.Join(dst, hdr.Name)` without `Clean` and a prefix check; no symlink guard.
- Java: `ZipInputStream`/`ZipFile` with `new File(dir, entry.getName())` and no canonical-path containment (Zip Slip).
- Node: `tar`, `adm-zip`, `unzipper`, `decompress` writing member paths verbatim; `extract` without validation.
- Ruby: `rubygems/package`, `Zip::File`, `Gem::Package::TarReader` extracting names without containment.
- C/C++: libarchive/minizip/unzip writing member paths verbatim; symlink and hardlink members followed.
- PHP: `ZipArchive::extractTo`, `PharData::extractTo` with attacker-controlled entry names.

## How to validate
Craft an archive with a `..` member and a symlink member and extract it in an
authorized lab; oracle is a sentinel file written outside the intended root (or a
read of a lab-only file through a symlink). Negative control: a safe extractor or a
containment check must reject the same archive. Require signed target-bound proof.

## Counterexamples and limits
Canonicalization plus a verified root-containment check, rejection of `..`/absolute
members, and refusal to follow out-of-root symlinks refute the traversal (LATENT).
A path-looking string without a demonstrated out-of-root write/read is a lead.
""",

    "discovery/ssrf-server-side-request-forgery.md": """# Skill: Server-Side Request Forgery and URL-Fetch Abuse

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: http-client, webhook, proxy, pdf, image, url-fetch, cloud-metadata
- **Signals**: requests, httpx, urllib, axios, node-fetch, net/http, resttemplate, okhttp, guzzle, faraday, libcurl, wkhtmltopdf, imagemagick, 169.254.169.254
- **Unique vs**: ai-proxy-ssrf-identity (an AI proxy that lets the caller choose the upstream). This is the general class: any server-side fetch of a URL influenced by request input.

## Doctrine
A server-side fetch influenced by request input is an SSRF lead, not a finding.
Establish whether it crosses an intended destination or network trust boundary;
an intentionally public URL fetch alone does not establish a vulnerability. Possible
impact includes protected internal data or unauthorized service access, which must
be demonstrated with a bounded local-lab oracle and signed target-bound proof.

## Discovery vectors (up to ten)
1. Grep server-side HTTP clients and reverse-trace the URL or host argument to a request source.
2. Find webhook, callback, and notify-URL features that fetch an operator- or user-supplied endpoint.
3. Find import-from-URL, link-preview, avatar/image proxy, and HTML/PDF-to-image renderers.
4. Test the recorded metadata-fetch path against a lab-only metadata emulator; never query real cloud metadata.
5. Check URL scheme handling for `file:`, `gopher:`, `dict:`, and `ftp:` beyond `http` and `https`.
6. Probe allowlist logic for bypasses: DNS rebinding, decimal/hex IPs, `[::]`, `0.0.0.0`, userinfo `@`, trailing-dot hosts.
7. Follow redirects: an allowlisted host that 302s to an internal address (redirect-based SSRF).
8. Look for blind/out-of-band SSRF where only timing or a DNS/HTTP callback confirms reach.
9. Check whether the fetched body or headers are reflected back (full-read vs blind).
10. Trace SSRF-to-more: internal admin APIs, unauthenticated internal services, or a second-stage RCE.

## Cross-language and stack examples
- Python: `requests.get(user_url)`, `httpx`, `urllib.request.urlopen`; a Django link-preview or webhook worker.
- Node: `fetch`/`axios`/`node-fetch`/`got` on a caller URL; an image proxy piping the response.
- Go: `http.Get`/`http.NewRequest` with a header or param host; a `net.Dial` to a supplied address.
- Java: `RestTemplate`/`WebClient`/`URL.openStream`/`OkHttp` on a request-derived URI; SSRF via XXE.
- Ruby/PHP: `Net::HTTP`/`open-uri`/`Faraday`; PHP `file_get_contents`/`curl` on a user URL.
- .NET: `HttpClient`/`WebRequest` on a request-derived URL; an SVG or URL-preview fetch.
- Any: a redirect-following client or a DNS-rebinding bypass of a host allowlist.

## How to validate
In the isolated local lab, point the fetch at a sentinel behind the intended boundary
or a lab-only metadata emulator. The oracle is a forbidden request reaching that
sentinel or returning its synthetic protected value. Negative control: the same
request must be refused when the destination guard is enforced. Never contact real
metadata or external services. Require signed target-bound proof.

## Counterexamples and limits
A strict destination allowlist enforced after DNS resolution, a dedicated egress
proxy with no metadata route, and scheme/host validation refute the lead (LATENT).
An operator-only URL not influenced by request input is NO-BOUNDARY.

Evidence bar: a reachable fetch is a lead, not a finding - confirm an unauthorized boundary crossing with a lab-only sentinel or metadata emulator, a passing negative control under an enforced destination guard, and signed target-bound proof on the shipped artifact.
""",

    "discovery/known-vulnerable-dependencies.md": """# Skill: Known-Vulnerable and Outdated Dependencies (SCA)

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: sca, dependencies, supply-chain, lockfile
- **Signals**: requirements.txt, package-lock.json, yarn.lock, pnpm-lock.yaml, go.sum, gemfile.lock, pom.xml, cargo.lock, composer.lock, poetry.lock

## Doctrine
The fastest real-world bugs are often already public: a pinned dependency with a
known advisory whose vulnerable code path the application actually reaches. Presence
of a vulnerable version is a lead; reachability of the vulnerable symbol from an
untrusted source is a qualified lead requiring local proof of the advisory-specific
security impact. Prioritize direct, pre-auth, reachable dependencies; only a signed
target-bound oracle and negative control can support a confirmed finding.

## Discovery vectors (up to ten)
1. Enumerate direct and transitive dependencies from every lockfile and manifest, with exact versions.
2. Map each version to known advisories (CVE/GHSA/OSV) and note the fixed version.
3. For each candidate, locate the vulnerable API or symbol and confirm the app calls it.
4. Trace whether an untrusted source reaches that call (pre-auth beats authenticated).
5. Rank by severity times reachability times exposure; a reachable pre-auth deserializer beats a dev-only issue.
6. Diff the pinned version against the fix commit to understand the exact vulnerable code.
7. Check history for silent version bumps that hint at a quietly patched advisory (see silent-fix).
8. Flag unpinned or floating ranges that can resolve to a vulnerable or malicious version.
9. Look for typosquat, dependency-confusion, and abandoned packages in the tree.
10. Check vendored or copied third-party code that a lockfile scan would miss.

## Cross-language and stack examples
- Python: `requirements.txt`/`poetry.lock`/`Pipfile.lock`; a vulnerable `pyyaml`/`jinja2`/`requests` actually invoked.
- Node: `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`; a prototype-pollution or RCE advisory in a used library.
- Java: `pom.xml`/`gradle.lockfile`; a Log4Shell/Jackson/SnakeYAML-class issue on a reachable path.
- Go: `go.mod`/`go.sum`; an advisory in a directly-imported module reached by a handler.
- Ruby/PHP/Rust: `Gemfile.lock`/`composer.lock`/`Cargo.lock` mapped to advisories and call sites.
- .NET/NuGet: `packages.lock.json`/`.csproj` mapped to advisories; a reachable vulnerable package.
- Containers/OS: base-image and OS packages (Trivy/Grype-class) with a reachable CVE in the running service.

## How to validate
Confirm the exact installed version, the advisory, and a call path from an untrusted
source to the vulnerable symbol; the oracle is triggering the documented behavior
against the shipped build in an authorized lab. Negative control: the fixed version
or an unreachable call must not reproduce it. Require signed target-bound proof.

## Counterexamples and limits
A vulnerable version present but never called, gated behind auth the attacker lacks,
or already back-patched refutes exploitability (LATENT). A version-only match from a
scanner, with no reachability, is a lead - not a confirmed finding.

Evidence bar: a version match is a lead, not a finding - confirm with a bounded oracle (the documented vulnerable behavior triggered against the shipped build), a passing negative control (the fixed version or an unreachable path does not reproduce), and signed target-bound proof on the shipped artifact.
""",

    "discovery/secret-and-credential-exposure.md": """# Skill: Hardcoded Secrets and Credential Exposure

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: secrets, credentials, config, git, ci
- **Signals**: .env, id_rsa, .pem, credentials, aws_access_key_id, private_key, .npmrc, .git-credentials, .aws, secret_key_base

## Doctrine
A committed API key, private key, database URL, or signing secret in source, config,
history, CI logs, or a container layer is a lead requiring scope and exposure evidence.
Use synthetic credentials in the local lab to demonstrate the captured code's
unauthorized disclosure or access behavior. The validity, rotation status, and impact
of any discovered external credential remain unknown; never test it against its service.

## Discovery vectors (up to ten)
1. Grep for high-entropy strings and known key prefixes (cloud keys, tokens, `BEGIN` private-key blocks).
2. Search config, `.env`, sample configs, and checked-in secret files.
3. Walk git history and deleted files - a rotated-out secret may still be valid.
4. Inspect CI/CD config, build logs, and pipeline variables echoed into output.
5. Peel container image layers and Dockerfiles for `ARG`/`ENV` secrets and copied key files.
6. Check client bundles, mobile apps, and minified JS for embedded API keys.
7. Look for signing secrets (JWT `secret_key_base`, HMAC keys) that enable token forgery.
8. Find default or shared credentials in seeds, fixtures, and docs used in production.
9. Check backups, logs, and error dumps for credentials in transit.
10. Record the intended service and privilege from source; external validity remains unknown and must not be tested.

## Cross-language and stack examples
- Any language: a cloud access key or a `BEGIN PRIVATE KEY` block committed to source or history.
- Node: a token in `.npmrc`, a bundled frontend key, or a `config.js` with a live secret.
- Python/Ruby/PHP: `settings.py`/`secrets.yml`/`.env` with a database URL or signing key.
- Java/Go: `application.properties`/`application.yml` or a struct default holding a token.
- Infra: Terraform state, Kubernetes Secrets committed as plaintext, or a Dockerfile `ENV` secret.
- Mobile/desktop: a hardcoded key in an APK/IPA or an Electron/asar bundle.
- Git/CI: a secret in commit history, a `.git-credentials` file, or a CI log echoing a masked variable.

## How to validate
Treat discovered secrets as sensitive and redact their values from model context,
logs, and reports. Never use discovered credentials or call their external services.
In the isolated local lab, use synthetic credentials to reproduce an unauthorized
disclosure or privilege crossing through the captured code. A guarded build or
invalid synthetic credential must prevent the same effect. External validity remains
unknown; require signed target-bound proof for any demonstrated local behavior.

## Counterexamples and limits
An already-rotated, example, or test-only secret with no production scope is LATENT.
A high-entropy string that is not a credential (a hash, a public key, an asset
fingerprint) is a false positive.

Evidence bar: a secret-looking string is a lead, not a finding - confirm with a bounded oracle (unauthorized disclosure or access reproduced with synthetic credentials in the local lab), a passing negative control, and signed target-bound proof on the shipped artifact. Never use discovered credentials; external validity remains unknown.
""",

    "discovery/path-traversal-and-file-disclosure.md": """# Skill: Path Traversal and Arbitrary File Read/Write

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: file-download, upload, static-files, lfi, templating
- **Signals**: send_file, sendfile, staticfiles, filepath.join, os.path.join, path.join, fs.readfile, readfile, include, x-accel-redirect
- **Unique vs**: archive-extraction (zip-slip inside archives) and sql-file-privilege (SQL FILE verbs). This is request-driven file path handling in download, upload, static serving, and includes.

## Doctrine
When a request field reaches a filesystem path, the destination is attacker-influenced
until canonicalized and confirmed within an intended root. Reads leak source, config,
and secrets (LFI); writes drop web shells or overwrite config; includes can execute.
The bug is the missing containment check, not the presence of a dot-dot sequence.

## Discovery vectors (up to ten)
1. Grep file APIs (open/read/write/sendfile/static handlers) and reverse-trace the path argument to a source.
2. Find download and export endpoints that take a filename or path parameter.
3. Find upload handlers that derive the stored path from a client-supplied name.
4. Check static-file and asset routes for traversal above the served root.
5. Test dot-dot sequences, absolute paths, and encoded variants (`%2e%2e`, double-encoding, overlong UTF-8).
6. Check null-byte and trailing-dot or trailing-space truncation on the target platform.
7. Inspect template include and partial resolution that accepts a user-controlled name (LFI to RCE).
8. Look for `X-Accel-Redirect`/`X-Sendfile` trust where the app path is not contained.
9. Verify path-component containment and prevent symlink replacement between validation and opening; a string prefix check is insufficient.
10. Trace write primitives to a code or config path for traversal-to-RCE.

## Cross-language and stack examples
- Python: `open(os.path.join(base, name))` or `send_file(user_path)` without containment; a Django static misroute.
- Node: `fs.readFile(path.join(root, req.query.f))`; `res.sendFile` without the `root` option.
- Go: `filepath.Join(root, query.Get("f"))` without `Clean` and a prefix check; `http.ServeFile`.
- Java: `new File(base, request.getParameter("name"))`; a Spring resource handler above the root.
- PHP: `include`/`require`/`readfile`/`fopen` of a user path; wrappers like `php://filter`.
- Ruby/Rails: `send_file`/`File.read` on a params-derived path; a static route above `public/`.
- .NET: `Path.Combine(root, userInput)` without a canonical-prefix check; `PhysicalFile` on a user path.

## How to validate
In an authorized lab, request a lab-only sentinel outside the intended root; the
oracle is the sentinel contents returned (read) or a sentinel file appearing outside
the root (write). Negative control: a contained path resolves normally and a
traversal attempt is rejected. Require signed target-bound proof.

## Counterexamples and limits
Verified path-component containment through the actual file operation, or an enforced
allowlist of names, can refute the specific traversal path. A read-only mount prevents
writes but does not establish read confinement. A reflected dot-dot in an error with
no out-of-root read or write is a lead only.

Evidence bar: a path-looking parameter is a lead, not a finding - confirm with a bounded oracle (a lab sentinel read from, or written, outside the intended root), a passing negative control (a contained path works while traversal is refused), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/web-xss-and-output-encoding.md": """# Skill: Cross-Site Scripting and Output Encoding (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: html, templating, react, vue, angular, jinja2, erb, thymeleaf
- **Signals**: innerhtml, dangerouslysetinnerhtml, v-html, mark_safe, html_safe, bypasssecuritytrust, document.write, insertadjacenthtml
- **Unique vs**: injection-by-language (the umbrella). This is the deep web-XSS lens: contexts, framework escape opt-outs, DOM sinks, and sanitizer bypass.

## Doctrine
XSS is output-encoding failure: untrusted data reaches an HTML, JS, attribute, or URL
context without context-correct escaping. Reflected and stored variants execute
server-rendered payloads; DOM XSS executes purely client-side. The context (HTML body
vs attribute vs script vs URL) decides the required encoding and the bypass.

## Discovery vectors (up to ten)
1. Inventory sinks: raw HTML emission, `innerHTML`, `document.write`, `insertAdjacentHTML`, framework raw-output directives.
2. Grep template auto-escape opt-outs: Jinja2 `safe` filter, Django `mark_safe`, Rails `html_safe`/`raw`, ERB unescaped output.
3. Find framework-specific bypasses: React `dangerouslySetInnerHTML`, Vue `v-html`, Angular bypassSecurityTrust APIs.
4. Trace stored inputs (names, comments, filenames) rendered later in a different page (stored XSS).
5. Trace reflected inputs (search, error messages, headers) echoed into the response.
6. Map DOM sources (`location`, `document.referrer`, `postMessage`) to client sinks (DOM XSS).
7. Check attribute and URL contexts: `href`/`src` accepting a `javascript:` URL and event-handler attributes.
8. Check JSON or JS embedding where an unescaped closing script tag or data breaks out of a script block.
9. Assess sanitizer correctness and mutation XSS that survives a DOMPurify-style clean.
10. Evaluate CSP as mitigation and look for bypasses (unsafe-inline, JSONP, permissive host allowlists).

## Cross-language and stack examples
- Python/Django/Jinja2: `mark_safe` or the `safe` filter on user data; `format_html` misuse.
- Node/React: `dangerouslySetInnerHTML`, an `href` set to a `javascript:` URL, `document.write` of a param.
- Ruby/Rails: `raw`/`html_safe` in a view; a helper returning unescaped user input.
- Java/Thymeleaf/JSP: unescaped `utext`, unescaped EL, or a JSP scriptlet writing a request parameter.
- PHP: `echo` of a request field into HTML, or a template engine with escaping disabled.
- Go: `template.HTML` or `text/template` emitting unescaped user data into an HTML response.
- Angular/Vue SPA: an `[innerHTML]` or `v-html` binding, or `bypassSecurityTrustHtml` on user data.

## How to validate
Deliver a benign marker payload (a unique DOM change, not a noisy dialog) in the exact
context and confirm attacker-controlled script execution in the affected principal's
origin; HTML breakout alone is insufficient. The oracle is the marker running in a
real browser DOM against the shipped app. Negative control: a correctly encoded input
renders inert. Require signed target-bound proof.

## Counterexamples and limits
Context-correct auto-escaping, a strict CSP that blocks execution, and a vetted
sanitizer refute the lead (LATENT). Reflected input that is HTML-encoded, or a sink in
a non-HTML content type, is a false positive.

Evidence bar: a reachable sink is a lead, not a finding - confirm with a bounded oracle (a benign marker executing in the real DOM in the correct context), a passing negative control (an encoded input stays inert), and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/ssti-server-side-template-injection.md": """# Skill: Server-Side Template Injection (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: jinja2, twig, freemarker, velocity, thymeleaf, handlebars, erb, mustache, spel, ognl
- **Signals**: render_template_string, from_string, freemarker, velocity, spelexpressionparser, ognl, handlebars.compile, lodash.template, text/template
- **Unique vs**: cpp-inja (the C++ Inja engine specifically) and java-gateway-plugin-script-rce (a gateway plugin evaluating scripts). This is the general cross-language SSTI class.

## Doctrine
SSTI is user input becoming template source, not just template data. When a request
field is compiled or evaluated as a template, the engine expression language runs,
often to RCE. The distinction is rendering a fixed template with user data (safe)
versus rendering a user-supplied template string (injectable). Sandbox strength
decides how far it goes.

## Discovery vectors (up to ten)
1. Grep render-from-string APIs and confirm the template text (not just the data) is user-controlled.
2. Identify the engine and its expression language to choose the right polyglot probe.
3. Send a math or marker probe (an arithmetic expression) and check for evaluation in the output.
4. Escalate from expression evaluation to object and attribute access to a runtime call.
5. Check email, report, and notification templates that admins or users can edit.
6. Check filename, subject, and label fields rendered into a template downstream (second-order).
7. Assess sandbox escapes for the specific engine (attribute walks, builtins, class loaders).
8. Distinguish SSTI from reflected XSS by proving server-side evaluation, not client rendering.
9. Look for expression-language contexts (SpEL, OGNL, MVEL) reachable from request data.
10. Trace SSTI-to-file-read or SSRF where full RCE is sandboxed but I/O is reachable.

## Cross-language and stack examples
- Python: Jinja2 `render_template_string(user)`; a Mako or Tornado template from a string; an arithmetic probe yielding its product.
- Java: Freemarker/Velocity/Thymeleaf from user input; SpEL or OGNL evaluation of a request field.
- Node: Handlebars/Pug/EJS compiling a user template; `lodash.template` on input.
- Ruby: ERB/Slim/Liquid rendering a user-supplied template string.
- Go: `text/template` or `html/template` parsed from user input flowing into a sink.
- PHP: Twig/Smarty/Blade compiling a user-supplied template string reaching evaluation.
- .NET: RazorEngine or Scriban compiling a user template; a `DataBinder.Eval`-style expression.

## How to validate
In an authorized lab, submit an arithmetic marker and confirm server-side evaluation,
then a bounded probe of the claimed security boundary. Arithmetic evaluation alone
may be an intended template feature: the oracle must show unauthorized execution,
protected data access, or another demonstrated privilege crossing. Negative control:
the same input used as template data renders literally. Require signed target-bound proof.

## Counterexamples and limits
Rendering user input strictly as data into a fixed, auto-escaping template refutes
SSTI (it may still be XSS). A logic-less engine (Mustache) or a hardened sandbox
limits impact. A reflected template expression that is not evaluated is a lead only.

Evidence bar: an evaluated probe is a lead, not a finding - demonstrate unauthorized execution, protected data access, or a privilege crossing beyond intended template behavior, with a passing negative control and signed target-bound proof on the shipped artifact.
""",

    "bug-classes/race-condition-and-toctou.md": """# Skill: Race Conditions and TOCTOU (bug class)

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
""",

    "bug-classes/xxe-xml-external-entity.md": """# Skill: XML External Entity and Unsafe XML Parsing (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: xml, soap, saml, svg, office-xml, xslt
- **Signals**: documentbuilder, saxparser, xmlreader, lxml, etree, libxml2, nokogiri, expat, xstream, resolve_entities, doctype
- **Unique vs**: document-library-untrusted-input (parser libraries fed untrusted documents). This is XML-entity handling in request-facing XML: APIs, SOAP, SAML, SVG, and office-XML uploads.

## Doctrine
Untrusted XML that causes external resource resolution is an XXE lead; accepting a
DOCTYPE alone is not proof. Demonstrate the claimed file read, forbidden fetch, or
resource-limit violation. SAML or SOAP signature bypass requires separate evidence. The bug is a parser configured to load external
entities; the fix is disabling DOCTYPE and external entities. Any XML endpoint is in
scope until proven safe.

## Discovery vectors (up to ten)
1. Grep XML parser construction and check whether DOCTYPE and external entities are disabled.
2. Find request-facing XML: SOAP endpoints, XML APIs, and XML-RPC handlers.
3. Find file uploads that are XML underneath: SVG, DOCX/XLSX/PPTX, SAML assertions, RSS/Atom.
4. Test an external-entity probe pointing at a lab-only file and an out-of-band URL (blind XXE).
5. Check for parameter entities and out-of-band exfiltration when direct reflection is absent.
6. Assess denial of service via entity expansion and nested entity limits.
7. Check XInclude and XSLT document loading or external stylesheets as entity-adjacent vectors.
8. In SAML or SOAP, check whether entity or comment handling enables a signature-wrapping bypass.
9. Trace whether resolved entity content is reflected (full read) or only observable out-of-band (blind).
10. Look for language defaults that are unsafe (older libxml2, some Java parsers) versus hardened configs.

## Cross-language and stack examples
- Java: `DocumentBuilderFactory`/`SAXParser`/`XMLReader` without disallow-doctype-decl; XStream or JAXB.
- Python: `lxml.etree` with `resolve_entities=True`, or `xml.etree`/`xml.sax` on untrusted input.
- PHP: entity loading left enabled on older runtimes; `simplexml_load_string` on user XML.
- Ruby/Go/dotnet: Nokogiri with entity loading enabled; XML readers with DTD processing on.
- Uploads: an SVG avatar or an office-XML document parsed server-side with entities enabled.
- Node: `libxmljs`/`node-expat` with entity expansion enabled; a SAML library parsing assertions.
- .NET: `XmlDocument`/`XmlReader` with `DtdProcessing=Parse` and an `XmlResolver` set.

## How to validate
In an authorized lab, submit an entity referencing a lab-only sentinel file or an
out-of-band URL and confirm retrieval; the oracle is the sentinel content reflected
or the out-of-band callback firing. Negative control: a parser with DOCTYPE and
entities disabled must not resolve it. Require signed target-bound proof.

## Counterexamples and limits
A parser with DOCTYPE and external entities disabled, or input that is not parsed as
XML, refutes XXE (LATENT). A DOCTYPE echoed in an error without entity resolution is a
lead only.

Evidence bar: a DOCTYPE reaching a parser is a lead, not a finding - confirm with a bounded oracle (a lab sentinel file read via an entity or an out-of-band callback), a passing negative control (a hardened parser refuses to resolve entities), and signed target-bound proof on the shipped artifact.
""",
}


def seed_all(skills_dir: Path) -> int:
    """Write missing defaults or exact known old defaults; preserve custom text."""
    import hashlib
    # Exact shipped revisions from the live and reviewed releases. Operator edits
    # and enable/disable state are preserved; repeat hydration is a no-op.
    reviewed_revisions = {
        'bug-classes/guard-authorization-bypass.md': {
            '33b5a945e8b181424df6b67d255c08a517b9e907faaecb568608a572f3c08c48',
            '8f71c04e8614b9331d8bb6ad93dec35ef5e239dc3d62426a1f5222f40b22ef14',
            'ec171787354ba0236f2ce95540593f0db9bd8d2748355908a73c21596780b18e',
        },
        'bug-classes/injection-by-language.md': {
            '497ab2a7135616b5ebf29e46443f18d5d7ed06c39607043016035c5926113870',
        },
        'bug-classes/jwt-dashboard-auth-bypass.md': {
            '849a44a55740d3efc4fb3fc95b1f4273fc78af8b35a5710d78f91e2bfa876e6c',
            '8df95458c05cd375868a9fc697ad7d0e30eddb2e6ca04c97fc60ae0adc0c3f5f',
            '9b591c167792c3fc3573e274c11f222c54bfa0a0b8945dc2455666a41edbe4f7',
        },
        'bug-classes/logic-and-state.md': {
            '061b66fd456b904ff1fe359f1ab31db4c69b6d637110c012530ebaa78ae5ed10',
            '2c44dd3eb5dbb727da7d945cd13fed5034aaa4be4ecbec2622fd49b612859d1a',
        },
        'bug-classes/plugin-script-engine-rce.md': {
            '73781008fcaf9dee2c6369159c6ac7c898e4b57064e5af47b8d05d4c66cf45eb',
            'cefd4bb76871ca9a10a7631450aa65ff18ed50dc514da8b4d1c65faafe8e8ca5',
            'd34c658c0aa4321692c19a05040b0427213826169dbe84496a053ebcb7994997',
        },
        'bug-classes/race-condition-and-toctou.md': {
            '9b6f8338ade6b77e65429a40688c1df2ec1774b9d557a0ef88cf0e19448f027f',
        },
        'bug-classes/ruby-command-injection.md': {
            '25e59c69657c640ec5c87bc5982e5f8f0488ba74f26dec98c05d09cc98409929',
            'b805b1a884148a3df659dbf7c3cf5781f19925f51d3d2d469b74b61aa3a9ae9e',
            'f499051d1bc73f34d2defcea4d19d481da042f569bb9f06d60acacf7b1db4c82',
        },
        'bug-classes/ruby-unsafe-deserialization.md': {
            '886c23ac400973b6bb8e7267f4b1ba5f6a9aaa83c0a3631bd453aae75050b27f',
            'c8f4836749338dd84def009d2463e0b2f03624c6b8ac00002b4a48597c4e4102',
            'e2bc65122ad6b46f6f0412fb46b08b18c00c7098cfcdc8ef91c9f16b4805f508',
        },
        'bug-classes/ruby-yaml-pson-catalog-deser.md': {
            '3102a807bcb4aac7f0669063a5edb99bdb10849f690ec358a20f6728fe8efcd4',
            'a5abd1f9d07f2c8a4a563f11d8dd4e1446de31335aa1f5eccf28dac4230d5c99',
            'b17de51b1d057a6dc9427e955d09687de811ef97bf3921395ee6a8f139221366',
        },
        'bug-classes/ssti-server-side-template-injection.md': {
            '015181d69be3478311d30fea228ca60bb52d9ff9b5b35f3135501bcfd38f3e23',
        },
        'bug-classes/web-xss-and-output-encoding.md': {
            '810fe230ece54877d356834917d3a56a3ca22f6e6ad3cded842edce2e9eae772',
        },
        'bug-classes/xxe-xml-external-entity.md': {
            '3e0a07dedf431f6281f66a1aa21ed58404dcf5b38117eed90a8b87799dd0964b',
        },
        'discovery/ai-proxy-ssrf-identity.md': {
            '9b6b65de6a0093438da06f9ac99a432d1c16faa63353db6ccd68a22dfe8eb461',
            'c29f980fed567b5953c78a9c44d4b4c405ce9af74db5e634ac2e6c5b11933e31',
            'ddd1616ff08b683365ebb5f6ac58dd4c4c88250570c46159aa60ae7300f6db92',
        },
        'discovery/archive-extraction-and-tar-path-traversal.md': {
            'cf11b8c476f7e0f8d50564b57c40b265b78bd22edc0cb33df02328097959df71',
            'ee34b5110903b21292cb3ef4ab8f03db6a97b37218eea15dbcb72fc73bb2ee63',
        },
        'discovery/ci-cd-pipeline-step-parser-command-injection.md': {
            '1e705e8a9ca0587c03bba1ac42f5d3f9adc7dbf74ba6bc238171a8d8d1ca3c59',
            '4bfd6a0986e0d29b4b37458a09851973612a4a17a33b54b7370b3f14af17973c',
            '87fcdc1ed1717a685283cb3239157291b8d15a69ad9180485124aeb2658b8a61',
        },
        'discovery/cpp-inja-template-script-rendering.md': {
            '0a6e91ef4faf00d03b35bc9de506aeebe0293bb543bdbbf27d1d912ed926e432',
            'b1ff83ba6bcf24ceec45fad67f20acf56173880bb99af283ea3667ea998bf717',
        },
        'discovery/default-insecure-deploy.md': {
            '2bc4c3b9e5a36b613b7839823693f7b10c1d044b73fc02c5aedd402470f1fe0b',
            '86f8f211f4e58cf52c3584181a60d9ddb6362f237c172bd42f4f2ac2d9907e30',
            'af44abe9333c0ad182af71808a015b95023c2b6245f08e6528b8dbcec986e56a',
            'c2c9d77d7582c84e4387353b44ce6c69e87001183ca9c5ca3faa0c80f4d2e1bd',
        },
        'discovery/django-object-authz-gap.md': {
            '402485fe688984a1f6406b5092a2e12b9c489a9d5e5aec38c53f0b5b75cc34ea',
            '7f27aa403e46a5ddb17022ea345c15d955fd6f092c757ced3b63985b336e3b2c',
            'a538773e7689ac3a8d984f2db411aaee498cb04e2fb4d9e2f08e7469ebbd3aa7',
        },
        'discovery/document-library-untrusted-input.md': {
            'c8884a7c195f07cb76e7c5b277b2e40623a639aaaddb0bc31718b94cf1acba5e',
            'da717e8c589707741fc01ae4ea0cdd23e5f7e209475a57c29eefe249468b1150',
        },
        'discovery/envoy-ext-authz-fail-open.md': {
            '563c74febf2a7f487e1d8223ede4c464c7fee143b06c48fdeec638f4ce77595b',
            '6369aeb88f4af610903affac81601ec57a6cf531d1eb79e560fc2252cd35c111',
        },
        'discovery/fail-open-native-auth.md': {
            '8715850e4cdb04f1435e73c2b1048abd3e75d49b9e98cf9b6da70eedbaa9efab',
            '94813e1fcdc6cb473c8ac4460b0c0abcb4b8ca9f5ecb0287a0e369cdd9581360',
            '9914cd81e348b3c0a0ff5335384aed7a063441400a23f96495b0c1db507e3718',
        },
        'discovery/fastapi-authentication-and-dependency.md': {
            '429405857a2043ee24352727b562fb9fdf105de8923ba5ef61e72c70dd912add',
            '5929eb82b6da6aac2725fa32262c1325cd22172b6deb09e2f3728a88c531a3c2',
            '94f8e609b82457329f918cd55aac031baa9aef198e578f0a59ab7aa36726f18a',
        },
        'discovery/go-reverse-proxy-dashboard-auth.md': {
            '54d7bb58aabc888f53013cf9de2040cb10c6dbd141ad2e233bc8350d08693f3e',
            '7726057cd9659797667f15f5eee24a5c0743f7f0e2db73f411d1f1a13a7bb707',
            '8f1e0d108137a19981d327d30968dd99cfc67a1c77ecd95efa56b8c263f1185b',
        },
        'discovery/guard-alternate-path.md': {
            '08e2c27da457a65e71823a8cd184f391d23c44578392a4694c9ebca67bbc71c9',
            '3c6be65cbc40f8a9b8b330c3d88775f26b8b71124bac5f0bab09b6b0d09b3418',
        },
        'discovery/java-gateway-plugin-script-rce.md': {
            '177701eb6973ac7baf5139d9f933aebd03c8854cc4bf3f685c7880de8bfd2342',
            'f08d5fdcfde75315850874427cbc6959a5f62889d43af3e60a0cbaa265f544ad',
        },
        'discovery/known-vulnerable-dependencies.md': {
            '39a6a6ee95b45755c2855fd740ebbbaf68688bd8e0dc3273a90c65bf49201366',
        },
        'discovery/path-traversal-and-file-disclosure.md': {
            '98ad56b1c39a87e2f64f514f3cfa89ceb80f85011512664a7d4cb72eacef68e2',
        },
        'discovery/plugin-dlopen-rce.md': {
            '16ac06405285c913cb6c17aaf4420323ad5ffca98cef65a21cba5ed17138def3',
            '1ff2beee4ed1d9cc216d28cce2f3f3d2c832e5ccd73bdd9c5cda5768d781b36a',
            '344bfa3c2c33d6248da35ef28d876eab3ff075ec53474f7b12bb562725155335',
        },
        'discovery/privileged-cli-hook-rce.md': {
            '7983b75429b43537a414497ca28acba5bd713bf32611693f9222d514753b25e4',
            '8ec8215e951c4e08748b001b0d9337be6825d02a7e30a3768ea80c6730681d00',
        },
        'discovery/protocol-control-plane.md': {
            '283be58d2527042a92cd862c2e5cd9573701f4cdcfd1ea986d724825b1487d9f',
            '72b652e553157fceb9693a7fd680a349cb03b422f098e47f4439b1602bdc7b09',
            '860255402aed2f08817b9a101d7ee936907340856cd5d8b4175c07b72035dcfc',
            '93ccc4509f47a2ad9c7160f06e4fa082a4da267c88c5ce567b00645a38b79b56',
        },
        'discovery/puppet-agent-catalog-rce.md': {
            'a6a2438d25e73c81840813f66024168e22256db2e19db67a5b7fd4f2b1689836',
            'd400792cfac8237e531a03f07c42c56844150db51c55a8d254016827c6522b59',
            'f0a891f43067da748431116cb756e9ed642a331a5b85deb60a0e05bb0f3b1e6b',
        },
        'discovery/python-mlops-artifact-deserialization.md': {
            '1a9e56530ddd0b3ed1b7247e4c87b8df7db3cfc84efcba677805755207ec5a23',
            '4e8fac4b48a5352bde4bf13c638c98f1c0da5096cb36dec712b14c2e3ff48b45',
            'a1362ae34e4038631e7a06f3c663ebe400b87e50869f0d102f37efc07083b55d',
        },
        'discovery/rails-node-ssr-exec.md': {
            '03319e1220c2bb9db598f9cb41bf03e03105fdc7e27e0eada2eca9773e8b7a45',
            '400b0b4fd2cd02c5b3c6e90dfb67067b7b43e375a5b70f56e8ef6a12fa7a9e2c',
            'b77191bcdf7d4ed726c65b98ec946b90baa5f56f5bc4f2b053ae6d64ed297b58',
        },
        'discovery/secret-and-credential-exposure.md': {
            '471543cba0396304f2f4cf4b113796b1e92aa0fb460c4944a68745d69639bc2f',
        },
        'discovery/silent-fix-and-variants.md': {
            '84851784b6387050a3e55df11276de5c5893bd7736214ba9bb2886c138165fe8',
            'b39fe2b6aab2065a351bc3a85191bd87d9310b58c1244a447437414de81a0315',
        },
        'discovery/sinatra-unauth-control-ui.md': {
            '287c8e44c34ea350ff6d2e9dc89ae5c608062aff97b211b50d9d824b38d0e5f0',
            '5b1d893f978ebcf5523a3f1bbb1ba593fc910f76ba7ccbc02cbe37189e3a0f14',
            'b46b27699d04491b9d6a539ee18d6c538bbb3f4fa5253ee6424e116984d998fe',
        },
        'discovery/sink-first-reachability.md': {
            'c865a3dba9eb09d07331b31190150f5ddc37ee6c82220ce99e04d8d47d30a9fe',
        },
        'discovery/sql-file-privilege.md': {
            '86641c0a2b61e3e4459d33f465cc48f9692c78949ea4de6a61b3b1c122c26906',
            'f068c74e7c9a70d50e50f2f4b0ed7bd4ef9dcdaeaece7e90655af026eb7ef102',
        },
        'discovery/ssrf-server-side-request-forgery.md': {
            '8124dddd61202d6d8a1b7a4778aa7b7e1af26a45dd164fa977a21169cd2d273e',
        },
        'discovery/stubbed-privilege-check.md': {
            '166853a77da3f04f6298807eb29483113138d9af3e27eedc8ecccbe8e89a244d',
            '6f7f314d349bbf7cb98fd3a55e461575d7585db64a3c868b71ca7dd51b4233ac',
        },
        'discovery/t1-t11-discovery-techniques.md': {
            'e4f70e9d3ac914cf0be4fc90632615271e59b52bad9366cd327d972157b7f6d3',
        },
        'discovery/test-oracle-mining.md': {
            '377d12eed34dd5c3d4a8f2f58ba40f851d1a6b094ad85f1463071df38a956e49',
            '3f1e370ac3b5ac8769c1d78aa56e55021498c15897cb725efebf1eaf686aeeda',
            '73bda55e7ad0082b031f81feabfc86588a78344f04ffb3c81fe07562c1a14d6b',
        },
        'discovery/waf-management-plane-bypass.md': {
            '36c8a9517a0dc1c11df0c98aaa95564666a3165e21999c12a6c07fe5e1394b3e',
            '39f2aee2dcfbb97912ff61370227dff1f7daeadb518f382d9761ae089362323d',
            '84b7ecc2fcde0c6a7c802fa62f9f5ac483f6613c6add6004858ddc8f984091bd',
        },
        'discovery/weak-secrets-jwt-oauth.md': {
            '1afa2f15d8dbea4c1fa68c9868c7f9d4f2cf74e0982cb9092d631802eed60084',
            'da1229bfdd371e9a1cb328e00a4ae125104591302726fe4a50ca5ba9dfd86479',
        },
        'gating/false-positive-patterns.md': {
            '093820e7cb9523a89293e9be401e187f2666c218ce698be17c0290f18c05ecab',
            '359200b120d9ec837a2536283f289df4e35c4cfefb2bbe360cc42011ca291dff',
            '4b83da9dd95cd0d3fb2d1d72ceeb72b04c84bc163e6c2c1927ccea0c3985421b',
            'aba421f56976de8de01a276ff74aebd20edb62484ebc25084c4310561b0d587f',
        },
        'gating/high-severity-priority.md': {
            '318aa61efbdf9e58d925e3708220f135c746dbf3ac4b5742b0f47af47f64ac88',
            'ad65395f7ae3b938da8041c6dcecd8cb21efcacc5a5c420eb76bfb36659fc772',
        },
        'gating/hypothesis-qualification.md': {
            'b14c80a9f68be4416e64df085bc50f16e2424ea372f986566dfdc34f218f9181',
            'e059da04eb4529c4e75171a2a5740cd1393548f4daa1186c1e04eb54abd1be71',
        },
        'gating/triage-prioritization.md': {
            '00deb099525a6d020dfa8ab94f3bf25d5461c27d2465ea60295ccd2ba2cb3b20',
            '9e8bb4257cc080661933548b95102e5cea8ba05d66f35828b3a1251bb38d11a5',
        },
        'methodology/agent-app-lab-poc.md': {
            '963e314e85caa10e6d578e2e2439b0239919867fd2d68412cbbbfec0e37f2eb3',
            'f1d7a53d960ebc7b42b88d4692eb5f5eb30d3bc821856c45af3a8eb58271284d',
        },
        'methodology/conviction-ladder.md': {
            '954f11eb45d4ed215f048484a71e17079b9211f5c86029a805f8b0e0bda8cc68',
            'd5814bc3b4bb5c516f6e3027ec27b55d2a5957fac94550b11af6deec531f32c1',
        },
        'methodology/coverage-ledger.md': {
            '04713b6368d44d1a53b8616a8eaa32a1542a007f867be9aa37f3b83b9135e896',
            '13b7fa8907c69d963f748e49bd07e4bf4e4b32e937484dc94663f4f1b4446703',
            '7fdfa3ea4e1879c4b9b697688a7b9850b483e34c9ef8280d753898adc1fd7af8',
        },
        'methodology/gateway-lab-poc.md': {
            '7e9384e96e1dac371d395dfd4e2f5c5db7ab0ad3e0aecf31f49d64d0fd30c81c',
            'aba2877c6e2e77119c9aae5cad9f7206bc2a0b6d1f21df949db00664aa1c9580',
        },
        'methodology/library-lab-poc.md': {
            '384d5eb08d000c550b2f622a86bdbe2098ada5e2e2f01d174bbfd86179374477',
            '73a5a3fb4a6301fc66588afb7cf9c490ac72cf71bd4971a312c50150b6b8e90c',
        },
        'methodology/mistake-categories.md': {
            '6b923550237e106b34918135185a47aa1c39fcd3f7a1a350327469f94065509b',
            'ca19ecc776ce0d327dae4861d21d0e067ebabfaa04dcc55756d6c16918fef852',
        },
        'methodology/rwx-primitive-coverage-matrix.md': {
            '5b8df3c36f373287cfdf22892e8ada71396cbbd9033a3e23d7288e161e6c1a3c',
            '7e25f873fcbfd10afce73207262b95ddb692fd92abae9067a96e4d439a045cbd',
        },
        'methodology/severity-honesty.md': {
            '8ca44ddd7fa4eb4d28c192d0408d83e17d4ef913b7545fb8026b3d5ccff91f5d',
            'dc1cf7d82357fec48abeccf0e4c39da0a6fe6dcd421617861ecaa1db2d13e09a',
        },
    }
    seeded = 0
    for rel, content in SEED_FILES.items():
        path = skills_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content.strip() + "\n", encoding="utf-8")
            seeded += 1
        else:
            # Upgrade thin stubs (< 800 chars) with rich content
            try:
                existing = path.read_text(encoding="utf-8")
            except Exception:
                existing = ""
            if rel in reviewed_revisions:
                if hashlib.sha256(existing.encode("utf-8")).hexdigest() in reviewed_revisions[rel]:
                    path.write_text(content.strip() + "\n", encoding="utf-8")
                    seeded += 1
                continue  # A short operator edit is still an edit, not a stub.
            if len(existing) < 800 and len(content) > len(existing):
                path.write_text(content.strip() + "\n", encoding="utf-8")
                seeded += 1
    return seeded
