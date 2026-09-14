# Skill: Triage Prioritization and Devil's Advocate

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
