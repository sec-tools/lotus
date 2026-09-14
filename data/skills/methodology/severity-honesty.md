# Skill: Severity Honesty (SH-1..SH-9)

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
