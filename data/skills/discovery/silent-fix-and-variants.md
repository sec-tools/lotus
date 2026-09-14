# Skill: Silent-Fix Mining and Sibling Variants (B6)

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
