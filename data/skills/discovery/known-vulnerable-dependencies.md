# Skill: Known-Vulnerable and Outdated Dependencies (SCA)

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
