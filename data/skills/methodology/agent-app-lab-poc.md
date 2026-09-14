# Skill: Frictionless Agent/App Lab PoCs

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
