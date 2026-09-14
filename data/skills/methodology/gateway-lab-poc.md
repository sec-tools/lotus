# Skill: Frictionless Gateway Lab PoCs

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
