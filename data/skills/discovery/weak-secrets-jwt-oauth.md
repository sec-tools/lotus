# Skill: Weak Secrets, JWT Header Attacks, and OAuth Confusion

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
