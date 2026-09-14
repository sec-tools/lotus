# Skill: JWT / Dashboard Auth Bypass

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
