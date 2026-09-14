# Skill: WAF/Proxy Management-Plane vs Data-Plane Bypass

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
