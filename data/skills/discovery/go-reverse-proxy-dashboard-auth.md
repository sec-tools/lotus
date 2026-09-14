# Skill: Go Reverse-Proxy Dashboard and Empty-Token Fail-Open

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
