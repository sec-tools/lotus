# Skill: Envoy / Sidecar ext_authz Fail-Open, Admin Bind, and Lua RCE

## Metadata
- **Category**: discovery
- **Language**: c/cpp yaml lua envoy multi-proxy
- **Stacks**: envoy, nginx, traefik, haproxy, xds, lua, service-mesh, istio
- **Signals**: failure_mode_allow, ext_authz, envoyproxy, auth_request, forwardauth
- **Unique vs**: fail-open-native-auth (a C++ broker anonymous credential, not xDS HTTP filters) and waf-management-plane-bypass (a WAF management API).

## Doctrine
An external-authorization filter is a data-plane gate. `failure_mode_allow: true`
(or the C++ `failure_mode_allow_` / `FailureModeAllow`) means: if the authorization
service is unreachable, every request is allowed. That is a pre-auth data-plane
bypass, not DoS. An admin interface bound to all interfaces exposes config and
lifecycle endpoints. Inline scripting that shells out is RCE when request data
reaches the argument.

## Discovery vectors (up to ten)
1. Grep `failure_mode_allow: true` in YAML and `failure_mode_allow_`/`FailureModeAllow` in C++.
2. Find the admin block bound to `0.0.0.0` and which endpoints it exposes (config dump, lifecycle, stats).
3. Grep inline scripting sinks (`os.execute`, `io.popen` in Lua filters) and trace request data into them.
4. Check what happens when the authz cluster is down: fail-open vs fail-closed, per-route overrides.
5. Compare routes: a filter chain applied to most virtual hosts but skipped on one.
6. Inspect timeout/error handling in the authz call for an implicit allow on error.
7. Look for trusted-header injection where the authz decision is carried in a spoofable header.
8. Review RBAC/JWT filters ordering relative to the authz filter.
9. Check for a management/xDS control plane reachable without auth.
10. Map the sibling stack (nginx `auth_request`, HAProxy, Traefik ForwardAuth, API gateways) for the same fail-open toggle.

## Cross-language and stack examples
- Envoy: `ext_authz` with `failure_mode_allow`, admin on `0.0.0.0`, a Lua filter calling `os.execute`.
- nginx: `auth_request` where a `500` from the auth subrequest is mishandled into allow.
- Traefik/HAProxy: ForwardAuth/`http-request auth` misconfigured to pass on error.
- API gateways: a custom authorizer whose error path defaults to allow.
- Kong/APISIX: an auth plugin whose error path defaults to allow on the data path.
- Istio: compare the effective `AuthorizationPolicy` action, workload/port scope, and rules with the intended boundary; a nonmatching rule or permitted request alone is not a bypass.

## Phase-2 PoC
1. Start the proxy (or the lab gateway analog) with the authz service reachable.
2. BEFORE: authz up, an unauthenticated request to a privileged path is denied (403).
3. AFTER: stop the authz cluster; the same request returns 200 with a privileged body or a marker (`LOTUS_AUTHZ_BYPASS`, admin config dump).
4. Oracle: a privileged body (`uid=`, `LOTUS_ADMIN`, config-dump clusters), not merely HTTP 200.
5. Measure: status_before must differ from status_after; body_after must contain the oracle. Require signed target-bound proof.

## Counterexamples and limits
`failure_mode_allow: false` with the admin interface on loopback only is LATENT.
Compile-only Lua in tests with no request-reachable path is not a finding.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the request passing to the upstream while the authz backend errors or denies), a passing negative control (a healthy authz backend blocks the same request), and signed target-bound proof on the shipped artifact.
