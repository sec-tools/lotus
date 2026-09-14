# Skill: Unauthenticated Debug / Control UI

## Metadata
- **Category**: discovery
- **Language**: ruby python java multi-framework
- **Stacks**: sinatra, flask, werkzeug, spring-actuator, rails, thin, rack
- **Signals**: mailcatcher, rack-auth, actuator, web-console, sidekiq
- **Unique vs**: jwt-dashboard-auth-bypass (JWT/HS256) and fail-open-native-auth (native brokers). This skill is a debug/mail/admin UI with no authentication layer, often bound to all interfaces.

## Doctrine
Catch-all debug, mail, and control UIs frequently ship with no authentication. "No
password" is not a feature; a GET that dumps captured messages, environment, or
internal state is pre-auth data exfiltration, and some expose code execution.

## Discovery vectors (up to ten)
1. Find debug/admin apps with no auth layer (no basic-auth wrapper, no login filter, no middleware).
2. Check the bind address (all interfaces vs loopback) against intended reachability.
3. Grep for routes that dump captured data, config, env, or internal objects.
4. Look for framework debug consoles that allow code execution (interactive evaluator, PIN-gated debugger).
5. Inspect actuator/management endpoints exposed without auth.
6. Check search/observability dashboards left open (cluster, logs, metrics with query power).
7. Find mail/webhook capture tools that store and serve message bodies.
8. Verify whether a documented "dev only" tool is actually running in the deployment.
9. Look for a reverse proxy that forwards the debug UI publicly.
10. Confirm sensitive content (password-reset mail, tokens, secrets) is retrievable.

## Cross-language and stack examples
- Ruby (Sinatra/Thin): a mail-catcher UI on all interfaces with no Rack auth serving `/messages`.
- Python (Flask/Werkzeug): the interactive debugger enabled in production; an unauthenticated admin blueprint.
- Java (Spring Boot): actuator `/env`, `/heapdump`, `/jolokia` exposed without security.
- Rails: `web-console` or `/rails/info` reachable; an open Sidekiq web UI.
- Node: an Express admin router or a Bull/Arena queue dashboard mounted without auth.
- Go: a `net/http/pprof` or an admin mux registered outside the auth middleware.
- Search/infra: an open cluster, log, or metrics dashboard with query and mutate power.

## Phase-2 PoC
BEFORE: with the enforced analog (auth on), a GET of the control route is 401.
AFTER: with auth off, the same GET is 200 and emits `LOTUS_MAIL_UNAUTH` (or the
relevant marker) plus the sensitive body. The oracle is the marker plus real
content, not merely HTTP 200. Require signed target-bound proof.

## Counterexamples and limits
A UI bound to loopback and wrapped in basic auth, or a debug console disabled in
the deployment build, is LATENT. A reachable route returning only static, non-
sensitive content is not impact.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the debug/control UI performing a privileged action for an unauthorized caller), a passing negative control (the same action requires credentials when auth is enabled), and signed target-bound proof on the shipped artifact.
