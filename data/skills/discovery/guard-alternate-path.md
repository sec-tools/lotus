# Skill: Guard Alternate Path (the #1 real finding shape)

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any
- **Source**: Skill 49

## Doctrine
The alternate path skips the guard. This is the shape of almost every real authz
and logic finding: the guard exists and is correct on the path you read first, and
a sibling path reaches the same sink without it. Completeness is the whole game.

## Method
1. Inventory every guard: auth middleware, `authorize!`, `@PreAuthorize`, `Gate::allows`, policy check, feature flag, tenant scope.
2. Inventory every path to each sensitive sink (write, delete, privilege change, money move, data read).
3. Classify each path GUARDED or UNGUARDED and record why.
4. Explicit skips (`skip_before_action`, `@public`, `PermitAll`, `csrf_exempt`, `AllowAnonymous`) are P0 leads.

## Discovery vectors (up to ten)
1. Diff sibling routes/controllers: same resource, one guarded, one not.
2. Grep the explicit-skip annotations and list every route they cover.
3. Compare HTTP verbs on one resource: GET guarded, POST/PUT/DELETE/PATCH forgotten.
4. Find second entry points to the same action: GraphQL resolver, gRPC method, CLI, cron, admin panel, batch import, webhook.
5. Check object-level vs route-level authz: login is required but ownership/tenant is not (IDOR; see django-object-authz-gap).
6. Look for guards attached by convention (naming, base class, decorator) that a new handler forgot to inherit.
7. Mine commits that added a guard and check whether every peer call site received the same fix (silent-fix siblings).
8. Inspect middleware ordering: a guard registered after the handler, or short-circuited by an earlier return/redirect.
9. Trace wildcard/catch-all routes and default handlers that bypass per-route guards.
10. Read negative tests: a `test_*_forbidden` that exists for one path and is missing for its sibling.

## Cross-language and stack examples
- Rails: `before_action :authorize` plus a controller that calls `skip_before_action`; `send`-based dispatch.
- Django/DRF: `permission_classes` on one view, `AllowAny` or a raw function view on the sibling.
- Spring: `@PreAuthorize` on the service but a controller that calls the repository directly.
- Express/Koa: auth middleware mounted on `/api` but a route registered on `/internal` or before the middleware.
- Go net/http: `authMiddleware(mux)` wrapping most routes while one handler is registered on the bare mux.
- ASP.NET: `[Authorize]` on the controller but `[AllowAnonymous]` on an action; minimal-API endpoint missing the filter.

## How to validate
Pick one UNGUARDED path to a real sink. In an authorized lab, exercise it without
credentials (or with a lower-privilege identity) and confirm the state change,
then run the guarded sibling as the negative control (it must be denied). Require
signed target-bound proof.

## Counterexamples and limits
If a second guard (gateway, service-layer policy, database RLS) enforces the same
rule on the "unguarded" path, it is defense-in-depth, not a bypass (LATENT).
Completeness is the exit criterion: every reachable path to every sink classified.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the guarded action succeeding when reached through the unguarded sibling route), a passing negative control (the primary guarded route still returns 401/403), and signed target-bound proof on the shipped artifact.
