# Skill: Web-Framework Authentication and Dependency Wiring

## Metadata
- **Category**: discovery
- **Language**: python multi-framework
- **Stacks**: fastapi, starlette, flask, django, drf, express, nestjs
- **Signals**: fastapi, starlette, flask, djangorestframework

## Doctrine
Modern frameworks attach authentication and authorization through dependencies,
decorators, and middleware. A missing dependency, an overridden one, or a sibling
route wired without it is a boundary gap. A missing dependency is a lead until an
unsafe operation is reached in the default deployment with a signed receipt.

## Discovery vectors (up to ten)
1. Inventory every route and router include, and the auth dependency each declares.
2. Find routes that omit the auth dependency while siblings require it.
3. Check dependency overrides (test overrides leaking to prod, an override that disables auth).
4. Inspect middleware order and whether it actually covers all mounted routers.
5. Compare authentication on WebSocket and streaming endpoints against HTTP siblings.
6. Check background tasks and startup hooks that perform privileged actions without a caller check.
7. Trace object-level authorization beyond route-level auth (IDOR neighbor).
8. Look for global dependencies assumed but not applied to a sub-app or mounted router.
9. Probe no-credential, invalid-credential, and lower-privilege requests on each route.
10. Review docs/OpenAPI for routes marked public that reach privileged logic.

## Cross-language and stack examples
- FastAPI/Starlette: `Depends(get_current_user)` on most routes but missing on one; an `include_router` without the dependency; `app.dependency_overrides` left set from tests.
- Flask: a blueprint without the `before_request` auth; `@login_required` missing on a sibling; `app.debug=True` in production.
- Django/DRF: `permission_classes` gaps, `AllowAny` on a privileged viewset, `@csrf_exempt` on a mutating view.
- Express/NestJS: a guard/middleware not applied to a mounted sub-router; `app.use(auth)` registered after a route.
- Spring: `@PreAuthorize` on the service but a controller calling the repository directly; a `permitAll` on a broad matcher.
- Go (chi/gin/echo): an auth middleware wrapping one router group while a handler is registered on the bare mux.
- Rails: a controller inheriting a `skip_before_action :authenticate`; a route outside the authenticated namespace.

## How to validate
Send no-credential, invalid-credential, and lower-privilege requests to each
candidate route and confirm a privileged effect on the unprotected one; the
protected sibling is the negative control (must deny). Require signed target-bound
proof and confirm reachability in the default deployment.

## Counterexamples and limits
A global dependency that genuinely covers the router, a second-layer check, or a
route that reaches no privileged operation refutes the lead (LATENT/NO-BOUNDARY).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the unguarded route performing a protected action for an unauthorized caller), a passing negative control (the guarded sibling denies the same unauthorized action), and signed target-bound proof on the shipped artifact.
