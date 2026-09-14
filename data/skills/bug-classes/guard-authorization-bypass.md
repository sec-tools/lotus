# Skill: Guard / Authorization Bypass Classes

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: any

## Doctrine
Authorization fails at the edges: a sibling that skips the guard, an object
reference without an ownership check, a guard that protects many sinks but not one,
or a long-lived session that never re-validates. Enumerate the classes so no edge
is missed.

## Patterns
1. Missing middleware/decorator on a sibling route.
2. Explicit skip: `skip_before_action`, `@public`, `PermitAll`, `AllowAnonymous`, `csrf_exempt`.
3. IDOR: object reference used without an ownership or tenant check.
4. Keystone-guard dominance: one guard protects many sinks and a new sink forgot it.
5. Lifecycle/revocation: long-lived channel/token never re-checks authorization.
6. Mass assignment / over-posting into privileged fields.
7. Confused deputy: a trusted internal caller relays an untrusted request unchecked.
8. Vertical vs horizontal: role check present, tenant/owner check absent (or vice versa).

## Discovery vectors (up to ten)
1. Inventory guards and sinks separately, then compute the unguarded intersection.
2. Grep explicit-skip annotations and list every route they cover.
3. Test object access with another user's id (horizontal IDOR) and with a lower role (vertical).
4. Compare all HTTP verbs on one resource for verb-specific gaps.
5. Enumerate alternate entry points (GraphQL, gRPC, CLI, webhook, batch) to the same action.
6. Check mass-assignment allowlists on model binding for privileged fields.
7. Inspect internal service-to-service calls that forward user intent without re-authorizing.
8. Review session/token revocation and re-validation on privilege-relevant actions.
9. Mine commits that added an ownership check and look for peer call sites without it.
10. Read negative authz tests and note which sibling paths lack one.

## Cross-language and stack examples
- Rails: `before_action`/`skip_before_action`, `params.permit` gaps, `find(params[:id])` without scoping to `current_user`.
- Django/DRF: `permission_classes`, object-level `has_object_permission` missing, `AllowAny`.
- Spring: `@PreAuthorize`/`@PostAuthorize`, method-security not applied to a controller-direct repo call.
- Express/NestJS: guards/middleware order, `req.user` trusted without a per-object check.
- Go: handler-level checks vs a bare mux route; context identity not scoped to the resource.
- PHP/Laravel: a route without `middleware('auth')` or a `Gate`/policy check missing on one action.
- ASP.NET: `[Authorize]` on the controller but `[AllowAnonymous]` on an action, or a minimal-API endpoint missing the filter.

## How to validate and limits
Exercise the unguarded path with the wrong identity in an authorized lab and
confirm the state change; the guarded sibling is the negative control. A
second-layer enforcement (gateway, DB RLS) makes it defense-in-depth (LATENT).
Require signed target-bound proof.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the protected action succeeding through the missing-check path), a passing negative control (the properly-scoped path denies it), and signed target-bound proof on the shipped artifact.
