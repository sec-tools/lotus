# Skill: Object-Level Authorization Sibling Skip (IDOR)

## Metadata
- **Category**: discovery
- **Language**: python django multi-framework
- **Stacks**: django, drf, rails, express, spring, flask
- **Signals**: has_message_access, csrf_exempt, urlopen, pickle.loads, objects.get
- **Unique vs**: guard-alternate-path (generic decorator skip). This skill is a view that loads an object by id but skips the per-object access helper, plus webhook csrf-exempt and link-preview SSRF neighbors.

## Doctrine
Real authorization is often per-object, not merely login-required. A sibling view
that accepts an object id and loads it without the ownership/access helper is an
IDOR of private data. Link-preview fetchers are SSRF; csrf-exempt webhooks with
deserialization are RCE/authz.

## Discovery vectors (up to ten)
1. Grep the per-object access helper (an ownership/tenant check) and list views that load the object without it.
2. Grep object loads by id (`.objects.get`/`.filter`, `find(params[:id])`, `findById`) near request handlers.
3. Test horizontal IDOR: request another user's object id with your session.
4. Test vertical gaps: a role check present, an object-scope check absent.
5. Find `csrf_exempt`/`AllowAny` webhook endpoints and what they deserialize.
6. Grep link/preview fetchers (`urlopen(url)`, an image/preview fetch) for SSRF.
7. Check batch/list endpoints that leak objects across tenants without scoping.
8. Inspect GraphQL resolvers and API viewsets for missing object-level permissions.
9. Compare sibling views: one calls the access helper in the same function, one does not.
10. Mine tests for a `test_*_forbidden` that exists for one view and is missing for its sibling.

## Cross-language and stack examples
- Django/DRF: `Model.objects.get(id)` without `has_object_permission`/owner filter; `get_object_or_404(Model, pk=...)` not scoped to `request.user`.
- Rails: `Model.find(params[:id])` not scoped to `current_user`; a Pundit/CanCan policy missing on one action.
- Node/Express: `Model.findById(req.params.id)` without an ownership check; a Prisma/Sequelize query not filtered by tenant.
- Java/Spring: a repository `findById` in a controller behind only a role check, not a per-object owner check.
- Go: a handler loading a record by path id and trusting context identity without scoping to the resource.
- PHP/Laravel: `Model::find($id)` without a policy/gate; a route-model binding not constrained to the user.
- Any: sequential or guessable ids (IDOR) plus mass-assignment updating another tenant's row.

## Phase-2 PoC
BEFORE: with the enforced analog, GET another user's object as a different user is
denied (403). AFTER: with the gap, the same GET is 200 and returns the private body
(`LOTUS_IDOR`). Link preview: a request for an internal/metadata URL returns
`LOTUS_SSRF`. Require signed target-bound proof.

## Counterexamples and limits
If every object fetch calls the access helper in the same function, or a second
layer enforces tenancy (DB RLS), the lead is LATENT. A preview fetcher with an
allowlist refutes the SSRF.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (another tenant's object returned or mutated without the ownership check), a passing negative control (the access helper denies the cross-tenant id), and signed target-bound proof on the shipped artifact.
