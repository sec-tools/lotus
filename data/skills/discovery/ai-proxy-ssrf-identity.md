# Skill: Reverse-Proxy Caller-Supplied Upstream + Identity Spoofing (AI-proxy class)

## Metadata
- **Category**: discovery
- **Language**: python go node multi-stack
- **Stacks**: llm, proxy, litellm, openai, httpx, requests, gateway
- **Signals**: verify_false, 169.254.169.254, extractall, x-forwarded, base_url
- **Unique vs**: fail-open-native-auth and envoy-ext-authz-fail-open. This skill is a proxy that lets the caller pick the upstream URL and spoof an identity header, often with an optional (bypassable) proxy token.

## Doctrine
A proxy that reads the upstream base URL from the caller is SSRF to internal
services and cloud metadata. Identity headers accepted without a binding token are
authorization bypass. Disabled TLS verification plus a broad bind is credential
theft. Extracting a model/artifact bundle is overwrite/RCE-adjacent.

## Discovery vectors (up to ten)
1. Grep for a base-URL/upstream value read from a request header, query, or body.
2. Grep identity headers trusted without verification (a user-id header, a tenant header).
3. Check whether the proxy token is optional or defaults to empty.
4. Grep `verify=False`/`InsecureSkipVerify`/`rejectUnauthorized:false` on the upstream client.
5. Test SSRF to cloud metadata and to internal-only addresses.
6. Look for archive extraction of a fetched bundle (`extractall`, tar/zip) without path checks.
7. Inspect bind address and whether credentials are reachable off-host.
8. Trace whether the spoofable identity grants access to another tenant's data or quota.
9. Check redirect following that turns an allowlisted host into an internal fetch.
10. Review logging that may capture and expose forwarded secrets.

## Cross-language and stack examples
- Python LLM proxy: a base-URL header reaching `requests`/`httpx` with `verify=False`; a user-id header without a token; `tarfile.extractall` of a model bundle.
- Go proxy: an upstream from a header dialed with `InsecureSkipVerify`; a trusted identity header.
- Node proxy: `fetch(userUpstream)` with `rejectUnauthorized:false`; a spoofable auth header.
- Java/Spring AI gateway: an upstream base-URL from a header dialed with TLS verification disabled; a trusted `X-User` header.
- Ruby proxy: `Net::HTTP` to a caller-supplied upstream; an identity header accepted without a signed token.
- PHP: a proxy using `curl`/`file_get_contents` on a caller upstream; an identity header trusted without a token.
- Any: a model or tool download-URL reaching `tarfile.extractall` or a fetch with TLS verification disabled.

## Phase-2 PoC
BEFORE: with the enforced analog (allowlist + required token), a metadata-URL header
is denied (403). AFTER: with enforcement off, the same request is 200 and returns
`LOTUS_SSRF` (a metadata value). Optional-token analog: a request without
authorization returns `LOTUS_AI_UNAUTH`. Require signed target-bound proof.

## Counterexamples and limits
An upstream host allowlist, a required binding token, TLS verification on, and
extraction with a safe filter refute the claims (LATENT). A configurable upstream
that only an operator sets is NO-BOUNDARY.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the proxy fetching an attacker-chosen upstream or trusting a spoofed identity header), a passing negative control (the same disallowed upstream or forged identity is rejected by the enforced allowlist or identity binding), and signed target-bound proof on the shipped artifact.
