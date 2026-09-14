# Skill: Server-Side Request Forgery and URL-Fetch Abuse

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: http-client, webhook, proxy, pdf, image, url-fetch, cloud-metadata
- **Signals**: requests, httpx, urllib, axios, node-fetch, net/http, resttemplate, okhttp, guzzle, faraday, libcurl, wkhtmltopdf, imagemagick, 169.254.169.254
- **Unique vs**: ai-proxy-ssrf-identity (an AI proxy that lets the caller choose the upstream). This is the general class: any server-side fetch of a URL influenced by request input.

## Doctrine
A server-side fetch influenced by request input is an SSRF lead, not a finding.
Establish whether it crosses an intended destination or network trust boundary;
an intentionally public URL fetch alone does not establish a vulnerability. Possible
impact includes protected internal data or unauthorized service access, which must
be demonstrated with a bounded local-lab oracle and signed target-bound proof.

## Discovery vectors (up to ten)
1. Grep server-side HTTP clients and reverse-trace the URL or host argument to a request source.
2. Find webhook, callback, and notify-URL features that fetch an operator- or user-supplied endpoint.
3. Find import-from-URL, link-preview, avatar/image proxy, and HTML/PDF-to-image renderers.
4. Test the recorded metadata-fetch path against a lab-only metadata emulator; never query real cloud metadata.
5. Check URL scheme handling for `file:`, `gopher:`, `dict:`, and `ftp:` beyond `http` and `https`.
6. Probe allowlist logic for bypasses: DNS rebinding, decimal/hex IPs, `[::]`, `0.0.0.0`, userinfo `@`, trailing-dot hosts.
7. Follow redirects: an allowlisted host that 302s to an internal address (redirect-based SSRF).
8. Look for blind/out-of-band SSRF where only timing or a DNS/HTTP callback confirms reach.
9. Check whether the fetched body or headers are reflected back (full-read vs blind).
10. Trace SSRF-to-more: internal admin APIs, unauthenticated internal services, or a second-stage RCE.

## Cross-language and stack examples
- Python: `requests.get(user_url)`, `httpx`, `urllib.request.urlopen`; a Django link-preview or webhook worker.
- Node: `fetch`/`axios`/`node-fetch`/`got` on a caller URL; an image proxy piping the response.
- Go: `http.Get`/`http.NewRequest` with a header or param host; a `net.Dial` to a supplied address.
- Java: `RestTemplate`/`WebClient`/`URL.openStream`/`OkHttp` on a request-derived URI; SSRF via XXE.
- Ruby/PHP: `Net::HTTP`/`open-uri`/`Faraday`; PHP `file_get_contents`/`curl` on a user URL.
- .NET: `HttpClient`/`WebRequest` on a request-derived URL; an SVG or URL-preview fetch.
- Any: a redirect-following client or a DNS-rebinding bypass of a host allowlist.

## How to validate
In the isolated local lab, point the fetch at a sentinel behind the intended boundary
or a lab-only metadata emulator. The oracle is a forbidden request reaching that
sentinel or returning its synthetic protected value. Negative control: the same
request must be refused when the destination guard is enforced. Never contact real
metadata or external services. Require signed target-bound proof.

## Counterexamples and limits
A strict destination allowlist enforced after DNS resolution, a dedicated egress
proxy with no metadata route, and scheme/host validation refute the lead (LATENT).
An operator-only URL not influenced by request input is NO-BOUNDARY.

Evidence bar: a reachable fetch is a lead, not a finding - confirm an unauthorized boundary crossing with a lab-only sentinel or metadata emulator, a passing negative control under an enforced destination guard, and signed target-bound proof on the shipped artifact.
