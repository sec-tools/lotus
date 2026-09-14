# Skill: Cross-Site Scripting and Output Encoding (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: html, templating, react, vue, angular, jinja2, erb, thymeleaf
- **Signals**: innerhtml, dangerouslysetinnerhtml, v-html, mark_safe, html_safe, bypasssecuritytrust, document.write, insertadjacenthtml
- **Unique vs**: injection-by-language (the umbrella). This is the deep web-XSS lens: contexts, framework escape opt-outs, DOM sinks, and sanitizer bypass.

## Doctrine
XSS is output-encoding failure: untrusted data reaches an HTML, JS, attribute, or URL
context without context-correct escaping. Reflected and stored variants execute
server-rendered payloads; DOM XSS executes purely client-side. The context (HTML body
vs attribute vs script vs URL) decides the required encoding and the bypass.

## Discovery vectors (up to ten)
1. Inventory sinks: raw HTML emission, `innerHTML`, `document.write`, `insertAdjacentHTML`, framework raw-output directives.
2. Grep template auto-escape opt-outs: Jinja2 `safe` filter, Django `mark_safe`, Rails `html_safe`/`raw`, ERB unescaped output.
3. Find framework-specific bypasses: React `dangerouslySetInnerHTML`, Vue `v-html`, Angular bypassSecurityTrust APIs.
4. Trace stored inputs (names, comments, filenames) rendered later in a different page (stored XSS).
5. Trace reflected inputs (search, error messages, headers) echoed into the response.
6. Map DOM sources (`location`, `document.referrer`, `postMessage`) to client sinks (DOM XSS).
7. Check attribute and URL contexts: `href`/`src` accepting a `javascript:` URL and event-handler attributes.
8. Check JSON or JS embedding where an unescaped closing script tag or data breaks out of a script block.
9. Assess sanitizer correctness and mutation XSS that survives a DOMPurify-style clean.
10. Evaluate CSP as mitigation and look for bypasses (unsafe-inline, JSONP, permissive host allowlists).

## Cross-language and stack examples
- Python/Django/Jinja2: `mark_safe` or the `safe` filter on user data; `format_html` misuse.
- Node/React: `dangerouslySetInnerHTML`, an `href` set to a `javascript:` URL, `document.write` of a param.
- Ruby/Rails: `raw`/`html_safe` in a view; a helper returning unescaped user input.
- Java/Thymeleaf/JSP: unescaped `utext`, unescaped EL, or a JSP scriptlet writing a request parameter.
- PHP: `echo` of a request field into HTML, or a template engine with escaping disabled.
- Go: `template.HTML` or `text/template` emitting unescaped user data into an HTML response.
- Angular/Vue SPA: an `[innerHTML]` or `v-html` binding, or `bypassSecurityTrustHtml` on user data.

## How to validate
Deliver a benign marker payload (a unique DOM change, not a noisy dialog) in the exact
context and confirm attacker-controlled script execution in the affected principal's
origin; HTML breakout alone is insufficient. The oracle is the marker running in a
real browser DOM against the shipped app. Negative control: a correctly encoded input
renders inert. Require signed target-bound proof.

## Counterexamples and limits
Context-correct auto-escaping, a strict CSP that blocks execution, and a vetted
sanitizer refute the lead (LATENT). Reflected input that is HTML-encoded, or a sink in
a non-HTML content type, is a false positive.

Evidence bar: a reachable sink is a lead, not a finding - confirm with a bounded oracle (a benign marker executing in the real DOM in the correct context), a passing negative control (an encoded input stays inert), and signed target-bound proof on the shipped artifact.
