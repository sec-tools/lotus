# Skill: Server-Side Rendering Exec / Prerender RCE

## Metadata
- **Category**: discovery
- **Language**: ruby rails node python multi-stack
- **Stacks**: rails, react_on_rails, node, ssr, next, nuxt
- **Signals**: execjs, open3, prerender, mini_racer, server_render
- **Unique vs**: ruby-command-injection (generic shell_out). This skill is server-side JS execution (ExecJS / a spawned Node) at request time with attacker-influenced props, bundle path, or argv.

## Doctrine
Prerendering executes JavaScript on the server during the HTTP request. If props,
the bundle path, or the process argv are influenced by the client, that is RCE in
the server's user, not XSS.

## Discovery vectors (up to ten)
1. Grep server-render sinks: `ExecJS.eval`/`compile`/`exec`, a server-rendering helper, `Open3`/`spawn` of `node`.
2. Trace props passed into the render call back to request data.
3. Check whether the bundle path or node argv can be influenced by the client.
4. Look for `prerender: true` / `server_render` flags on components that take user input.
5. Inspect any place the server evaluates a JS/template string built from input (SSTI-adjacent).
6. Follow file paths for the bundle that a request could redirect (upload, param, header).
7. Check subprocess construction for shell interpretation of interpolated values.
8. Review caching of rendered output that might execute stored attacker props later.
9. Mine tests for the render API and payload shape.
10. Verify the render runtime's privileges and egress.

## Cross-language and stack examples
- Rails + react_on_rails: `ExecJS`/`Open3` running a Node bundle with client props (`prerender: true`).
- Node SSR (Next/Nuxt/custom): `vm`/`eval` of a template or a spawned render worker fed user data.
- Python: a view that spawns `node` to render, interpolating request fields into argv.
- Java: Nashorn/GraalJS server-side rendering evaluating a template built from request fields.
- PHP: V8Js or a spawned `node` renderer interpolating user input into the script.
- .NET: a Node-services JS SSR bridge (`INodeServices`) evaluating a template built from input.
- Any: a headless-browser or `wkhtmltopdf` render fed user HTML/JS (SSR-adjacent to XSS and SSRF).

## Phase-2 PoC
BEFORE: POST a benign script or props (`1+1`) and confirm no `uid=`.
AFTER: props that reach `child_process.execSync('id')` (or the analog) produce
`uid=` and `ROR_EXECJS`. Negative control: a static, integrity-checked bundle with
no user props must not execute. Require signed target-bound proof.

## Counterexamples and limits
Rendering a static, integrity-hashed bundle with no user-controlled props, path, or
argv is LATENT. Output that is escaped and never executed server-side is XSS at
most, not RCE.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (injected JavaScript executing in the SSR/render worker), a passing negative control (static props render without evaluating the payload), and signed target-bound proof on the shipped artifact.
