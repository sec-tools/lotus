# Skill: Plugin / Script-Engine RCE (embedded interpreters)

## Metadata
- **Category**: bug-classes
- **Language**: java go lua python multi-runtime
- **Stacks**: groovy, spel, ognl, lua, plugin
- **Signals**: groovyshell, spelexpressionparser, plugin.open, scriptenginemanager

## Doctrine
Embedding an interpreter or dynamic loader turns configuration into code. If plugin
handle JSON, a selector predicate, a request header, or a config path reaches an
evaluator or module loader, that is remote code execution, not a feature.

## Crown jewels
- `GroovyShell.evaluate` / `GroovyClassLoader` of plugin handle JSON.
- `SpelExpressionParser.parseExpression` / OGNL / MVEL / JEXL of selector predicates.
- Lua `os.execute` / `io.popen` of a request-derived value in a proxy filter.
- Go `plugin.Open` of a config or HTTP-supplied path.
- Python `eval`/`exec`/`importlib` of a request or config value; Node `vm`/`require(var)`.

## Discovery vectors (up to ten)
1. Grep each evaluator/loader sink and trace its input to config, admin API, or request.
2. Separate a sandboxed engine (allowlisted) from an unsandboxed one.
3. Find the write path that persists the script (admin/unauthenticated API, config file, DB row).
4. Check the trigger path that later evaluates it (a request hitting the selector/rule).
5. Confirm the engine runs with the host's privileges and network position.
6. Look for autoType/gadget deserialization on the same control plane.
7. Inspect template engines for SSTI adjacent to the plugin system.
8. Check integrity/signature verification before load or evaluation.
9. Mine tests for the exact evaluate/compile API and payload shape.
10. Review versions and known CVEs of the embedded engine.

## Cross-language and stack examples
- Java: ShenYu/Spring Cloud Gateway Groovy or SpEL; Struts OGNL; Nashorn/GraalJS/JSR-223 `ScriptEngineManager`; MVEL/JEXL.
- Go: `plugin.Open` from an admin path; a rule engine using `text/template` or an embedded interpreter (yaegi, expr, gopher-lua).
- Lua: an Envoy/OpenResty filter calling `os.execute`/`loadstring` on a header or rule.
- Python: `eval`/`exec`/`compile` behind a rule or automation engine; a plugin importing a request-named module.
- Node/JS: `vm`/`vm2` escapes, `new Function`, `eval` of a stored rule expression.
- .NET: `CSharpScript`/Roslyn eval, `DataTable.Compute`, or a Razor template from input.
- Ruby: `eval`/`instance_eval` or ERB rendering of a stored plugin expression.

## How to validate
In an authorized lab, store a benign script that runs `id` and trigger it; oracle is
`uid=` in the response or lab log. Negative control: a script that returns a
constant, and a sandboxed/allowlisted configuration, must not execute. Do not
report "an engine is present" without a trigger that prints the oracle. Require
signed target-bound proof.

## Counterexamples and limits
A strict sandbox/allowlist, admin-only reach with no escalation, or compile-only
test usage refutes the RCE claim (LATENT).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-controlled rule/plugin expression crossing the intended boundary and causing unauthorized code execution, observed with a harmless lab marker), a passing negative control (a plain-data rule is not evaluated), and signed target-bound proof on the shipped artifact.
