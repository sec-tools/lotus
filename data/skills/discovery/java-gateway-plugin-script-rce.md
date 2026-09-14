# Skill: JVM Gateway Plugin / Expression-Engine RCE

## Metadata
- **Category**: discovery
- **Language**: java kotlin shenyu spring multi-engine
- **Stacks**: shenyu, spring, spring-cloud-gateway, struts, groovy, spel, ognl, mvel, jexl, freemarker, velocity, hessian, fastjson
- **Signals**: groovyshell, spelexpressionparser, hessian2input, fastjson, ognl, scriptenginemanager
- **Unique vs**: plugin-dlopen-rce (native .so load) and plugin-script-engine-rce (the generic bug class). This skill is JVM gateways storing handle/config that is later evaluated as an expression or script.

## Doctrine
API gateways and rule engines store plugin handle JSON or rules that are later
evaluated as Groovy, SpEL, OGNL, MVEL, JEXL, or JSR-223 scripts. An admin write, or
an unauthenticated selector/rule API, becomes RCE without a classic gadget. Hessian
and Fastjson autoType on the same control plane are the sibling deserialization
class.

## Discovery vectors (up to ten)
1. Grep script/expression evaluators: `GroovyShell`/`GroovyClassLoader`, `SpelExpressionParser.parseExpression`, `Ognl.getValue`, `MVEL.eval`, `ScriptEngineManager`.
2. Trace whether the expression string comes from stored config, an admin API, or a request field.
3. Find the write path: an admin or unauthenticated selector/rule/plugin endpoint that persists the script.
4. Check anonymous-access annotations and sign-skip flags on those endpoints.
5. Grep deserialization siblings: `Hessian2Input`, `HessianProxyFactory`, Fastjson `autoTypeSupport`, `ObjectInputStream`.
6. Inspect template engines used for responses (Freemarker, Velocity, Thymeleaf) for SSTI.
7. Look for OGNL in web frameworks (Struts-style) reachable from parameters.
8. Check whether evaluated scripts run with the gateway's privileges and network position.
9. Mine tests that compile/evaluate scripts to learn the exact API shape.
10. Verify version and known CVEs of the gateway and expression libraries.

## Cross-language and stack examples
- Apache ShenYu / Spring Cloud Gateway: plugin handle JSON evaluated as Groovy/SpEL.
- Struts-style OGNL from a request parameter.
- Freemarker/Velocity SSTI in an admin-editable template.
- Fastjson/Hessian autoType on a rule-sync channel.
- Node: a rule engine running `eval`/`new Function`/`vm` on an admin-supplied expression.
- Python: a plugin or rule path calling `eval`/`exec` on stored rule text.

## Phase-2 PoC
1. PUT/POST a plugin script or rule that runs `Runtime.getRuntime().exec("id")` (or the analog `/plugin/run`).
2. Send a request that hits the selector/rule so the script evaluates.
3. Oracle: `uid=` or `GROOVY_RCE` in the response or lab log.
4. BEFORE: a script returning a constant produces no `uid=`. AFTER: the payload produces `uid=`.
5. Deserialization sibling: a canary file or `uid=` from a benign gadget analog; DISPROVE on 400/deny. Require signed target-bound proof.

## Counterexamples and limits
Compile-only expressions in unit tests with no admin/runtime path are not findings.
A sandboxed engine with a strict allowlist, or an admin API behind enforced auth
with no privilege escalation, is LATENT.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-controlled Groovy/SpEL/OGNL expression crossing the intended boundary and causing unauthorized code execution, observed with a harmless lab marker), a passing negative control (a non-expression value is treated as inert data), and signed target-bound proof on the shipped artifact.
