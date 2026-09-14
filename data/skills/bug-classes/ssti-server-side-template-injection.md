# Skill: Server-Side Template Injection (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: jinja2, twig, freemarker, velocity, thymeleaf, handlebars, erb, mustache, spel, ognl
- **Signals**: render_template_string, from_string, freemarker, velocity, spelexpressionparser, ognl, handlebars.compile, lodash.template, text/template
- **Unique vs**: cpp-inja (the C++ Inja engine specifically) and java-gateway-plugin-script-rce (a gateway plugin evaluating scripts). This is the general cross-language SSTI class.

## Doctrine
SSTI is user input becoming template source, not just template data. When a request
field is compiled or evaluated as a template, the engine expression language runs,
often to RCE. The distinction is rendering a fixed template with user data (safe)
versus rendering a user-supplied template string (injectable). Sandbox strength
decides how far it goes.

## Discovery vectors (up to ten)
1. Grep render-from-string APIs and confirm the template text (not just the data) is user-controlled.
2. Identify the engine and its expression language to choose the right polyglot probe.
3. Send a math or marker probe (an arithmetic expression) and check for evaluation in the output.
4. Escalate from expression evaluation to object and attribute access to a runtime call.
5. Check email, report, and notification templates that admins or users can edit.
6. Check filename, subject, and label fields rendered into a template downstream (second-order).
7. Assess sandbox escapes for the specific engine (attribute walks, builtins, class loaders).
8. Distinguish SSTI from reflected XSS by proving server-side evaluation, not client rendering.
9. Look for expression-language contexts (SpEL, OGNL, MVEL) reachable from request data.
10. Trace SSTI-to-file-read or SSRF where full RCE is sandboxed but I/O is reachable.

## Cross-language and stack examples
- Python: Jinja2 `render_template_string(user)`; a Mako or Tornado template from a string; an arithmetic probe yielding its product.
- Java: Freemarker/Velocity/Thymeleaf from user input; SpEL or OGNL evaluation of a request field.
- Node: Handlebars/Pug/EJS compiling a user template; `lodash.template` on input.
- Ruby: ERB/Slim/Liquid rendering a user-supplied template string.
- Go: `text/template` or `html/template` parsed from user input flowing into a sink.
- PHP: Twig/Smarty/Blade compiling a user-supplied template string reaching evaluation.
- .NET: RazorEngine or Scriban compiling a user template; a `DataBinder.Eval`-style expression.

## How to validate
In an authorized lab, submit an arithmetic marker and confirm server-side evaluation,
then a bounded probe of the claimed security boundary. Arithmetic evaluation alone
may be an intended template feature: the oracle must show unauthorized execution,
protected data access, or another demonstrated privilege crossing. Negative control:
the same input used as template data renders literally. Require signed target-bound proof.

## Counterexamples and limits
Rendering user input strictly as data into a fixed, auto-escaping template refutes
SSTI (it may still be XSS). A logic-less engine (Mustache) or a hardened sandbox
limits impact. A reflected template expression that is not evaluated is a lead only.

Evidence bar: an evaluated probe is a lead, not a finding - demonstrate unauthorized execution, protected data access, or a privilege crossing beyond intended template behavior, with a passing negative control and signed target-bound proof on the shipped artifact.
