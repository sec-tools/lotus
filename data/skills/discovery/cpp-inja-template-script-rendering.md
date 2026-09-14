# Skill: Template / Expression Rendering to Scripts and Args (SSTI)

## Metadata
- **Category**: discovery
- **Language**: c/cpp multi-language
- **Stacks**: inja, jinja2, freemarker, velocity, thymeleaf, mustache, handlebars, template
- **Signals**: render_template_string, jinja2, freemarker, inja

## Doctrine
Template and expression engines are interpreters. When untrusted step or
configuration fields flow into a rendered script, compiler flag, process argument,
or file path, separate intended template capability from a vulnerability and
require a signed lab oracle for the shipped target.

## Discovery vectors (up to ten)
1. Identify the template/expression engine and whether it can call functions or execute.
2. Distinguish user-data-into-a-fixed-template from a user-controlled-template string (SSTI).
3. Trace rendered output into a shell, compiler invocation, process argv, or file path.
4. Grep engine render/eval calls and their inputs.
5. Check for engine features that expose the host (function calls, includes, filesystem access).
6. Look for path fields rendered into `open`/write locations (traversal).
7. Inspect config-driven rendering where an operator value is actually attacker-influenced.
8. Check sandbox settings and whether they are enabled in the shipped build.
9. Mine tests for template payloads and expected output.
10. Review adjacency to command injection and file write primitives.

## Cross-language and stack examples
- C/C++: an Inja/Mustache-style engine rendering step fields into a script or compiler flags.
- Python: Jinja2 `render_template_string` on user input; Mako/Tornado from a string; format-string expression abuse.
- Java: Freemarker/Velocity/Thymeleaf SSTI; SpEL/OGNL evaluation of a request field.
- Node: Handlebars/Pug/EJS or `lodash.template` compiling a user template; `vm` rendering.
- Go: `text/template`/`html/template` output flowing into a shell or HTML sink.
- Ruby: `ERB.new(user).result`, Slim, or Liquid rendering a user-supplied template string.
- PHP: Twig/Blade/Smarty with a user-controlled template string or expression.

## How to validate
Render a benign probe that would only evaluate if the engine executes it (a marker
computed by the engine, or a lab-only side effect); the negative control is the
same input treated as literal data. For argv/flag/path sinks, use a sentinel file
oracle. Require signed target-bound proof.

## Counterexamples and limits
A sandboxed engine with no host access, user data confined to a fixed template, and
rendered output never reaching a shell/compiler/path refute the lead (LATENT).
