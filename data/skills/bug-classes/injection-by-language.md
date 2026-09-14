# Skill: Injection Patterns by Language

## Metadata
- **Category**: bug-classes
- **Language**: multi-language
- **Stacks**: any

## Doctrine
Injection is one class with many dialects: untrusted data reaches an interpreter
(shell, SQL, template, HTML, expression, deserializer) without safe separation of
code and data. Learn the per-language sinks so the same lens transfers everywhere.

## Discovery vectors (up to ten)
1. Grep the language-native command/eval/deserialize sinks (below) and reverse-trace to a source.
2. Find string-built SQL (concatenation, format, f-strings) instead of parameters.
3. Find HTML/JS emitted without context-aware escaping (raw output, `|safe`, `dangerouslySetInnerHTML`).
4. Find template render of a user-controlled template string (SSTI) versus user data into a fixed template.
5. Find expression-language evaluation (SpEL, OGNL, MVEL, JEXL) of request data.
6. Find deserializers reading untrusted bytes (pickle, Marshal, `ObjectInputStream`, unserialize, YAML full-load).
7. Find OS command construction from request fields, including indirect via env or config-that-executes.
8. Find NoSQL/LDAP/XPath query building from raw input.
9. Find header/CRLF and log injection where input reaches protocol or log framing.
10. Check for second-order injection: stored input rendered/executed later in a different context.

## Cross-language and stack examples
- Python: `os.system`, `subprocess(..., shell=True)`, `eval`/`exec`, `pickle.loads`, `yaml.load`, `render_template_string`, SQL via f-strings.
- JavaScript/Node: `child_process.exec`, `eval`, `new Function`, `vm`, deserialize libs, `innerHTML`, prototype pollution via deep merge.
- Ruby: `system`/`exec`/backticks, `eval`, `YAML.load`, `Marshal.load`, `constantize`, `render inline:`, `send`.
- Go: `exec.Command` with a shell, `text/template` into HTML/shell, `fmt.Sprintf` into SQL, `template.HTML` on user data.
- Java: `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream`, `Statement.execute`, `Class.forName`, XXE-enabled parsers.
- PHP: `system`/`exec`/`passthru`, `eval`, `unserialize`, `include` of a user path, string-built `mysqli_query`.

## How to validate and limits
Demonstrate code/data confusion with a bounded oracle (a benign marker command, a
sentinel row/file, a reflected script that runs) and a negative control that a
correctly escaped input produces no effect. Parameterized queries, auto-escaping
templates, safe-loaders, and argv-list exec refute the lead. Require signed
target-bound proof.
