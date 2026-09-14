# Skill: Sink-First Backward Reachability

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any
- **Source**: Skill 76 / SYSTEM D44

## When it runs
After the initial sink inventory and before spending lab budget on shallow greps.
Working backward from a dangerous sink is higher yield than forward taint from
every input, because sinks are few and attacker inputs are many.

## Method
1. Enumerate crown-jewel sinks: command exec, deserialize, query build, path open, allocation size, privilege grant, template render, redirect/URL fetch.
2. BFS backward through callers up to N hops, recording each frame.
3. Stop when an untrusted source (HTTP body/query/header, CLI arg, env, file, queue message, RPC field) is reached: that is a QUALIFIED lead.
4. Record the full source-to-sink chain as lead_depth evidence with file:line at each hop.

## Discovery vectors (up to ten)
1. Token-grep the sink itself across the repo, then rank hits by proximity to request handlers.
2. Build a call graph (AST or an indexer) and query callers-of-sink transitively.
3. Reverse-taint: treat the sink argument as tainted and propagate backward through assignments and returns.
4. Interprocedural hop across module and package boundaries; sinks are often one wrapper away from the source.
5. Follow framework indirection: route table, dependency injection, event bus, middleware chain, ORM hooks.
6. Cross the process boundary: a sink reached by a queue consumer or RPC server whose producer is attacker-facing.
7. Mine tests that already call the sink with attacker-shaped data (see test-oracle-mining).
8. Check config/DI wiring where the sink argument is bound to a request-scoped value.
9. Diff sibling handlers: if one sanitizes before the sink and a sibling does not, the sibling is the lead.
10. Note reflection/dynamic dispatch (`getattr`, `send`, `Method.invoke`, `reflect`) that hides the edge from static callers.

## Cross-language and stack examples
- Python: `subprocess.run`/`os.system`, `pickle.loads`, `yaml.load`, `eval`, `Template().render`, `open(path)`.
- Node/TS: `child_process.exec`, `vm.runInNewContext`, `res.sendFile`, `db.query(string)`, `JSON` revivers.
- Go: `exec.Command`, `text/template` into shell, `filepath.Join` with `..`, `sql.DB.Query(fmt.Sprintf(...))`.
- Java: `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream.readObject`, `Statement.execute`, `Class.forName`.
- C/C++: `system`, `execve`, `sprintf` size math, `memcpy` length, `dlopen`.
- Ruby: backticks, `Kernel.system`, `Marshal.load`, `constantize`, `render inline:`.

## How to validate
For each P1 sink, either exhibit a concrete source path and prove it with a
bounded oracle plus a negative control, or mark it unreachable-with-evidence
(cite the guard, the constant argument, or the missing edge). Require signed
target-bound proof before a chain becomes a finding.

## Counterexamples and limits
A sink fed only by compile-time constants, a sink behind an enforced allowlist on
every path, or a sink in dead/test code is not reachable. Exit criteria: every P1
sink has either a source path or an evidence-backed unreachable verdict.
