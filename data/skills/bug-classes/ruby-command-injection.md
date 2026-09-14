# Skill: Ruby Command and Subprocess Injection

## Metadata
- **Category**: bug-classes
- **Language**: ruby ruby/rails
- **Stacks**: rails, sinatra
- **Signals**: open3, kernel.system, backticks, shellwords

## Doctrine
Ruby offers many ways to reach a shell, and several are easy to miss because they
do not look like `system`. Any of them with an attacker-influenced argument, or
with a shell interpreting the string, is command injection.

## Sinks
`Kernel.system`, `exec`, backticks, `%x{}`, `Open3.*` (popen3/capture2/capture3),
`IO.popen`, `Kernel.open("|...")`, `URI.open` of a pipe/URL, `Process.spawn`,
`` `#{...}` ``, and `Shellwords` misuse.

## Discovery vectors (up to ten)
1. Grep each sink token above and reverse-trace its argument to a request/CLI/env source.
2. Flag string-interpolated commands (`"cmd #{x}"`) passed to any exec sink.
3. Distinguish the safe argv form (`system("cmd", arg)`) from the shell form (`system("cmd #{arg}")`).
4. Check `IO.popen`/`Kernel.open` where a value may begin with `|` (pipe injection).
5. Look for `Open3.capture2/3` and `spawn` with a single interpolated string.
6. Find library wrappers (e.g. a `shell_out` helper) that hide the sink one call away.
7. Check Rake tasks, generators, and deploy scripts that build shell strings from input.
8. Inspect gems known to shell out (image/video/pdf tooling) called with user data.
9. Look for `send`/`public_send` reaching an exec method by dynamic name.
10. Mine tests and fixtures for command strings built from parameters.

## Cross-language and stack examples
- Kernel sinks: `system`, `exec`, backticks, `%x[...]`, `IO.popen`, `Open3.capture2/3`/`popen3`, `Process.spawn` with a shell string.
- Rails: a controller building `system("convert #{params[:file]} out.png")`; `Kernel.spawn` from a job argument.
- Background jobs: `Open3.capture3("git clone #{repo_url}")` in a Sidekiq/Resque worker.
- Gem wrappers: `shell_out!`/`shell_out` (mixlib-shellout), Terrapin/Cocaine line builders interpolating input.
- Indirect: `send`/`public_send`/`constantize` on a user string reaching a command method; `eval`/`instance_eval` of input.
- Safe contrast: argv-array `system("convert", file, "out.png")` and `Shellwords.escape` - the negative control.
- Adjacent languages (same class): Python `subprocess(..., shell=True)`, Node `child_process.exec`, Go `exec.Command("sh","-c",...)`, PHP `shell_exec`.

## How to validate
In an authorized lab, send an input whose benign marker (a lab-only `echo` or a
sentinel file) would only appear if a shell interpreted it; the negative control is
the same input through the argv form, which must not execute. Prefer `uid=` from a
harmless `id` where safe. Require signed target-bound proof.

## Counterexamples and limits
The argv form with a constant command, strict `Shellwords.escape`, or an allowlist
of fixed subcommands refutes the injection. A sink reached only by trusted operator
config is LATENT/NO-BOUNDARY.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (your injected shell command running (a marker in output)), a passing negative control (a list-arg or escaped invocation runs nothing extra), and signed target-bound proof on the shipped artifact.
