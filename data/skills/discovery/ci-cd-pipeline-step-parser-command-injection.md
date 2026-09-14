# Skill: CI/CD Pipeline and Step-Parser Command Injection

## Metadata
- **Category**: discovery
- **Language**: multi-language yaml
- **Stacks**: github-actions, gitlab-ci, jenkins, drone, tekton, argo, circleci, ci
- **Signals**: .github/workflows, .gitlab-ci.yml, jenkinsfile, azure-pipelines.yml
- **Scope**: build runners and CI services; a concatenation is a lead, not a finding

## Doctrine
CI systems interpolate untrusted fields (branch names, PR titles, commit messages,
webhook payloads, config values) into shell strings, process arguments, container
commands, and template renderers. A concatenation is a lead; require a signed
target-bound receipt showing the default trust-boundary crossing before calling it
a finding.

## Discovery vectors (up to ten)
1. Grep where pipeline/step definitions are parsed and fields are interpolated into a command.
2. Identify untrusted inputs: branch/tag/PR title, commit message, author, webhook body, external config.
3. Grep expression contexts injected into `run:`/script blocks (e.g. a templating expression placed into a shell line).
4. Trace fields into container `docker run`/args, `exec`, and template renderers.
5. Check whether PR-triggered pipelines run with write tokens or on privileged runners.
6. Look for `eval`/shell of a config value in the runner itself.
7. Inspect matrix/parameter expansion that concatenates user values into commands.
8. Find plugin/step marketplaces where a step evaluates its inputs.
9. Check artifact/cache keys built from untrusted fields reaching a shell.
10. Review self-hosted runner isolation and secret exposure to injected steps.

## Cross-language and stack examples
- GitHub Actions: an expression interpolating `github.event.*` (PR title/branch) directly into a `run:` shell step.
- GitLab CI: a `script:` line concatenating `CI_COMMIT_*` or a webhook variable.
- Jenkins: a Groovy pipeline building a `sh` string from a build parameter.
- Drone/Tekton/Argo: a step template rendering an untrusted field into args.
- C/C++ build runners: a step parser interpolating configuration into compiler flags or process arguments.
- CircleCI/Azure Pipelines: an untrusted PR field interpolated into a `run`/`bash` step.
- Bitbucket/Buildkite: a pipeline step rendering a webhook variable into a shell command.

## How to validate
In an authorized lab, supply an untrusted field whose benign marker (a lab-only
`echo`/sentinel) only appears if a shell interpreted it; the negative control is
the same field passed as a quoted argument or through an allowlist, which must not
execute. Require signed target-bound proof; prefer `uid=` from a harmless `id`
where safe.

## Counterexamples and limits
Quoted argv, an input allowlist, and untrusted fields never reaching a shell refute
the injection. A pipeline that only trusted maintainers can trigger is a reduced
boundary; classify accordingly rather than as pre-auth.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an interpolated untrusted field executing in the runner shell (a marker)), a passing negative control (a quoted or parameterized field is treated as literal), and signed target-bound proof on the shipped artifact.
