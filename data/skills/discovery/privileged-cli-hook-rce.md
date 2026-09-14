# Skill: Privileged Hook / Lifecycle-Script RCE (Certbot class)

## Metadata
- **Category**: discovery
- **Language**: python go multi-runtime
- **Stacks**: certbot, acme, systemd, cron, git-hooks, ci
- **Signals**: pre_hook, post_hook, deploy_hook, renew_hook, yaml.load, chmod
- **Unique vs**: injection-by-language os.system. This skill is a privileged (often root) tool that runs deploy/pre/post/renew hooks, loads config unsafely, or loosens permissions on secrets.

## Doctrine
Tools that run hooks as root after a privileged operation are RCE if the hook path
or its contents are writable by a lower-privilege user. Unsafe config loading is
deserialization RCE; over-permissive modes on private keys are key theft.

## Discovery vectors (up to ten)
1. Grep hook runners: `pre_hook`/`post_hook`/`deploy_hook`/`renew_hook`, lifecycle scripts run by a privileged process.
2. Check the ownership and writability of hook paths and hook directories.
3. Grep unsafe config loaders (`yaml.load` without SafeLoader) on the tool's config.
4. Grep `subprocess`/`os.system` that runs a hook value or an interpolated path.
5. Grep permission changes on secrets (`chmod 0777`/`0666` on a private key).
6. Follow other privileged lifecycle runners: git hooks, systemd units, cron entries, package post-install scripts, CI runners.
7. Check whether a lower-privilege user can influence the hook path via config, env, or a writable file.
8. Inspect PATH and environment inheritance in the privileged context.
9. Look for symlink/TOCTOU on files the privileged tool writes or reads.
10. Review setuid/sudo wrappers that pass through user-controlled arguments.

## Cross-language and stack examples
- Certbot-class Python: root-run `deploy_hook`; `yaml.load` of `cli.ini`; `chmod 0777` on `privkey.pem`.
- Git: a repository-supplied hook executed by a privileged automation user.
- systemd/cron/package managers: a post-install or unit script whose command is attacker-influenced.
- CI runners: a pipeline step that runs a repo-supplied script as a privileged agent.
- Node: a `postinstall` or lifecycle script from a dependency run by a privileged CI or deploy user.
- Ruby: a gem native-extension or Rake hook executed during a privileged install.

## Phase-2 PoC
BEFORE: invoke the hook path with a benign value (`true`) and confirm no `uid=`.
AFTER: a value of `id` (or a writable hook that runs `id`) produces `uid=` and
`CERTBOT_HOOK`. Negative control: a root-owned hook directory with a SafeLoader and
`0600` keys must not execute attacker content. Require signed target-bound proof.

## Counterexamples and limits
Hooks loaded only from a root-owned path, SafeLoader config parsing, and `0600`
key modes refute the RCE/theft claims (LATENT/PRECONDITIONED).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (an attacker-influenced hook command running as the privileged user), a passing negative control (a pinned or validated hook path runs nothing extra), and signed target-bound proof on the shipped artifact.
