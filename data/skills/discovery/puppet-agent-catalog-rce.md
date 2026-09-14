# Skill: Config-Management Agent Catalog Deserialization and Execution RCE

## Metadata
- **Category**: discovery
- **Language**: ruby puppet multi-agent
- **Stacks**: puppet, chef, salt, ansible, config-management
- **Signals**: psych, pson, create_additions, shell_out
- **Unique vs**: ruby-command-injection (generic Kernel.system) and ruby-unsafe-deserialization (Marshal/PDF). This skill is catalog-shaped: full YAML/PSON of facts and catalogs plus execution of interpolated resource parameters plus an over-broad REST allow.

## Doctrine
A configuration-management agent treats the catalog it fetches as trusted code.
Full YAML/PSON loading of a network catalog instantiates arbitrary objects; an
execution helper that interpolates resource parameters is RCE as the agent user
(often root); an over-broad REST allow makes it pre-auth.

## Discovery vectors (up to ten)
1. Grep full-load deserializers on network data: `YAML.load`/`Psych.load`/`unsafe_load`, `PSON.parse`, `create_additions: true`.
2. Trace catalog/fact ingestion from the wire into those loaders.
3. Grep execution helpers that interpolate parameters into a command (`Execution.execute`, `shell_out`, backticks).
4. Inspect the agent's REST/auth config for wildcard allows (`allow '*'`) versus a named-cert allowlist.
5. Check whether the agent runs as root and what the interpolated command touches.
6. Follow report/inventory upload paths that also deserialize.
7. Look for a fetch-then-apply flow where a spoofed master or MITM supplies the catalog.
8. Compare safe vs unsafe loader usage across the codebase (safe_load elsewhere but not here).
9. Mine tests/fixtures for catalog payloads to reuse as templates.
10. Check version/CVEs for catalog-handling fixes missing on the pinned build.

## Cross-language and stack examples
- Puppet-style Ruby agent: `YAML.load`/`PSON.parse` of catalogs; `Puppet::Util::Execution.execute` interpolation; `auth.conf` `allow '*'`.
- Chef-style Ruby agent: `shell_out` of interpolated node attributes; unsafe node-data load; an `execute` resource built from attributes.
- Salt (Python): a master/minion accepting unauthenticated commands; templated `cmd.run` from pillar or grains.
- Ansible-adjacent: a playbook templating a shell task from untrusted inventory/vars; a dynamic-inventory script running input.
- MCollective/Bolt: a task or agent action executing an interpolated command from an orchestration request.
- Generic config-management: any agent that fetches a catalog/manifest over the network and full-loads or templates it into execution.
- Safe contrast: a signed catalog with `safe_load` and no attribute interpolation into a shell - the negative control.

## Phase-2 PoC
1. Start the agent-app analog (do not compile the real product).
2. BEFORE: with the enforced analog, a catalog fetch is denied (403).
3. AFTER: with the fail-open analog, the same fetch is 200 and emits `LOTUS_PUPPET_AUTH`.
4. YAML gadget analog: POST a catalog with an object payload; oracle is `uid=` and `PUPPET_YAML_RCE`.
5. Measure status_before vs status_after; uid_after true, uid_before false. Require signed target-bound proof.

## Counterexamples and limits
`safe_load`/`safe_load` with permitted classes, execution of a constant argv, and a
REST allow limited to a named certificate are LATENT.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted catalog/fact input causing an unintended privileged action or code execution, observed with a harmless lab marker), a passing negative control (a safe loader with permitted classes rejects the same payload), and signed target-bound proof on the shipped artifact.
