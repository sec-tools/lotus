# Skill: Ruby YAML/PSON Catalog Deserialization (bug class)

## Metadata
- **Category**: bug-classes
- **Language**: ruby puppet
- **Stacks**: puppet
- **Signals**: psych, pson, create_additions

## Doctrine
Distinct from Marshal-of-parser-state: this class is YAML/PSON catalogs and facts
loaded from the wire, where a full loader instantiates arbitrary Ruby objects. The
loader choice (full vs safe) is the whole bug.

## Unique vs
`ruby-unsafe-deserialization.md` covers `Marshal.load` of parser hashes (e.g. PDF).
This class is YAML/PSON catalogs and facts: object tags, `json_class`,
`create_additions: true`, and full loads of a catalog from the network.

## Sinks
`YAML.load` / `Psych.load` / `Psych.unsafe_load`, `PSON.parse`,
`JSON.load(create_additions: true)`, and `Marshal.load` of reports (adjacent).

## Discovery vectors (up to ten)
1. Grep each full-load sink and confirm the bytes come from the network (catalog/fact/report).
2. Distinguish `safe_load`/permitted-classes from full loads.
3. Grep `create_additions: true` and object-tag handling.
4. Trace fact submission and catalog fetch into the loader.
5. Check report/inventory upload paths for adjacent Marshal loads.
6. Assess gadget availability in the loaded gem set.
7. Look for a spoofable master or MITM that supplies the catalog.
8. Compare safe usage elsewhere against the unsafe call here (silent-fix sibling).
9. Mine tests/fixtures for catalog payloads.
10. Review version/CVEs for loader-hardening fixes.

## Cross-language and stack examples
- Puppet-style: `YAML.load`/`PSON.parse` of a network catalog or facts instantiating a Ruby object.
- `Psych.unsafe_load`/`YAML.load` of an uploaded document or report on older defaults.
- `JSON.load(create_additions: true)` reconstructing tagged objects from the wire.
- Chef/Salt-adjacent Ruby tooling: node data or report payloads full-loaded server-side.
- Any Ruby service accepting YAML/PSON uploads and full-loading them (config import, backup restore).
- Safe contrast: `YAML.safe_load(..., permitted_classes: [...])` or SafeYAML - the negative control.

## How to validate
Deliver a benign object payload to the loader in an authorized lab; oracle is
`uid=` and `PUPPET_YAML_RCE` or a lab-only side effect. Negative control: a
safe-loader with permitted classes must reject the same payload. Require signed
target-bound proof.

## Counterexamples and limits
`YAML.safe_load` with permitted classes, or loading only trusted internal data,
refutes the RCE claim (LATENT).

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted YAML/PSON input causing an unintended privileged action or code execution, observed with a harmless lab marker), a passing negative control (safe_load with permitted classes rejects the same catalog), and signed target-bound proof on the shipped artifact.
