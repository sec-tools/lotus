# Skill: Ruby Unsafe Deserialization

## Metadata
- **Category**: bug-classes
- **Language**: ruby ruby/rails
- **Stacks**: rails
- **Signals**: marshal.load, psych, yaml.load, oj

## Doctrine
Ruby object deserialization instantiates arbitrary classes and can reach code
execution through gadget chains. `Marshal.load` and full YAML loading on
attacker-influenced bytes are the crown jewels; safe-loaders close them.

## Sinks
`Marshal.load`/`Marshal.restore`, `YAML.load` (pre-3.1 unsafe default),
`Psych.load`/`Psych.unsafe_load`, `Oj.load` in an unsafe mode, and any wrapper
that clones state via Marshal.

## Discovery vectors (up to ten)
1. Grep the sinks above and trace their argument to a request body, cookie, cache, file, or queue message.
2. Distinguish `YAML.safe_load`/`Psych.safe_load` (safe) from `YAML.load`/`unsafe_load` (unsafe).
3. Find `Marshal.load` used for caching, sessions, or inter-process state on untrusted data.
4. Check libraries that deep-clone via `Marshal.load(Marshal.dump(x))` on parser-built structures.
5. Look for `Oj`/`MessagePack`/`BSON` loads configured to instantiate arbitrary classes.
6. Trace second-order paths: data stored now, deserialized later by a privileged worker.
7. Check whether a permitted-classes allowlist is passed to the loader.
8. Inspect Rails cookie/session stores and cache backends for the serializer in use.
9. Assess gadget availability in the loaded gem set (Rails, common gems ship known chains).
10. Mine tests/fixtures that serialize objects for reuse as payload templates.

## Cross-language and stack examples
- `Marshal.load`/`Marshal.restore` of a cookie, cache value, or uploaded blob (the universal Ruby gadget surface).
- `YAML.load`/`Psych.load`/`Psych.unsafe_load` instantiating `!!ruby/object` tags (pre-safe-load defaults).
- `Oj.load` in object mode (`:object`/`:custom`) on untrusted JSON.
- `JSON.load(create_additions: true)` and `PSON.parse` reconstructing arbitrary classes.
- `PStore`, MessagePack with type extensions, and `MessageVerifier`/`MessageEncryptor` with a leaked or weak secret.
- Library-specific: `PDF::Reader` clone_state via `Marshal.load`; parsers caching state hashes.
- Safe contrast: `YAML.safe_load` with permitted classes, `Oj.load(..., mode: :strict)`, `JSON.parse` - the negative control.

## How to validate
In an authorized lab, deliver a benign gadget payload and confirm execution
(`uid=`) or object instantiation with a lab-only side effect. Negative control: a
safe-loader or permitted-classes allowlist must reject the same payload. Require
signed target-bound proof.

## Counterexamples and limits
`safe_load` with an allowlist, deserialization of only trusted internal data, or
absence of a usable gadget chain refutes the RCE claim. Instantiation without a
demonstrated harmful effect is a lead, not a confirmed critical.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (untrusted serialized input causing unauthorized code execution or a specific unauthorized file operation, observed with a harmless lab marker), a passing negative control (a safe loader or permitted-classes list rejects it), and signed target-bound proof on the shipped artifact.
