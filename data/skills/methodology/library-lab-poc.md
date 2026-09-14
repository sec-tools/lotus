# Skill: Library and Native-Protocol Lab PoCs

## Metadata
- **Category**: methodology
- **Language**: ruby python go java c/cpp multi-runtime
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Prove the class with the cheapest faithful harness. Prefer published images and
package installs over multi-hour source builds so the audit is never starved by a
compile. Always emit PROVEN or DISPROVEN; never leave a high-severity lead
untested.

## Frictionless lab
- Package install over source build: `gem build && gem install` then `require`; `pip install`; `npm i`; `go run`; a published container image.
- Prefer README-documented images (an official published image on its default port) over compiling C/C++ toolchains (CMake/Ninja/Bazel) that take hours.
- The native-protocol health gate is a TCP connection, not an HTTP 200.
- For a native admin plane, complete the real handshake, then send one admin command.

## Discovery vectors (up to ten)
1. Read the project README/CONTRIBUTING for the fastest supported run path.
2. Check for an official published image and use it before building from source.
3. Use the language package manager to install just the library under test.
4. Copy the exact client sequence from the project's own tests into the lab (test-oracle-mining).
5. Health-gate native services on TCP/handshake, not HTTP.
6. Keep the harness minimal: one entry, one sink, one oracle, one negative control.
7. Pin the target revision/digest so the receipt is reproducible.
8. Isolate the lab (no network egress except to lab-controlled hosts).
9. Emit a PROVEN or DISPROVEN receipt for every high-severity lead.
10. Prefer reversible, benign oracles (a marker file, a printed `uid=`) over destructive actions.

## Cross-language and stack examples
- Ruby gem: a bundler harness calling the vulnerable API on a crafted input.
- Python lib: a `pytest` driver or `python -c` invoking the parser or loader directly.
- Go module: `go test`/`go run` a tiny driver against the vulnerable function.
- Java lib: a JUnit or `jshell` snippet exercising the sink with a gadget input.
- C/C++ library: a libFuzzer or `main` harness linking the library and feeding the crafted buffer.

## How to validate and limits
A green smoke test proves the harness runs, not that a bug exists. Confirmation
requires the oracle firing with a passing negative control and signed target-bound
proof. If the lab cannot be stood up, record inconclusive honestly rather than
inferring impact.
