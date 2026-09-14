# Skill: Mine Integration Tests as Oracles

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: any

## Doctrine
The project's own tests often encode the exact client sequence, fixtures, and
success assertion you need. A test named for anonymous or default access IS the
proof of concept; copy it into the lab instead of reinventing probes.

## Discovery vectors (up to ten)
1. Grep test names for `anonymous`, `default`, `allows`, `bypass`, `insecure`, `no_auth`, `public`, `admin`.
2. Find assertions that a privileged call succeeds without a prior authenticate step.
3. Extract fixtures with empty or default credentials (`IDENTIFIED BY ''`, `password=""`, `token=""`).
4. Reuse test client helpers that build the exact protocol frames or requests.
5. Mine the fuzz corpus and regression inputs for payloads that reach dangerous branches.
6. Read negative tests to learn what the developer believes is forbidden, then test the sibling that lacks one.
7. Use snapshot/golden files to learn expected privileged responses (the oracle body).
8. Follow test setup/teardown to reproduce the vulnerable configuration quickly.
9. Check CI configs for how the service is started with auth off for tests.
10. Diff test expectations against production config to find test-only guarantees that prod lacks.

## Cross-language and stack examples
- xUnit families (JUnit, pytest, RSpec, Go `testing`, Jest, PHPUnit): reuse fixtures, helper clients, and assert helpers verbatim as ready-made oracles.
- Broker/queue tests: a client that connects without `authenticate()` and asserts `result.code == 0` (fail-open oracle).
- Database tests: users created with empty passwords and admin operations expected to succeed (privilege oracle).
- Web/API tests: a client that hits an admin route and asserts `200` with no login step (authz oracle).
- Integration/e2e (Cypress, Playwright, Testcontainers, docker-compose rigs): a full lab already wired with seeded creds and endpoints.
- Fuzz/property tests (libFuzzer, go-fuzz, Hypothesis): existing harnesses that already reach the parser or sink.
- Snapshot/golden files and VCR cassettes: recorded payloads that reveal expected inputs and secret formats.

## How to validate and limits
A passing upstream test is a recipe, not proof about the target: re-run the copied
sequence against the shipped artifact with a negative control (auth enforced) and
require signed target-bound proof. A test that asserts denial is itself a negative
control you can reuse.

Evidence bar: a match here is a lead, not a finding - confirm with a bounded oracle (the repo's own test client observing a protected action succeed on the target without credentials), a passing negative control (the same unauthenticated request is denied when the intended authorization check is enforced, while an authorized request succeeds), and signed target-bound proof on the shipped artifact.
