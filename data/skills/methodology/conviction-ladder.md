# Skill: Conviction Ladder and Bridges

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Impact is earned one rung at a time. Name the current rung, name the next, and name
the bridge that gets you there. Skipping rungs is how theoretical criticals get
published.

## Logic-bug ladder
L0 anomaly, L1 check bypass, L2 privilege/state change, L3 account takeover or
critical business impact.

## Memory-bug ladder
R0 crash, R1 controlled crash, R2 read/write primitive, R3 relative overwrite,
R4 controlled pointer/PC, R5 RCE. Walk each rung against the real mitigations
(ASLR, stack cookies, NX, CFI, allocator hardening).

## Bridges (mandatory before a critical score)
- Memory bridge (Skill 87): a crash is not control; show influence over PC or a write-what-where.
- Write bridge (Skill 104): a write is not RCE until a webshell, cron entry, `.so`, key, or config-that-executes is demonstrated.
- Auth bridge: a missing check is not takeover until an action without creds and control with creds are both shown.

## Discovery vectors (up to ten)
1. For each lead, write its current rung and the single next observation needed.
2. Look for the missing bridge explicitly: which artifact would turn write into execute here?
3. Probe mitigations to know which rungs are even reachable on this target build.
4. Search for a second primitive that shortens the ladder (info leak to defeat ASLR).
5. Check whether a state change persists across requests (L2 durability) versus a one-shot effect.
6. Ask whether the privilege gained crosses a tenant/user boundary (L3) or stays within the actor.
7. For crashes, inspect the faulting instruction and whether attacker data reaches a pointer.
8. For writes, enumerate attacker-writable, later-executed locations on the target OS.
9. For logic bugs, chase downstream trust: does the changed state authorize a later action?
10. Record the negative control for each rung: the input that should NOT advance the ladder.

## Cross-language and stack examples
- C/C++ memory: heap overflow (R0) to tcache/allocator control (R2) to hijacked control flow (R4), with proof at each rung.
- Web authz: IDOR read (L1) to cross-tenant write (L2) to account or role takeover (L3).
- Deserialization: gadget presence (L0) to instantiated object (L1) to command execution (L3) via a real chain.
- Injection: reflected marker (L1) to out-of-band callback (L2) to command output on the target (L3).
- SSRF: internal reachability (L1) to metadata credential read (L2) to an authenticated internal action (L3).
- Race: an observed window (L1) to one invariant violation (L2) to a reliable double-spend (L3).

## How to validate and limits
Advance a rung only with a bounded oracle and a passing negative control; claim
critical only after the relevant bridge is demonstrated with signed target-bound
proof. An unbridged crash or write caps the score below critical.
