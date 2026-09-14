# Skill: Hypothesis Qualification Before Lab Spend

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: Skill 75

## Doctrine
Lab time is scarce; qualify before you spend it. A hypothesis earns lab budget only
when it has a clear source-to-sink path, a missing or skippable guard, and a
testable oracle. Everything else is deepened or deferred, not probed.

## Labels
- **QUALIFIED**: clear source to sink, missing/skippable guard, lab-testable oracle.
- **LATENT**: needs more hops or preconditions before it is testable.
- **NO-BOUNDARY**: no security boundary is actually crossed.
- **MIRROR-ONLY**: proven only in a reimplementation, not the shipped artifact.
- **PRECONDITIONED**: requires an unrealistic attacker position.

## Discovery vectors (up to ten)
1. State the source, the sink, and every hop between them; a gap means LATENT.
2. Identify the guard on the path and whether it is missing, skippable, or enforced.
3. Define the oracle now: the exact observation that would confirm impact.
4. Define the negative control now: the input that must NOT trigger it.
5. Check that the input is attacker-controlled on the real deployment, not operator-set.
6. Confirm the boundary being crossed (privilege, tenant, trust zone); none means NO-BOUNDARY.
7. Verify you are targeting the shipped artifact, not a mirror (else MIRROR-ONLY).
8. Assess attacker position realism (network location, credentials, timing) for PRECONDITIONED.
9. Estimate cost-to-confirm and expected impact to rank lab spend.
10. For LATENT, name the single next hop that would qualify it, then pursue that first.

## Cross-language and stack examples
- QUALIFIED: an unauthenticated route reaching `exec.Command` with a request field in Go.
- QUALIFIED: a pre-auth `pickle.loads` on request bytes in a Python webhook.
- LATENT: a deserialization sink reachable only after an unproven auth step.
- LATENT: a Java `ObjectInputStream` gadget with no confirmed source path.
- NO-BOUNDARY: a config value an operator already controls reaching a local command.

## How to validate and limits
Never spend lab budget on MIRROR-ONLY or NO-BOUNDARY. Deepen LATENT by exactly one
hop before probing. Confirmation still requires a bounded oracle, a passing
negative control, and signed target-bound proof.
