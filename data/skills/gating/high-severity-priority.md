# Skill: High-Severity Priority Gate

## Metadata
- **Category**: gating
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded

## Doctrine
Protect lab budget for the leads that can be critical. DoS and hangs may be real
but must never block a protocol, auth, or RCE proof-of-concept. Order work by
demonstrable impact.

## Priority
- **P0**: pre-auth RCE, fail-open authz, unauthenticated admin, unsafe deserialization on request bytes.
- **P1**: authenticated RCE, sibling auth miss, file read/write primitive (LOAD DATA / arbitrary write).
- **P2**: medium-impact issues with a real boundary crossing.
- **P3**: DoS, hang, infinite recursion, decompression bombs; never consume lab budget until every P0/P1 lead is proven or disproven.

## Discovery vectors (up to ten)
1. Tag each lead P0-P3 by demonstrated primitive and reachability, not by how interesting it looks.
2. Pull pre-auth and unauthenticated-admin leads to the front.
3. Separate a crash from a control primitive before scoring (see conviction-ladder).
4. Identify read/write primitives that bridge to execution and prioritize the bridge.
5. Defer pure DoS behind all P0/P1 work and cap its CVSS.
6. Check whether a "DoS" is actually a memory-safety bug with an exploit path (then it is not P3).
7. Confirm the actor for each lead (unauth vs authed vs admin) to place it correctly.
8. Re-rank after each confirmation; a proven primitive can promote adjacent leads.
9. Record why a lead is deprioritized so it is not silently dropped.
10. Ensure at least one P0/P1 has a running oracle before touching P3.

## Cross-language and stack examples
- A Go regex or parser DoS is P3 and must not delay a Go dashboard auth-bypass PoC.
- A C/C++ decompression bomb is P3; a C/C++ pre-auth deserialization or overflow is P0/P1.
- A verbose error or missing security header is P3 next to a Python pre-auth RCE.
- A self-DoS an authenticated user inflicts on their own tenant is low; a cross-tenant write is high.
- Prefer one proven pre-auth critical over five unproven criticals from a scanner.

## Rule and limits
A DoS lead may exist but must not block protocol/auth/RCE PoCs. Cap DoS CVSS at
5.3 unless a bridged, higher-impact primitive is demonstrated with signed
target-bound proof.
