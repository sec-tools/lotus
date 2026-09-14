# Skill: R/W/X Primitive Coverage Matrix

## Metadata
- **Category**: methodology
- **Language**: multi-language
- **Applies to**: all repositories - cross-cutting doctrine, always loaded
- **Source**: TAXONOMIES-AND-ONTOLOGIES.md

## Doctrine
Score by the primitive you can demonstrate (Read, Write, eXecute), not by the
label of the bug. A coverage matrix keeps an audit from over-investing in one
class while a whole primitive family goes unexamined.

## Execute (X)
X-1 OS command, X-3 server-side template injection, X-4 eval/dynamic load,
X-5 deserialization, X-9 SQL-to-OS, X-10 reflection/dynamic dispatch.

## Write (W)
W-1 arbitrary file write, W-3 path-traversal write, W-7 cache/session poisoning,
W-9 prototype pollution, W-11 config/rule write that later executes.

## Read (R)
R-1 arbitrary file read, R-2 SQLi read, R-3 path-traversal read, R-4 SSRF,
R-6 memory disclosure, R-8 cross-tenant object read (IDOR).

## Discovery vectors (up to ten)
1. For each matrix cell, grep the canonical sinks and mark cells with at least one reachable candidate.
2. Convert each candidate to a conviction level (L0 hypothesis to L3 impact) and record the gap to the next level.
3. Look for cross-primitive escalation: a Write that becomes eXecute (drop a webshell, cron, .so, systemd unit, key).
4. Look for Read that enables Write or Execute (leak a secret, then authenticate to an admin sink).
5. Check SSRF (R-4) as a pivot into internal Write/Execute planes (cloud metadata, admin APIs).
6. Map SQLi to both R (dump) and X (stacked queries, `INTO OUTFILE`, UDF) cells.
7. Enumerate deserialization (X-5) across every format the app parses, not just the obvious one.
8. Find template/expression engines (X-3) reachable from request data for SSTI.
9. Audit cache and session stores (W-7) for poisoning that alters another user's execution.
10. Track which cells have zero candidates and say so honestly rather than implying they are safe.

## Cross-language and stack examples
- Execute (X): Python `eval`/`pickle`, Node `vm`/`child_process`, Java `ObjectInputStream`/`ScriptEngine`, Go `exec.Command`/`plugin.Open`, C/C++ `system`/`dlopen`, Ruby `Marshal`/`eval`.
- Write (W): prototype pollution in JS merges, `os.WriteFile`/`filepath.Join` traversal in Go, arbitrary `File.write` in Ruby, Zip Slip in Java, `INTO OUTFILE` in SQL.
- Read (R): `open(user_path)` in Python, `res.sendFile` in Node, `filepath.Join` traversal in Go, `pg_read_file` in SQL, XXE file read in Java, SSRF via any HTTP client.
- Bridges: R-to-X via config-that-executes, W-to-X via a writable plugin/hook path, X-to-RW via a shell.
- End-to-end chains: Node prototype-pollution (W) to a gadget (X); Python LFI (R) to config-exec (X); Go tar traversal (W) to a writable unit/hook (X); SQLi to `INTO OUTFILE` (W) to a web shell (X).

## Conviction ladder
L0 Hypothesis, L1 Reachable, L2 Triggerable (lab effect observed), L3 Impactful
(report-eligible). Memory and write primitives require conviction bridges before
scoring critical: a crash is not control, a write is not execution.

## How to validate and limits
Each claimed cell needs a bounded oracle and a negative control at L2+, and signed
target-bound proof at L3. An empty cell is "not examined / no candidate", never a
guarantee of safety.
