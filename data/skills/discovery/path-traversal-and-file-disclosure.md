# Skill: Path Traversal and Arbitrary File Read/Write

## Metadata
- **Category**: discovery
- **Language**: multi-language
- **Stacks**: file-download, upload, static-files, lfi, templating
- **Signals**: send_file, sendfile, staticfiles, filepath.join, os.path.join, path.join, fs.readfile, readfile, include, x-accel-redirect
- **Unique vs**: archive-extraction (zip-slip inside archives) and sql-file-privilege (SQL FILE verbs). This is request-driven file path handling in download, upload, static serving, and includes.

## Doctrine
When a request field reaches a filesystem path, the destination is attacker-influenced
until canonicalized and confirmed within an intended root. Reads leak source, config,
and secrets (LFI); writes drop web shells or overwrite config; includes can execute.
The bug is the missing containment check, not the presence of a dot-dot sequence.

## Discovery vectors (up to ten)
1. Grep file APIs (open/read/write/sendfile/static handlers) and reverse-trace the path argument to a source.
2. Find download and export endpoints that take a filename or path parameter.
3. Find upload handlers that derive the stored path from a client-supplied name.
4. Check static-file and asset routes for traversal above the served root.
5. Test dot-dot sequences, absolute paths, and encoded variants (`%2e%2e`, double-encoding, overlong UTF-8).
6. Check null-byte and trailing-dot or trailing-space truncation on the target platform.
7. Inspect template include and partial resolution that accepts a user-controlled name (LFI to RCE).
8. Look for `X-Accel-Redirect`/`X-Sendfile` trust where the app path is not contained.
9. Verify path-component containment and prevent symlink replacement between validation and opening; a string prefix check is insufficient.
10. Trace write primitives to a code or config path for traversal-to-RCE.

## Cross-language and stack examples
- Python: `open(os.path.join(base, name))` or `send_file(user_path)` without containment; a Django static misroute.
- Node: `fs.readFile(path.join(root, req.query.f))`; `res.sendFile` without the `root` option.
- Go: `filepath.Join(root, query.Get("f"))` without `Clean` and a prefix check; `http.ServeFile`.
- Java: `new File(base, request.getParameter("name"))`; a Spring resource handler above the root.
- PHP: `include`/`require`/`readfile`/`fopen` of a user path; wrappers like `php://filter`.
- Ruby/Rails: `send_file`/`File.read` on a params-derived path; a static route above `public/`.
- .NET: `Path.Combine(root, userInput)` without a canonical-prefix check; `PhysicalFile` on a user path.

## How to validate
In an authorized lab, request a lab-only sentinel outside the intended root; the
oracle is the sentinel contents returned (read) or a sentinel file appearing outside
the root (write). Negative control: a contained path resolves normally and a
traversal attempt is rejected. Require signed target-bound proof.

## Counterexamples and limits
Verified path-component containment through the actual file operation, or an enforced
allowlist of names, can refute the specific traversal path. A read-only mount prevents
writes but does not establish read confinement. A reflected dot-dot in an error with
no out-of-root read or write is a lead only.

Evidence bar: a path-looking parameter is a lead, not a finding - confirm with a bounded oracle (a lab sentinel read from, or written, outside the intended root), a passing negative control (a contained path works while traversal is refused), and signed target-bound proof on the shipped artifact.
