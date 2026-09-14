# Skill: Archive Extraction Path Traversal and Symlink Escape

## Metadata
- **Category**: discovery
- **Language**: c/cpp python go java multi-runtime
- **Stacks**: tar, zip, archive, unzip
- **Signals**: tarfile, zipfile, archive/tar, libarchive, extractall, adm-zip

## Doctrine
Archive extraction must canonicalize member names and symlink targets and confirm
every write stays below the intended root. A member named with `..` or an absolute
path, or a symlink member pointing outside the root, is arbitrary write (zip-slip),
and a symlink-then-follow is arbitrary read.

## Discovery vectors (up to ten)
1. Grep extractors: `tarfile.extractall`/`extract`, `ZipFile.extractall`, Go `archive/tar`/`zip` loops, Java `ZipInputStream`, C/C++ libarchive/unzip.
2. Check for a join-without-canonicalize of the member name onto the destination.
3. Check whether `..`, absolute paths, and drive/UNC prefixes are rejected.
4. Inspect symlink and hardlink member handling (created then written through).
5. Verify the final resolved path is confirmed to be within the root before write.
6. Look for TOCTOU between path check and write (a symlink swapped in mid-extraction).
7. Check nested archives and recursive extraction for the same flaws.
8. Follow file-mode/exec-bit preservation that could drop an executable into a run path.
9. Trace who supplies the archive (upload, dependency, model bundle, backup restore).
10. Compare against a safe helper (`filter='data'`, a root-containment check) used elsewhere but not here.

## Cross-language and stack examples
- Python: `tarfile.extractall`/`extract` without `filter='data'`; `zipfile.ZipFile.extractall` trusting member names; `shutil.unpack_archive`.
- Go: `archive/tar`/`archive/zip` loops calling `filepath.Join(dst, hdr.Name)` without `Clean` and a prefix check; no symlink guard.
- Java: `ZipInputStream`/`ZipFile` with `new File(dir, entry.getName())` and no canonical-path containment (Zip Slip).
- Node: `tar`, `adm-zip`, `unzipper`, `decompress` writing member paths verbatim; `extract` without validation.
- Ruby: `rubygems/package`, `Zip::File`, `Gem::Package::TarReader` extracting names without containment.
- C/C++: libarchive/minizip/unzip writing member paths verbatim; symlink and hardlink members followed.
- PHP: `ZipArchive::extractTo`, `PharData::extractTo` with attacker-controlled entry names.

## How to validate
Craft an archive with a `..` member and a symlink member and extract it in an
authorized lab; oracle is a sentinel file written outside the intended root (or a
read of a lab-only file through a symlink). Negative control: a safe extractor or a
containment check must reject the same archive. Require signed target-bound proof.

## Counterexamples and limits
Canonicalization plus a verified root-containment check, rejection of `..`/absolute
members, and refusal to follow out-of-root symlinks refute the traversal (LATENT).
A path-looking string without a demonstrated out-of-root write/read is a lead.
