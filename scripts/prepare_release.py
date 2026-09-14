#!/usr/bin/env python3
"""Create a reviewable source export without copying private runtime state.

Does not initialize Git, commit, upload, rewrite source, or select a license.
The manifest contains paths and SHA-256 hashes, never matched secret values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT_FILES = {
    "README.md", "LICENSE", "NOTICE", "lotus",
    ".gitignore", ".dockerignore", ".env.example", "Dockerfile", "docker-entrypoint.sh",
    "docker-compose.yml", "docker-compose.single.yml", "docker-compose.enterprise.yml",
    "docker-compose.host-lab.yml", "pytest.ini",
}
ROOT_DIRS = {"backend", "frontend", "k8s", "scripts", "test_projects", ".github"}
DOCS = {"APPLICATION_SBOM.json"}

DEFAULT_SKILLS = {"methodology", "discovery", "gating", "bug-classes", "packs"}
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", "node_modules", ".git", ".venv", ".lotus", ".lotus-local", ".lotus_harness", ".revisions", "test-results", "playwright-report"}
SUFFIXES = {".ttf", ".py", ".html", ".css", ".js", ".cjs", ".json", ".yaml", ".yml", ".md", ".txt", ".sh", ".toml", ".ini", ".go", ".mod", ".sum", ".java", ".rs", ".lock", ".svg", ".sql", ".c", ".h", ".cpp", ".hpp", ".rb", ".php", ".conf"}
SECRET_RULES = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github-token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
    "provider-token": re.compile(rb"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{40,}"),
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
}
# AWS's documented nonfunctional example is intentionally present in one
# authored scanner fixture. No path-wide or generic "test token" exemptions.
PUBLIC_EXAMPLES = {b"AKIAIOSFODNN7EXAMPLE"}
PRIVATE_CONFIG_NAMES = {"id_rsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc", "kubeconfig"}
PRIVATE_CONFIG_SUFFIXES = {".pem", ".p12", ".pfx", ".jks", ".keystore"}
CREDENTIAL_FORMATS = {"json", "yaml", "yml", "toml", "ini"}


def selected(relative):
    parts = relative.parts
    if any(p in EXCLUDED_PARTS for p in parts):
        return False
    if relative.name.startswith(".env") and relative != Path(".env.example"):
        return False
    # Source exports do not consult Git/Docker ignore files. Apply the same
    # private configuration boundary explicitly at every source-tree depth.
    name = relative.name.lower()
    if (name in PRIVATE_CONFIG_NAMES or name.startswith("kubeconfig.")
            or relative.suffix.lower() in PRIVATE_CONFIG_SUFFIXES
            or re.fullmatch(r"credentials(?:\.[a-z0-9_-]+)*\.(?:" + "|".join(sorted(CREDENTIAL_FORMATS)) + r")", name)):
        return False
    if parts[:4] == ("data", "skills", "packs", "learned"):
        return False
    if parts[:4] == ("data", "skills", "packs", "lotus-core") and name in {"pack.yaml", "pack.yml", "pack.json"}:
        return False
    if relative.name != "pom.xml" and re.search(r"(?:\.db(?:$|[.-])|\.sqlite|\.key|\.log$|\.xml$|\.dump$|\.pem$)", relative.name):
        return False
    if len(parts) == 1:
        return relative.name in ROOT_FILES
    if parts[0] == "docs":
        return len(parts) == 2 and parts[1] in DOCS
    if parts[0] == "data":
        return len(parts) >= 4 and parts[1] == "skills" and parts[2] in DEFAULT_SKILLS and relative.suffix in {".md", ".json"}
    # XML test-result files stay excluded; Maven's source manifest is explicit.
    if relative.name == "pom.xml":
        return parts[0] in ROOT_DIRS
    return parts[0] in ROOT_DIRS and (relative.suffix in SUFFIXES or relative.name in {"Dockerfile", "Makefile", "requirements.txt", "Gemfile"})


def inventory(root):
    files, issues = [], []
    license_nonempty = False
    # Only descend into intended source trees; never traverse the audit corpus.
    candidates = [root / name for name in ROOT_FILES if (root / name).exists()]
    for name in sorted(ROOT_DIRS):
        folder = root / name
        if folder.is_dir() and not folder.is_symlink():
            candidates.extend(folder.rglob("*"))
    candidates.extend(root / "docs" / name for name in DOCS)
    for name in DEFAULT_SKILLS:
        folder = root / "data" / "skills" / name
        if folder.is_dir() and not folder.is_symlink():
            candidates.extend(folder.rglob("*"))
    for path in sorted(set(candidates)):
        rel = path.relative_to(root)
        if not selected(rel) or not path.is_file():
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root):
            issues.append({"path": str(rel), "rule": "source-symlink"})
            continue
        data = path.read_bytes()
        if rel == Path("LICENSE"):
            license_nonempty = bool(data.strip())
        for rule, pattern in SECRET_RULES.items():
            for match in pattern.finditer(data):
                if match.group() in PUBLIC_EXAMPLES:
                    continue
                issues.append({"path": str(rel), "line": data[:match.start()].count(b"\n") + 1, "rule": rule})
        files.append({"path": str(rel), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "mode": path.stat().st_mode & 0o777})
    blockers = []
    if not license_nonempty:
        blockers.append("License text must be present and nonempty before exporting; ownership and third-party license review remain separate release gates.")
    if issues:
        blockers.append("Review flagged source files before exporting; matched values are intentionally omitted.")
    return {"schema_version": 1, "scope": "source-export", "files": files, "issues": issues,
            "blockers": blockers, "production_certification": False}


def export_sources(root, output, result):
    """Only write bytes already inspected by inventory; remove incomplete exports."""
    if result["blockers"] or result["issues"]:
        raise ValueError("Release blockers must be resolved before exporting")
    output.mkdir(parents=True, mode=0o700)
    identity = output.stat()
    try:
        for row in result["files"]:
            source = root / row["path"]
            if source.is_symlink() or any(p.is_symlink() for p in source.parents if p != root):
                raise RuntimeError("Source changed during export; retry after reviewing the source")
            data = source.read_bytes()
            if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise RuntimeError("Source changed during export; retry after reviewing the source")
            target = output / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(row["mode"])
        (output / "SOURCE_MANIFEST.json").write_text(json.dumps(result, indent=2) + "\n")
    except BaseException:
        # Only remove the new directory we created, never a replacement path.
        if not output.is_symlink() and output.exists():
            current = output.stat()
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="New, empty source export directory")
    args = parser.parse_args()
    root = args.root.resolve()
    result = inventory(root)
    if args.output:
        output = args.output.resolve()
        if output == root or output in root.parents or root in output.parents or output.exists():
            parser.error("Output must be a new directory separate from the source root")
        if result["blockers"]:
            print(json.dumps(result, indent=2))
            return 1
        export_sources(root, output, result)
    print(json.dumps({key: value for key, value in result.items() if key != "files"}, indent=2))
    print(f"Selected {len(result['files'])} source files. Dependency, image, runtime and license checks are separate release gates.")
    return 1 if result["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
