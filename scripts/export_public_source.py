#!/usr/bin/env python3
"""Prepare a separate source folder for public review; never clean the live tree.

Uses prepare_release's curated copy. Additional checks flag recognized secrets,
contact/home-path indicators and structured audit records. Detection is finite,
not a guarantee that all secrets, personal data or audit artifacts were found.
No Git initialization, commit, upload, dependency install or platform reset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

try:
    from scripts import prepare_release
except ModuleNotFoundError:
    import prepare_release

REVIEW_RULES = {"contact-address-review", "personal-path-review", "audit-record-review"}
EMAIL = re.compile(rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
HOME = re.compile(rb"(?:/(?:Users|home)/[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)")
AUDIT_FIELDS = {"target_snapshot", "progress_json", "tool_results", "report_context", "lab_status", "runtime_attachments", "notebook_runs"}
RUNTIME_NAMES = {"credentials.json", "lotus.db", "progress.json", "scan-jobs.json", "notebook-runs.json"}
MAX_JSON = 8 * 1024 * 1024
MAX_FILES = 20000
MAX_BYTES = 256 * 1024 * 1024


class ExportBlocked(Exception):
    def __init__(self, report):
        self.report = report
        super().__init__("Public source review blocked; matched values are omitted")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _location(relative):
    # Even an unusual filename may itself contain a credential or contact.
    raw = relative.encode()
    patterns = [EMAIL, HOME, *prepare_release.SECRET_RULES.values()]
    return {"path_sha256": sha(raw)} if any(p.search(raw) for p in patterns) else {"path": relative}


def _issue(relative, rule, data=None, offset=None):
    result = {**_location(relative), "rule": rule}
    if data is not None and offset is not None:
        result["line"] = data[:offset].count(b"\n") + 1
    return result


def _has_audit_record(value):
    pending = [(value, 0)]; visited = 0
    while pending:
        item, depth = pending.pop(); visited += 1
        if visited > 50000 or depth > 32:
            raise ValueError("Structured review bound")
        if isinstance(item, dict):
            if "repo_id" in item and ({"scan_job_id", "job_id"} & item.keys()) and (AUDIT_FIELDS & item.keys()):
                return True
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return False


def _private_contact(data):
    return next((m for m in EMAIL.finditer(data) if not (
        m.group().rsplit(b"@", 1)[1].lower() in {b"example.com", b"example.org", b"example.net"}
        or m.group().rsplit(b"@", 1)[1].lower().endswith((b".example", b".invalid", b".test")))), None)


def inspect_export(root, inventory):
    """Inspect the actual copied payload, then bind its content and membership."""
    issues = []
    expected = {row["path"] for row in inventory["files"]} | {"SOURCE_MANIFEST.json"}
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            issues.append(_issue(path.relative_to(root).as_posix(), "export-symlink"))
        elif path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        issues.append({"rule": "export-membership-changed"})
    for row in inventory["files"]:
        relative = row["path"]; path = root / relative
        name_bytes = relative.encode()
        for rule, pattern in prepare_release.SECRET_RULES.items():
            if any(m.group() not in prepare_release.PUBLIC_EXAMPLES for m in pattern.finditer(name_bytes)):
                issues.append(_issue(relative, rule))
        if _private_contact(name_bytes):
            issues.append(_issue(relative, "contact-address-review"))
        if HOME.search(name_bytes):
            issues.append(_issue(relative, "personal-path-review"))
        if (path.is_symlink() or not path.is_file()
                or any(parent.is_symlink() for parent in path.parents if parent != root)):
            issues.append(_issue(relative, "export-file-changed")); continue
        data = path.read_bytes()
        if len(data) != row["bytes"] or sha(data) != row["sha256"] or stat.S_IMODE(path.stat().st_mode) != row["mode"]:
            issues.append(_issue(relative, "export-file-changed"))
        for rule, pattern in prepare_release.SECRET_RULES.items():
            match = next((m for m in pattern.finditer(data) if m.group() not in prepare_release.PUBLIC_EXAMPLES), None)
            if match:
                issues.append(_issue(relative, rule, data, match.start()))
        contact = _private_contact(data)
        if contact:
            issues.append(_issue(relative, "contact-address-review", data, contact.start()))
        home = HOME.search(data)
        if home:
            issues.append(_issue(relative, "personal-path-review", data, home.start()))
        if data.startswith(b"SQLite format 3\x00") or path.name.lower() in RUNTIME_NAMES:
            issues.append(_issue(relative, "runtime-data-file"))
        if path.suffix.lower() == ".json":
            if len(data) > MAX_JSON:
                issues.append(_issue(relative, "structured-review-limit")); continue
            try:
                document = json.loads(data)
            except (ValueError, UnicodeDecodeError, RecursionError):
                issues.append(_issue(relative, "structured-review-unavailable")); continue
            try:
                if _has_audit_record(document):
                    issues.append(_issue(relative, "audit-record-review"))
            except ValueError:
                issues.append(_issue(relative, "structured-review-limit"))
    manifest = root / "SOURCE_MANIFEST.json"
    if not manifest.is_file() or manifest.is_symlink() or json.loads(manifest.read_text()) != inventory:
        issues.append({"rule": "export-manifest-changed"})
    return issues


def _acknowledge(issues, inventory, acknowledgements):
    """Only exact public-fixture/privacy reviews can be acknowledged, not secrets."""
    hashes = {row["path"]: row["sha256"] for row in inventory["files"]}
    accepted = set()
    if not isinstance(acknowledgements, list) or len(acknowledgements) > 1000:
        raise ValueError("Review acknowledgements must be a bounded list")
    for item in acknowledgements:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "rule"}
                or item["rule"] not in REVIEW_RULES or item["path"] not in hashes
                or item["sha256"] != hashes[item["path"]]):
            raise ValueError("Review acknowledgement is invalid or stale")
        key = (item["path"], item["rule"])
        if key in accepted or not any(i.get("path") == key[0] and i["rule"] == key[1] for i in issues):
            raise ValueError("Review acknowledgement is duplicate or unused")
        accepted.add(key)
    return [i for i in issues if (i.get("path"), i["rule"]) not in accepted]


def _remove_owned(path, identity):
    if identity and not path.is_symlink() and path.exists():
        current = path.stat()
        if (current.st_dev, current.st_ino) == identity:
            shutil.rmtree(path)


def export_public(root, output, acknowledgements=None):
    root = Path(root).resolve(); requested = Path(output).absolute()
    output = requested.resolve()
    report = {"schema_version": 1, "status": "blocked", "production_certification": False,
        "detection_scope": "Recognized secret patterns, contact/home-path indicators and structured audit records; not exhaustive detection or legal review.",
        "issues": [], "excluded": {"scope": "Category summary; excluded file contents are not read",
        "categories": ["Private runtime state, snapshots, keys and databases", "Learned skills and generated audit artifacts", "Caches, installed dependencies, Git history and verification outputs", "Unselected top-level files and directories"]}}
    def block(rule):
        report["issues"].append({"rule": rule}); raise ExportBlocked(report)
    if (not root.is_dir() or requested.is_symlink() or os.path.lexists(requested)
            or not output.parent.is_dir() or output == root or output in root.parents or root in output.parents):
        block("output-must-be-new-and-outside-source")
    inventory = prepare_release.inventory(root)
    report["selected_file_count"] = len(inventory["files"])
    selected_roots = prepare_release.ROOT_FILES | prepare_release.ROOT_DIRS | {"docs", "data"}
    report["excluded"]["unselected_top_level_entry_count"] = sum(p.name not in selected_roots for p in root.iterdir())
    report["issues"] = [{**_location(i["path"]), **{k: v for k, v in i.items() if k != "path"}} for i in inventory["issues"]]
    if inventory["blockers"]:
        block("curated-export-blocked")
    if len(inventory["files"]) > MAX_FILES or sum(r["bytes"] for r in inventory["files"]) > MAX_BYTES:
        block("source-export-size-limit")
    identity = None
    try:
        output.mkdir(mode=0o700); current = output.stat(); identity = (current.st_dev, current.st_ino)
        stage = output / ".export-stage"
        prepare_release.export_sources(root, stage, inventory)
        issues = inspect_export(stage, inventory)
        report["issues"] = _acknowledge(issues, inventory, [] if acknowledgements is None else acknowledgements)
        report["acknowledged_review_count"] = len(issues) - len(report["issues"])
        if report["issues"]:
            raise ExportBlocked(report)
        # Reserve the final folder exclusively; never rename over an existing
        # destination. This folder is ready only after the receipt is written.
        for child in stage.iterdir():
            child.rename(output / child.name)
        stage.rmdir()
        final_issues = inspect_export(output, inventory)
        if _acknowledge(final_issues, inventory, [] if acknowledgements is None else acknowledgements):
            block("export-changed-during-finalization")
        report.update(status="ready-for-review", source_manifest_sha256=sha((output / "SOURCE_MANIFEST.json").read_bytes()))
        (output / "PUBLIC_SOURCE_REVIEW.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    except ExportBlocked:
        _remove_owned(output, identity); raise
    except Exception:
        _remove_owned(output, identity); block("export-or-review-failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True, help="New folder outside the source tree; parent must already exist")
    parser.add_argument("--review-acknowledgements", type=Path, help="JSON list of exact path/sha256/rule acknowledgements for reviewed public fixtures")
    args = parser.parse_args(argv)
    try:
        acknowledgements = json.loads(args.review_acknowledgements.read_text()) if args.review_acknowledgements else []
        result = export_public(args.root, args.output, acknowledgements)
    except ExportBlocked as error:
        print(json.dumps(error.report, indent=2)); return 1
    except Exception:
        print(json.dumps({"status": "blocked", "issues": [{"rule": "invalid-request-or-source"}]})); return 1
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
