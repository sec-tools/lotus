"""Attested lab proof receipts.

Free-form PoC output is useful for investigation, but it is not evidence that can
support a report.  This module defines the small, signed receipt exchanged between
the trusted runner and the proof gate.  The signing key is deliberately mandatory:
without one, a run may remain a candidate but can never become report-eligible.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

RECEIPT_SCHEMA_VERSION = 1
ISSUER = "lotus-lab-runner"


def _signing_key() -> Optional[bytes]:
    raw = (os.environ.get("LOTUS_PROOF_SIGNING_KEY") or "").strip()
    # Do not accept short/demo keys.  A missing key intentionally makes all proof
    # candidates unreportable rather than silently using an in-process secret.
    if len(raw) < 32:
        return None
    return raw.encode("utf-8")


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _unsigned(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in receipt.items() if k != "signature"}


def receipt_signature(receipt: Dict[str, Any], key: Optional[bytes] = None) -> str:
    secret = key or _signing_key()
    if not secret:
        return ""
    return hmac.new(secret, _canonical(_unsigned(receipt)), hashlib.sha256).hexdigest()


def sign_blob(payload: bytes, *, purpose: str = "", key: Optional[bytes] = None) -> str:
    """Sign an opaque durable blob with domain separation.

    Reports use this helper because a plain digest stored next to a database
    row is not tamper evidence: an actor able to write the row can rewrite the
    digest too.  Keeping the key lookup here makes the same fail-closed policy
    apply to receipts and report publication snapshots.
    """
    secret = key or _signing_key()
    if not secret or not isinstance(payload, bytes):
        return ""
    domain = (purpose or "lotus-blob").encode("utf-8") + b"\0"
    return hmac.new(secret, domain + payload, hashlib.sha256).hexdigest()


def verify_blob(payload: bytes, signature: str, *, purpose: str = "", key: Optional[bytes] = None) -> bool:
    """Verify a domain-separated blob signature without accepting unsigned data."""
    expected = sign_blob(payload, purpose=purpose, key=key)
    return bool(expected and isinstance(signature, str) and hmac.compare_digest(signature, expected))


def tracked_source_paths(root: Path) -> Optional[list[str]]:
    """Enumerate index paths without executing enrolled Git configuration hooks."""
    base = Path(root).resolve()
    if not (base / ".git").exists():
        return None
    env = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    try:
        proc = subprocess.run(
            ["git", "-C", str(base), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
             "ls-files", "-z"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=15, check=False, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("captured Git file inventory is unavailable") from None
    if proc.returncode or len(proc.stdout or b"") > 32 * 1024 * 1024:
        raise ValueError("captured Git file inventory is unavailable or oversized")
    try:
        names = [raw.decode("utf-8", errors="strict") for raw in (proc.stdout or b"").split(b"\0") if raw]
    except UnicodeError:
        raise ValueError("captured Git paths require UTF-8 encoding") from None
    if len(names) > 100_000:
        raise ValueError("captured Git file inventory exceeds its file limit")
    return names


def source_content_files(root: Path) -> list[Path]:
    """Exact file selection shared by source digests, snapshots and viewers."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise FileNotFoundError("source tree is unavailable")
    # Only controller-managed snapshot objects may supply a captured inventory.
    # Arbitrary target-side manifests never become an authority for selection.
    if base.name == "source":
        from backend.target_snapshots import managed_snapshot_files
        captured = managed_snapshot_files(base)
        if captured is not None:
            return captured
    # Hash source, not VCS metadata or Lotus' own generated evidence.  Git
    # object packs and generated Dockerfiles are mutable implementation
    # details that would otherwise make a receipt appear stale immediately
    # after a normal audit run.  Dynamic language fuzzers also materialize
    # throwaway harnesses at the checkout root; those are platform output,
    # not target source, and must not invalidate an otherwise immutable
    # receipt after the runner cleans/rotates them.
    generated_names = {"Dockerfile.lotus", "cpg.bin"}
    vcs_dirs = {".git", ".hg", ".svn"}
    generated_dirs = {
        ".lotus_harness", "node_modules", "target", "build", "dist", "out",
        "coverage", ".pytest_cache", "__pycache__", ".mypy_cache", ".tox",
        ".venv", "venv",
    }

    # For a Git checkout, use the tracked file set.  This is stronger than
    # a name-based denylist: generated build output, ignored dependencies,
    # and fuzz corpus files cannot alter the target identity, while a
    # deliberately tracked source file named ``build`` or ``vendor`` still
    # remains bound to the receipt.  If Git metadata is unavailable (local
    # directory enrollment), fall back to a conservative walk below.
    files = []
    tracked = tracked_source_paths(base)
    if tracked is not None:
        for name in tracked:
            try:
                candidate = (base / name).resolve()
                if candidate.is_file() and base in candidate.parents:
                    files.append(candidate)
            except (OSError, ValueError):
                continue
    if tracked is None:
        files = sorted(
            p for p in base.rglob("*")
            if p.is_file()
            and not p.is_symlink()
            and not any(
                part in vcs_dirs or part == ".lotus" or part in generated_dirs
                for part in p.relative_to(base).parts
            )
            and p.name not in generated_names
        )
    else:
        files = sorted(set(files))
    return files


def content_tree_digest(root: Optional[Path], *, files=None) -> str:
    """Digest the exact selected source paths, excluding generated evidence."""
    if not root:
        return ""
    base = Path(root).resolve()
    if not base.is_dir():
        return ""
    digest = hashlib.sha256()
    try:
        selected = source_content_files(base) if files is None else [base / Path(path) for path in files]
        for path in selected:
            if not path.resolve().is_relative_to(base) or not path.is_file():
                return ""
            rel = path.relative_to(base).as_posix().encode("utf-8")
            digest.update(len(rel).to_bytes(4, "big"))
            digest.update(rel)
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
    except (OSError, ValueError):
        return ""
    return "sha256:" + digest.hexdigest()


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    payload = {
        "title": str(finding.get("title") or "").strip(),
        "file": str(finding.get("file") or "").strip(),
        "line": line,
        "class": str(finding.get("canonical_class") or finding.get("class") or finding.get("primitive_type") or "").strip(),
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def issue_receipt(
    *,
    audit_id: str,
    finding: Dict[str, Any],
    target_revision: str,
    target_tree_hash: str,
    lab_run_id: str,
    container_id: str,
    image_digest: str,
    network_id: str,
    command_argv: Iterable[str],
    request: Optional[Dict[str, Any]],
    baseline: Dict[str, Any],
    observed: Dict[str, Any],
    oracle_kind: str,
    artifact_hashes: Iterable[str],
) -> Optional[Dict[str, Any]]:
    """Create a signed receipt, or ``None`` when attestation is not configured."""
    key = _signing_key()
    if not key:
        return None
    receipt: Dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_id": str(uuid.uuid4()),
        "audit_id": str(audit_id),
        "finding_fingerprint": finding_fingerprint(finding),
        "target": {
            "revision": str(target_revision),
            "tree_hash": str(target_tree_hash),
        },
        "lab": {
            "run_id": str(lab_run_id),
            "container_id": str(container_id),
            "image_digest": str(image_digest),
            "network_id": str(network_id),
        },
        "execution": {
            "argv": [str(x) for x in command_argv],
            "request": request or {},
        },
        "oracle": {
            "kind": str(oracle_kind),
            "baseline": baseline,
            "observed": observed,
            "passed": True,
        },
        "artifact_hashes": sorted({str(x) for x in artifact_hashes if str(x).startswith("sha256:")}),
        "issuer": ISSUER,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    receipt["signature"] = receipt_signature(receipt, key=key)
    return receipt


def verify_receipt(receipt: Any, finding: Optional[Dict[str, Any]] = None) -> bool:
    """Verify structure, provenance, binding and signature of a receipt."""
    key = _signing_key()
    if not key or not isinstance(receipt, dict):
        return False
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION or receipt.get("issuer") != ISSUER:
        return False
    signature = str(receipt.get("signature") or "")
    if not signature or not hmac.compare_digest(signature, receipt_signature(receipt, key=key)):
        return False
    required_top = ("receipt_id", "audit_id", "finding_fingerprint", "target", "lab", "execution", "oracle", "artifact_hashes", "issued_at")
    if any(not receipt.get(k) for k in required_top):
        return False
    target = receipt.get("target")
    lab = receipt.get("lab")
    execution = receipt.get("execution")
    oracle = receipt.get("oracle")
    # Git checkouts carry a commit revision; local-directory enrollments may
    # have no VCS metadata and are bound solely by their deterministic content
    # digest.  Require at least one immutable identity plus a valid tree hash,
    # rather than rejecting every legitimate local-path proof.
    if (
        not isinstance(target, dict)
        or not (str(target.get("revision") or "").strip() or str(target.get("tree_hash") or "").strip())
        or not str(target.get("tree_hash") or "").startswith("sha256:")
    ):
        return False
    if not isinstance(lab, dict):
        return False
    if not str(lab.get("run_id") or "") or not str(lab.get("container_id") or ""):
        return False
    if not str(lab.get("image_digest") or "").startswith("sha256:") or not str(lab.get("network_id") or ""):
        return False
    if not isinstance(execution, dict) or not isinstance(execution.get("argv"), list) or not execution["argv"]:
        return False
    if not isinstance(oracle, dict) or oracle.get("passed") is not True or not str(oracle.get("kind") or ""):
        return False
    if not isinstance(oracle.get("baseline"), dict) or not isinstance(oracle.get("observed"), dict):
        return False
    artifacts = receipt.get("artifact_hashes")
    if not isinstance(artifacts, list) or not artifacts or any(not str(a).startswith("sha256:") for a in artifacts):
        return False
    if finding is not None and receipt.get("finding_fingerprint") != finding_fingerprint(finding):
        return False
    if finding is not None:
        expected_audit = finding.get("proof_audit_id") or finding.get("audit_id")
        if expected_audit is not None and str(receipt.get("audit_id")) != str(expected_audit):
            return False
    return True
