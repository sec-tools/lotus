"""Discovery measurement harness for before/after evaluation.

The platform's improvement loop needs a *deterministic, fast* way to measure
whether a change to tools or skills produces **more and deeper leads** on a
given codebase - without paying for the full AI/lab audit on every iteration.

This harness isolates the Phase-1 *discovery signal*:

  1. detects the repo's language(s),
  2. runs the high-yield discovery battery (:func:`run_high_yield_discovery`)
     and the containerized external analyzers (:mod:`backend.ext_analyzers`),
  3. aggregates findings and computes the platform's own KPIs via
     :func:`measure_discovery_effectiveness`,
  4. snapshots the result to JSON keyed by repo + code SHA + label, and
  5. diffs two snapshots so a change's lift is quantified
     (total/qualified/deep leads, techniques gained, per-class deltas).

Lead-level metrics are the right first measure for tool/skill work. Whether a
lead becomes a *proven finding* (PoC on the lab) is a separate, heavier gate
exercised by the full audit pipeline - this harness deliberately stops at the
lead boundary so iterations stay fast and comparable.

CLI:
    python -m backend.eval_harness scan <path> [--label L] [--no-containerized]
    python -m backend.eval_harness diff <before.json> <after.json>
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Priority bug classes from the audit directive (deprioritise DoS).
PRIORITY_CLASSES = {
    "rce": ["command inject", "code inject", "exec", "rce", "os.system", "eval(", "deserializ", "unmarshal", "pickle", "gadget"],
    "deserialization": ["deserializ", "unmarshal", "pickle", "yaml.load", "readobject", "marshal"],
    "authz": ["authz", "authoriz", "access control", "idor", "object-level", "privilege", "rbac", "abac", "policy"],
    "authn": ["authn", "authenticat", "auth bypass", "login", "session", "jwt", "oauth", "saml", "token"],
    "ssrf": ["ssrf", "server-side request", "upstream", "proxy"],
    "path_traversal": ["path travers", "directory travers", "file read", "arbitrary file"],
    "injection_sql": ["sql inject", "sqli", "query concat"],
}


def _repo_sha(dest: Path) -> str:
    """Best-effort content identity: git HEAD if available, else a tree hash."""
    try:
        out = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()[:12]
    except Exception:
        pass
    # Fallback: hash of sorted source file names + sizes (cheap, stable-ish).
    h = hashlib.sha256()
    try:
        for p in sorted(dest.rglob("*"))[:5000]:
            if p.is_file():
                h.update(p.name.encode(errors="ignore"))
                try:
                    h.update(str(p.stat().st_size).encode())
                except OSError:
                    pass
    except Exception:
        pass
    return "tree-" + h.hexdigest()[:10]


def _classify(f: Dict[str, Any]) -> List[str]:
    text = " ".join(str(f.get(k, "")) for k in ("title", "description", "tool", "discovery_technique")).lower()
    hits = []
    for cls, needles in PRIORITY_CLASSES.items():
        if any(n in text for n in needles):
            hits.append(cls)
    return hits


async def evaluate_repo(
    dest: Path,
    language: Optional[str] = None,
    include_containerized: bool = True,
) -> Dict[str, Any]:
    """Run the discovery signal on ``dest`` and return findings + metrics."""
    from backend.pipeline import detect_language
    from backend.discovery_engine import run_high_yield_discovery, measure_discovery_effectiveness

    dest = Path(dest)
    lang = language or detect_language(dest)

    findings: List[dict] = []
    tool_timing: Dict[str, int] = {}

    # 1) High-yield deterministic discovery battery.
    t0 = datetime.utcnow()
    hy_findings, hy_meta = run_high_yield_discovery(dest, lang)
    findings.extend(hy_findings)
    tool_timing["high-yield-discovery"] = int((datetime.utcnow() - t0).total_seconds() * 1000)

    # 2) Containerized external analyzers (best-effort; skip if docker/images absent).
    container_summary: Dict[str, Any] = {}
    if include_containerized:
        from backend import ext_analyzers as ext
        runners = [
            ("semgrep-registry", ext.run_semgrep_container),
            ("osv-scanner", ext.run_osv_scanner),
        ]
        if lang == "go":
            runners = [
                ("gosec", ext.run_gosec),
                ("govulncheck", ext.run_govulncheck),
                ("staticcheck", ext.run_staticcheck),
            ] + runners
        for name, runner in runners:
            t = datetime.utcnow()
            try:
                got = await runner(dest)
            except Exception as e:  # pragma: no cover - defensive
                got = []
                container_summary[name] = f"error: {str(e)[:120]}"
            tool_timing[name] = int((datetime.utcnow() - t).total_seconds() * 1000)
            container_summary.setdefault(name, len(got))
            findings.extend(got)

    # 3) De-dup on (tool, file, line, title).
    seen = set()
    deduped: List[dict] = []
    for f in findings:
        key = (f.get("tool"), f.get("file"), f.get("line"), f.get("title"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    findings = deduped

    # 4) KPIs + priority-class breakdown.
    duration_ms = sum(tool_timing.values())
    metrics = measure_discovery_effectiveness(findings, duration_ms=duration_ms)

    class_counts: Dict[str, int] = {c: 0 for c in PRIORITY_CLASSES}
    class_qualified: Dict[str, int] = {c: 0 for c in PRIORITY_CLASSES}
    for f in findings:
        is_q = f.get("qualification") == "QUALIFIED" or int(f.get("lead_depth") or 1) >= 3
        for cls in _classify(f):
            class_counts[cls] += 1
            if is_q:
                class_qualified[cls] += 1

    top = sorted(
        findings,
        key=lambda f: (
            0 if f.get("qualification") == "QUALIFIED" else 1,
            -float(f.get("cvss") or 0),
            -int(f.get("lead_depth") or 1),
        ),
    )[:25]

    return {
        "language": lang,
        "metrics": metrics,
        "tool_timing_ms": tool_timing,
        "containerized": container_summary,
        "priority_class_counts": class_counts,
        "priority_class_qualified": class_qualified,
        "tool_counts": _count_by(findings, "tool"),
        "technique_counts": _count_by(findings, "discovery_technique"),
        "top_leads": [
            {
                "tool": f.get("tool"),
                "title": (f.get("title") or "")[:120],
                "file": f.get("file"),
                "line": f.get("line"),
                "cvss": f.get("cvss"),
                "qualification": f.get("qualification"),
                "classes": _classify(f),
            }
            for f in top
        ],
    }


def _count_by(findings: List[dict], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        k = f.get(key) or "unknown"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def snapshot(
    dest: Path,
    label: str = "",
    out_dir: Optional[Path] = None,
    include_containerized: bool = True,
) -> Dict[str, Any]:
    """Evaluate ``dest`` and persist a JSON snapshot; returns the snapshot dict."""
    dest = Path(dest)
    result = asyncio.run(evaluate_repo(dest, include_containerized=include_containerized))
    snap = {
        "repo_path": str(dest),
        "repo_name": dest.name,
        "code_sha": _repo_sha(dest),
        "label": label,
        "timestamp": datetime.utcnow().isoformat(),
        "platform_fingerprint": _platform_fingerprint(),
        **result,
    }
    out_dir = Path(out_dir or (Path(os.environ.get("LOTUS_DATA_DIR", "./data")) / "eval_snapshots"))
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{dest.name}--{snap['code_sha']}--{label or 'run'}--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    (out_dir / fname).write_text(json.dumps(snap, indent=2))
    snap["_snapshot_path"] = str(out_dir / fname)
    return snap


def _platform_fingerprint() -> str:
    """Hash of the discovery-relevant source so snapshots record 'which platform'."""
    h = hashlib.sha256()
    root = Path(__file__).parent
    for rel in ("discovery_engine.py", "ext_analyzers.py", "pipeline.py"):
        p = root / rel
        try:
            h.update(p.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:12]


def diff(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compute lift of ``after`` over ``before``. Positive = improvement."""
    bm, am = before.get("metrics", {}), after.get("metrics", {})

    def d(key):
        return round((am.get(key, 0) or 0) - (bm.get(key, 0) or 0), 3)

    bc, ac = before.get("priority_class_counts", {}), after.get("priority_class_counts", {})
    bcq, acq = before.get("priority_class_qualified", {}), after.get("priority_class_qualified", {})
    class_delta = {c: (ac.get(c, 0) - bc.get(c, 0)) for c in set(bc) | set(ac)}
    class_q_delta = {c: (acq.get(c, 0) - bcq.get(c, 0)) for c in set(bcq) | set(acq)}

    b_tech, a_tech = set(before.get("technique_counts", {})), set(after.get("technique_counts", {}))
    b_tool, a_tool = set(before.get("tool_counts", {})), set(after.get("tool_counts", {}))

    return {
        "repo": after.get("repo_name") or before.get("repo_name"),
        "code_sha_before": before.get("code_sha"),
        "code_sha_after": after.get("code_sha"),
        "same_code": before.get("code_sha") == after.get("code_sha"),
        "deltas": {
            "total_leads": d("total_leads"),
            "qualified_leads": d("qualified_leads"),
            "lead_depth_ge3_pct": d("lead_depth_ge3_pct"),
            "cvss_demonstrated_ge9": d("cvss_demonstrated_ge9"),
            "high_signal_score": d("high_signal_score"),
        },
        "priority_class_delta": class_delta,
        "priority_class_qualified_delta": class_q_delta,
        "techniques_gained": sorted(a_tech - b_tech),
        "techniques_lost": sorted(b_tech - a_tech),
        "tools_gained": sorted(a_tool - b_tool),
        "tools_lost": sorted(b_tool - a_tool),
        "improved": (
            d("total_leads") > 0 or d("qualified_leads") > 0
            or d("lead_depth_ge3_pct") > 0 or len(a_tech - b_tech) > 0
        ),
    }


def _fmt_scan(snap: Dict[str, Any]) -> str:
    m = snap.get("metrics", {})
    lines = [
        f"repo={snap['repo_name']} sha={snap['code_sha']} lang={snap['language']} label={snap.get('label') or '-'}",
        f"  total_leads={m.get('total_leads')} qualified={m.get('qualified_leads')} "
        f"depth>=3%={m.get('lead_depth_ge3_pct')} high_signal={m.get('high_signal_score')}",
        f"  priority classes: " + ", ".join(
            f"{c}={n}" for c, n in snap.get("priority_class_counts", {}).items() if n
        ),
        f"  containerized: {snap.get('containerized')}",
        f"  snapshot: {snap.get('_snapshot_path')}",
    ]
    return "\n".join(lines)


def _fmt_diff(dd: Dict[str, Any]) -> str:
    lines = [
        f"DIFF repo={dd['repo']} same_code={dd['same_code']} improved={dd['improved']}",
        "  deltas: " + ", ".join(f"{k}={v:+g}" for k, v in dd["deltas"].items()),
        "  class delta: " + ", ".join(f"{c}={v:+d}" for c, v in dd["priority_class_delta"].items() if v),
        "  qualified class delta: " + ", ".join(f"{c}={v:+d}" for c, v in dd["priority_class_qualified_delta"].items() if v),
    ]
    if dd["techniques_gained"]:
        lines.append("  techniques gained: " + ", ".join(dd["techniques_gained"]))
    if dd["tools_gained"]:
        lines.append("  tools gained: " + ", ".join(dd["tools_gained"]))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Lotus discovery measurement harness")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="Evaluate a repo path and snapshot metrics")
    ps.add_argument("path")
    ps.add_argument("--label", default="")
    ps.add_argument("--no-containerized", action="store_true")

    pd = sub.add_parser("diff", help="Diff two snapshot JSON files (before after)")
    pd.add_argument("before")
    pd.add_argument("after")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        snap = snapshot(Path(args.path), label=args.label,
                        include_containerized=not args.no_containerized)
        print(_fmt_scan(snap))
        return 0
    if args.cmd == "diff":
        before = json.loads(Path(args.before).read_text())
        after = json.loads(Path(args.after).read_text())
        dd = diff(before, after)
        print(_fmt_diff(dd))
        print(json.dumps(dd, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
