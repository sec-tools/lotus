"""End-of-audit compounding: skills, PoC remeasure, fix verification.

Runs while the lab container is still up (before teardown). Heuristic when no AI.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.skills import (
    write_disprove_skill,
    write_retrospective_skill,
)

_SKILL_SCAN_EXTS = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".kt", ".swift", ".ex", ".exs",
)
_SKILL_SCAN_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "third_party", "dist", "build",
    "testdata", "__pycache__", ".venv", "venv", ".lotus",
}


def _load_lab_poc_results(dest: Path) -> Dict[str, Any]:
    p = Path(dest) / ".lotus" / "lab_poc_results.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _skill_display_name(path: str, finding: Optional[dict] = None) -> str:
    """Human label for a learned-skill file (its heading/id, not the raw path)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines()[:40]:
            s = line.strip()
            if s.startswith("# Skill:"):
                return s.split(":", 1)[1].strip()
            if s.startswith("title:"):
                return s.split(":", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    if finding and finding.get("title"):
        return str(finding["title"])
    return Path(path).stem.replace("-", " ")


def _validate_skill_against_repo(
    finding: dict, dest: Path, language: str, *, max_files: int = 400, max_hits: int = 6,
) -> Dict[str, Any]:
    """Prove a learned skill generalizes: match its detection pattern across the
    repo and report sites OTHER than the origin.

    A learned skill is distilled from a proof-gated finding, so the origin is
    already real capability. Validation additionally scans the audited source
    for the same pattern to demonstrate the skill would surface *additional*
    candidate sites next time (not just re-flag the single origin). This is
    evidence of usefulness, not a new proof-gated finding.
    """
    origin_file = str(finding.get("file") or finding.get("source_file") or "").replace("\\", "/")
    origin_line = int(finding.get("line") or finding.get("source_line") or 0) if str(
        finding.get("line") or finding.get("source_line") or ""
    ).isdigit() else 0
    regex = ""
    try:
        from backend.discovery_engine import extract_patterns_from_finding
        pat = extract_patterns_from_finding(finding, language=language) or {}
        regex = str(pat.get("regex") or "").strip()
    except Exception:
        regex = ""
    result: Dict[str, Any] = {
        "regex": regex,
        "origin": {
            "file": origin_file, "line": origin_line,
            "title": finding.get("title"), "cvss": finding.get("cvss"),
            "tool": finding.get("tool"),
        },
        "additional_matches": [],
        "scanned_files": 0,
        "verdict": "origin-only",
    }
    if not regex:
        return result
    try:
        rx = re.compile(regex)
    except re.error:
        return result
    scanned = 0
    hits: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in _SKILL_SCAN_SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            if not fn.endswith(_SKILL_SCAN_EXTS):
                continue
            if scanned >= max_files or len(hits) >= max_hits:
                break
            fp = Path(root) / fn
            try:
                rel = str(fp.relative_to(dest)).replace("\\", "/")
            except Exception:
                rel = fn
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            scanned += 1
            for i, ln in enumerate(text.splitlines(), start=1):
                if rel == origin_file and i == origin_line:
                    continue  # skip the origin site itself
                if rx.search(ln):
                    hits.append({"file": rel, "line": i, "excerpt": ln.strip()[:160]})
                    if len(hits) >= max_hits:
                        break
        if scanned >= max_files or len(hits) >= max_hits:
            break
    result["scanned_files"] = scanned
    result["additional_matches"] = hits
    result["verdict"] = "generalizes" if hits else "origin-only"
    return result


def compound_skills_from_audit(
    dest: Path,
    *,
    language: str,
    repo_source: str,
    plan: Optional[Dict[str, Any]] = None,
    confirmed: Optional[List[dict]] = None,
    lab_status: Optional[dict] = None,
    fix_results: Optional[List[dict]] = None,
    ai_call: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Write proven (if missing), DISPROVE, and retrospective skills."""
    dest = Path(dest)
    plan = plan or {}
    confirmed = confirmed or []
    written: List[str] = []
    # Per-skill provenance the UI surfaces: how/why the skill was learned, what
    # already existed (before), the capability it now adds (after), and a
    # validation that it generalizes beyond its origin site.
    skills: List[Dict[str, Any]] = []
    poc = _load_lab_poc_results(dest)
    disproven = list(poc.get("disproven") or [])

    for cf in confirmed:
        if not (cf.get("proven_in_lab") or cf.get("poc_result") == "triggered"):
            continue
        try:
            from backend.skill_learn import ingest_learned_skill
            result = ingest_learned_skill(
                cf, language=language, repo_source=repo_source, ai_call=ai_call,
            )
            written.append(result["path"])
            validation = _validate_skill_against_repo(cf, dest, language)
            skills.append({
                "kind": "learned",
                "path": result["path"],
                "name": _skill_display_name(result["path"], cf),
                # How/why it was learned.
                "action": result.get("action"),          # create | strengthen
                "created": bool(result.get("created")),
                "overlay": bool(result.get("overlay")),
                "reason": result.get("reason") or "",
                "decided_by": result.get("source") or "heuristic",  # heuristic | ai | heuristic+ai
                "used_ai": bool(result.get("used_ai")),
                # Capability BEFORE: the nearest pre-existing skills it was
                # compared against (empty/low-score => genuine gap it now fills).
                "before": result.get("candidates") or [],
                # Capability AFTER: the proof-gated finding this skill encodes.
                "origin_finding": {
                    "title": cf.get("title"), "cvss": cf.get("cvss"),
                    "file": cf.get("file") or cf.get("source_file"),
                    "line": cf.get("line") or cf.get("source_line"),
                    "tool": cf.get("tool"),
                    "primitive": cf.get("primitive_type") or cf.get("primitive"),
                },
                # Phase-3 usefulness proof.
                "validation": validation,
            })
        except Exception:
            pass
    for item in disproven:
        try:
            _dp = write_disprove_skill(item, language=language, repo_source=repo_source)
            written.append(_dp)
            skills.append({
                "kind": "disprove",
                "path": _dp,
                "name": _skill_display_name(_dp, item),
                "action": "create",
                "reason": "records a hypothesis that was tested and did NOT reproduce, "
                          "so future audits do not waste lab budget re-promoting it",
                "decided_by": "heuristic",
                "origin_finding": {
                    "title": item.get("title"), "verdict": item.get("verdict"),
                    "file": item.get("file"), "tool": item.get("tool"),
                },
                "validation": {"verdict": "disprove-memory", "additional_matches": []},
            })
        except Exception:
            pass
    retro_path = ""
    try:
        retro_path = write_retrospective_skill(
            plan, language=language, repo_source=repo_source,
            proven=confirmed, disproven=disproven,
            lab_status=lab_status, fix_results=fix_results,
        )
        written.append(retro_path)
    except Exception:
        pass

    ai_notes: List[str] = []
    if ai_call is not None and retro_path:
        try:
            from backend.audit_planner import _extract_json_object
            prompt = (
                "Distill this completed security audit into reusable heuristics.\n"
                "Return ONLY JSON with keys:\n"
                "  look_for: string[]  (what to hunt next time on similar stacks)\n"
                "  skip: string[]      (DISPROVE hypotheses not to re-promote)\n"
                "  lab: string[]       (how to build/run this class of repo)\n"
                "No exploit payloads.\n\n"
                f"language={language} repo={repo_source}\n"
                f"plan={json.dumps(plan, default=str)[:2500]}\n"
                f"proven={json.dumps([{'title': c.get('title'), 'cvss': c.get('cvss')} for c in confirmed[:12]], default=str)}\n"
                f"disproven={json.dumps([{'title': d.get('title'), 'verdict': d.get('verdict')} for d in disproven[:12]], default=str)}\n"
            )
            raw = ai_call(prompt)
            obj = _extract_json_object(raw if isinstance(raw, str) else "")
            if obj:
                for key in ("look_for", "skip", "lab"):
                    vals = obj.get(key) or []
                    if isinstance(vals, list):
                        ai_notes.extend(f"- [{key}] {v}" for v in vals[:12] if str(v).strip())
                if ai_notes:
                    p = Path(retro_path)
                    extra = "\n\n## AI-synthesized heuristics (this audit)\n" + "\n".join(ai_notes) + "\n"
                    p.write_text(p.read_text(encoding="utf-8") + extra, encoding="utf-8")
        except Exception:
            pass

    return {
        "skills_written": len(written),
        "paths": written[-12:],
        "disproven_count": len(disproven),
        "proven_count": len(confirmed),
        "ai_heuristics": len(ai_notes),
        # Structured provenance for the completion UI (how/why learned, before
        # vs after capability, and phase-3 generalization proof per skill).
        "skills": skills,
    }


def _poc_script_from_finding(finding: dict, lab_status: dict) -> str:
    """Best-effort shell snippet that re-runs a proven PoC inside the lab."""
    poc = finding.get("poc") or {}
    if isinstance(poc, str) and poc.strip():
        return poc
    cmds = []
    if isinstance(poc, dict):
        if poc.get("commands"):
            raw = poc["commands"]
            if isinstance(raw, list):
                cmds = [str(c) for c in raw]
            else:
                cmds = [str(raw)]
        elif poc.get("sql"):
            host = poc.get("host") or lab_status.get("host") or "127.0.0.1"
            port = poc.get("port") or lab_status.get("port") or ""
            cmds = [f"echo {poc.get('sql')!r}  # mysql {host}:{port}"]
    evidence = finding.get("lab_evidence") or []
    if not cmds and evidence:
        ev = evidence[0] if isinstance(evidence, list) else evidence
        if isinstance(ev, dict) and ev.get("command"):
            cmds = [str(ev["command"])]
    return "\n".join(cmds)


def _looks_like_repro_output(out: str) -> bool:
    o = (out or "").lower()
    needles = (
        "vulnerable", "uid=", "root:x:0:0", "cmd subcommands",
        "lost connection", "lotus_poc_impact", "progressive_merge",
        "kill_ok", "create database", "admincommandresponse",
        "triggered", "proven",
    )
    return any(n in o for n in needles)


async def measure_pocs_and_fixes(
    repo_id: int,
    dest: Path,
    confirmed: List[dict],
    lab_status: dict,
    *,
    language: str = "",
    send: Optional[Callable] = None,
    max_findings: int = 5,
) -> List[Dict[str, Any]]:
    """Re-run proven PoCs for timing; try ranked-fix apply when BEFORE/AFTER exist."""
    from backend.fix_suggestions import propose_fixes
    from backend.fix_verifier import verify_fix_in_lab
    from backend import lab as lab_mod

    results: List[Dict[str, Any]] = []
    if not lab_status.get("healthy") and not lab_mod.get_lab_container(repo_id):
        return results

    for finding in confirmed[:max_findings]:
        title = finding.get("title") or "finding"
        rec: Dict[str, Any] = {"title": title, "quality": "inconclusive", "verdict": ""}
        try:
            fixes = propose_fixes(finding)
            rec["bug_class"] = fixes.get("bug_class")
            rec["recommended"] = (fixes.get("options") or [{}])[0].get("title")
            finding["suggested_fixes"] = fixes
        except Exception as e:
            rec["verdict"] = f"fix catalog skipped: {e}"

        poc_script = _poc_script_from_finding(finding, lab_status)
        before_snip = finding.get("fix_before") or finding.get("before") or ""
        after_snip = finding.get("fix_after") or finding.get("after") or ""
        file_path = finding.get("file") or ""

        if before_snip and after_snip and file_path:
            try:
                v = await verify_fix_in_lab(
                    repo_id,
                    file=file_path,
                    before=before_snip,
                    after=after_snip,
                    repro_poc=poc_script,
                    test=finding.get("fix_test") or "",
                    test_lang=finding.get("fix_test_lang") or ("ruby" if "ruby" in language else "python"),
                    lang=language,
                    keep_applied=False,
                )
                rec.update({
                    "quality": v.get("quality"),
                    "verdict": v.get("verdict"),
                    "metrics": v.get("metrics"),
                    "applied": v.get("applied"),
                    "vulnerable_before": v.get("vulnerable_before"),
                    "blocked_after": v.get("blocked_after"),
                })
            except Exception as e:
                rec["verdict"] = f"verify_fix_in_lab error: {e}"
        elif poc_script:
            try:
                import time as _t
                t0 = _t.perf_counter()
                out = await lab_mod.exec_in_lab(repo_id, poc_script, timeout=45)
                ms = int((_t.perf_counter() - t0) * 1000)
                blob = (out.get("stdout") or "") + "\n" + (out.get("stderr") or "")
                rec["metrics"] = {"poc_remeasure_ms": ms}
                rec["vulnerable_before"] = _looks_like_repro_output(blob) or bool(finding.get("proven_in_lab"))
                rec["quality"] = "measured"
                rec["verdict"] = (
                    f"PoC remeasured in {ms}ms; no BEFORE/AFTER snippet so patch was not applied. "
                    f"Suggested: {rec.get('recommended') or 'see ranked fixes'}."
                )
            except Exception as e:
                rec["verdict"] = f"PoC remeasure skipped: {e}"
        else:
            rec["verdict"] = (
                f"No executable PoC snippet; ranked fix is {rec.get('recommended') or 'catalog generic'}. "
                "Use POST /api/reports/{id}/fix/verify with before/after to measure a patch."
            )
        results.append(rec)
        if send:
            await send(
                repo_id,
                f"Fix/PoC measure: {title[:60]} → {rec.get('quality')} "
                f"{(rec.get('verdict') or '')[:80]}",
                level="info",
            )
    return results
