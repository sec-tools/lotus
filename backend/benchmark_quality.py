"""Bug-discovery QUALITY benchmark.

Measures how good Lotus is at bug discovery/triage against **labeled ground truth**:
precision / recall / F1 (true/false positives and negatives), confirmation quality,
status-accuracy (does it correctly score DoS as latent instead of over-claiming RCE?),
report completeness, and skill-compounding gains across runs.

Why this exists
---------------
The pre-existing metrics (`benchmark.compute_audit_metrics`, `measure_discovery_
effectiveness`) only report lead counts and a conversion-rate proxy. They cannot say
"we missed a real bug" (false negative) or "we over-claimed" (false positive), because
nothing is compared to labeled ground truth. This module closes that gap.

Design
------
- Ground truth lives in JSON manifests (`benchmark_data/ground_truth/*.json`) with two
  label kinds:
    * `true_positive`  - a real bug the audit SHOULD find (recall), with the status a
      high-quality audit should assign (e.g. a DoS is `latent`, never RCE-`report-eligible`).
    * `known_safe`     - a lookalike / unreachable crash that must NOT be reported
      (precision). e.g. BlazingMQ's Event::Initialize assertion is unreachable in prod.
- Manifests declare `completeness`: `complete` (every real bug labeled - used for the
  self-contained seeded fixture, so full precision/recall is meaningful) or `partial`
  (real OSS repos where we only label KNOWN bugs/safe-spots - we then report recall over
  known TPs and precision-on-known-safe, and never punish unlabeled findings as FPs).
- Matching uses the unified `ontology` (canonical class) + file/line, so historical
  class-name drift doesn't corrupt scoring.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend import ontology

LINE_TOLERANCE = 25  # lines of slack when both finding and GT cite a line


# ---------------------------------------------------------------------------
# Manifest schema
# ---------------------------------------------------------------------------
@dataclass
class GroundTruthItem:
    id: str
    bug_class: str                 # will be normalized via ontology
    file: str
    label: str = "true_positive"   # true_positive | known_safe
    line: Optional[int] = None
    sink_hint: str = ""
    expected_status: str = ontology.STATUS_REPORT_ELIGIBLE  # what a good audit concludes
    cvss_max: float = 10.0
    provenance: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    @property
    def canonical_class(self) -> str:
        return ontology.normalize(self.bug_class, self.sink_hint, self.notes)


@dataclass
class Manifest:
    repo: str
    source: str
    language: str
    completeness: str = "partial"        # complete | partial
    commit: str = ""
    ground_truth: List[GroundTruthItem] = field(default_factory=list)

    @property
    def true_positives(self) -> List[GroundTruthItem]:
        return [g for g in self.ground_truth if g.label == "true_positive"]

    @property
    def known_safe(self) -> List[GroundTruthItem]:
        return [g for g in self.ground_truth if g.label == "known_safe"]


def load_manifest(path: str) -> Manifest:
    data = json.loads(Path(path).read_text())
    gts = [GroundTruthItem(**g) for g in data.get("ground_truth", [])]
    return Manifest(
        repo=data["repo"], source=data.get("source", ""), language=data.get("language", ""),
        completeness=data.get("completeness", "partial"), commit=data.get("commit", ""),
        ground_truth=gts,
    )


def manifest_dir() -> Path:
    return Path(__file__).resolve().parent / "benchmark_data" / "ground_truth"


# ---------------------------------------------------------------------------
# Finding normalization (findings persist location inside `description`)
# ---------------------------------------------------------------------------
_FILE_RE = re.compile(r"file=([^\s|]+)")
_LINE_RE = re.compile(r":(\d+)\b")


def normalize_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the fields the scorer needs from a DB/pipeline finding dict."""
    desc = str(f.get("description") or "")
    file_ = str(f.get("file") or "")
    line = f.get("line")
    if not file_:
        m = _FILE_RE.search(desc)
        if m:
            file_ = m.group(1)
    if line is None and file_ and ":" in file_:
        head, _, rest = file_.partition(":")
        if rest.split(":")[0].isdigit():
            line = int(rest.split(":")[0]); file_ = head
    if line is None:
        m = _LINE_RE.search(file_ or desc)
        if m:
            try:
                line = int(m.group(1))
            except ValueError:
                line = None
    status = str(f.get("status") or "unproven")
    report_eligible = bool(f.get("report_eligible") or status == "report-eligible")
    confirmed = bool(f.get("proven_in_lab") or f.get("confirmed")
                     or "proven_in_lab=true" in desc or report_eligible)
    return {
        "title": str(f.get("title") or ""),
        "file": os.path.basename(file_) if file_ else "",
        "file_full": file_,
        "line": line,
        "class": ontology.classify_finding(f),
        "status": status,
        "report_eligible": report_eligible,
        "confirmed": confirmed,
        "cvss": float(f.get("cvss") or 0.0),
        "_raw": f,
    }


def _loc_match(gt: GroundTruthItem, nf: Dict[str, Any]) -> bool:
    if not gt.file or not nf["file"]:
        return False
    if os.path.basename(gt.file) != nf["file"]:
        return False
    if gt.line and nf["line"]:
        return abs(gt.line - nf["line"]) <= LINE_TOLERANCE
    return True  # file-level match when a line isn't pinned on both sides


def _status_ok(gt: GroundTruthItem, nf: Dict[str, Any]) -> Tuple[bool, str]:
    """Did the audit assign a status consistent with the expected one?"""
    want = gt.expected_status
    got = nf["status"]
    if want == got:
        return True, ""
    # DoS/latent must NOT be escalated to report-eligible.
    report_like = {ontology.STATUS_REPORT_ELIGIBLE}
    latent_like = {ontology.STATUS_LATENT, ontology.STATUS_BELOW_THRESHOLD, "unproven"}
    if want in latent_like and got in report_like:
        return False, "over-escalated (claimed report-eligible for a latent/DoS issue)"
    if want in report_like and got in latent_like:
        return False, "under-escalated (real report-eligible bug left unproven/latent)"
    return True, ""  # both non-report-eligible variants: acceptable


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
@dataclass
class ScoreResult:
    repo: str
    completeness: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    known_safe_violations: int = 0
    over_escalations: int = 0
    under_escalations: int = 0
    confirmed_tp: int = 0
    n_labeled_tp: int = 0
    n_known_safe: int = 0
    matched: List[Dict[str, Any]] = field(default_factory=list)
    missed: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    safe_violations: List[Dict[str, Any]] = field(default_factory=list)
    by_class: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def surface_only(self) -> bool:
        return self.n_labeled_tp == 0 and self.n_known_safe == 0

    @property
    def precision(self) -> Optional[float]:
        d = self.tp + self.fp
        if d:
            return round(self.tp / d, 3)
        if self.completeness == "complete":
            return 1.0
        if self.n_known_safe:
            return 1.0  # avoided every labeled lookalike; unlabeled leads not counted
        return None

    @property
    def recall(self) -> Optional[float]:
        d = self.tp + self.fn
        return round(self.tp / d, 3) if d else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None:
            return None
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0

    @property
    def confirmation_rate(self) -> Optional[float]:
        return round(self.confirmed_tp / self.tp, 3) if self.tp else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": self.repo, "completeness": self.completeness,
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "n_labeled_tp": self.n_labeled_tp, "n_known_safe": self.n_known_safe,
            "surface_only": self.surface_only,
            "precision": self.precision, "recall": self.recall, "f1": self.f1,
            "grade": _grade(self.f1),
            "known_safe_violations": self.known_safe_violations,
            "over_escalations": self.over_escalations,
            "under_escalations": self.under_escalations,
            "confirmed_tp": self.confirmed_tp, "confirmation_rate": self.confirmation_rate,
            "missed": self.missed, "false_positives": self.false_positives,
            "safe_violations": self.safe_violations, "by_class": self.by_class,
        }


def score(findings: List[Dict[str, Any]], manifest: Manifest,
          *, report_eligible_only: bool = True) -> ScoreResult:
    """Score reported findings against a ground-truth manifest.

    report_eligible_only:
      - True  (full-scan mode): precision/FP consider only report-eligible findings  - i.e.
        the product's actual reported output.
      - False (recon mode): every surfaced lead counts, so we measure the discovery +
        tier-0 prefilter layer's precision (a lead landing on a known-safe / test / vendor
        spot is a discovery false positive).
    """
    res = ScoreResult(repo=manifest.repo, completeness=manifest.completeness,
                      n_labeled_tp=len(manifest.true_positives),
                      n_known_safe=len(manifest.known_safe))
    nfs = [normalize_finding(f) for f in findings]
    used = [False] * len(nfs)

    def _bump(cls: str, key: str):
        res.by_class.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})
        res.by_class[cls][key] += 1

    # 1) Recall: each true-positive GT item must be matched by >=1 finding.
    for gt in manifest.true_positives:
        gclass = gt.canonical_class
        hit_idx = -1
        for i, nf in enumerate(nfs):
            if used[i]:
                continue
            if ontology.classes_match(gclass, nf["class"]) and _loc_match(gt, nf):
                hit_idx = i
                break
        if hit_idx >= 0:
            nf = nfs[hit_idx]
            used[hit_idx] = True
            res.tp += 1
            _bump(gclass, "tp")
            if nf["confirmed"]:
                res.confirmed_tp += 1
            # Status-accuracy only makes sense for the final reported output (full scan).
            # In recon mode leads are legitimately 'unproven' (no lab yet), so skip it.
            why = ""
            if report_eligible_only:
                ok, why = _status_ok(gt, nf)
                if not ok and "over-escalated" in why:
                    res.over_escalations += 1
                elif not ok and "under-escalated" in why:
                    res.under_escalations += 1
            res.matched.append({"gt": gt.id, "class": gclass, "file": gt.file,
                                 "finding": nf["title"], "status": nf["status"],
                                 "confirmed": nf["confirmed"], "status_note": why})
        else:
            res.fn += 1
            _bump(gclass, "fn")
            res.missed.append({"gt": gt.id, "class": gclass, "file": gt.file,
                               "line": gt.line, "sink": gt.sink_hint, "notes": gt.notes})

    # 2) Precision on known-safe: a report-eligible finding matching a known-safe item is
    #    an over-claim (false positive of the worst kind).
    for gt in manifest.known_safe:
        gclass = gt.canonical_class
        for i, nf in enumerate(nfs):
            if used[i]:
                continue
            if ontology.classes_match(gclass, nf["class"]) and _loc_match(gt, nf):
                if nf["report_eligible"] or not report_eligible_only:
                    res.known_safe_violations += 1
                    res.fp += 1
                    _bump(gclass, "fp")
                    res.safe_violations.append({"gt": gt.id, "file": gt.file,
                                                "finding": nf["title"], "why": gt.notes})
                    used[i] = True

    # 3) Remaining report-eligible findings.
    #    - complete manifest: any unmatched report-eligible finding is a false positive.
    #    - partial manifest: we can't label unknown findings, so we don't punish them
    #      (recorded as `unlabeled` for transparency, not counted in precision).
    for i, nf in enumerate(nfs):
        if used[i]:
            continue
        if report_eligible_only and not nf["report_eligible"]:
            continue
        if manifest.completeness == "complete":
            res.fp += 1
            _bump(nf["class"], "fp")
            res.false_positives.append({"finding": nf["title"], "class": nf["class"],
                                        "file": nf["file_full"], "line": nf["line"]})
        else:
            res.false_positives.append({"finding": nf["title"], "class": nf["class"],
                                        "file": nf["file_full"], "line": nf["line"],
                                        "unlabeled": True})
    return res


# ---------------------------------------------------------------------------
# Report-quality rubric
# ---------------------------------------------------------------------------
_RUBRIC = [
    ("clean_title", lambda md: "## Finding " not in md, "titles are clean (no 'Finding N:')"),
    ("repo_label", lambda md: "**Repo**:" in md or "**Repo:**" in md, "executive summary uses Repo (not full URL)"),
    ("environment", lambda md: "Environment tested" in md, "environment tested is documented"),
    ("root_cause", lambda md: "### Root Cause" in md, "root cause section present"),
    ("code_snippet", lambda md: "Vulnerable code" in md or "```" in md, "code snippet present"),
    ("flow_diagram", lambda md: "UNTRUSTED SOURCE" in md and "SECURITY SINK" in md, "ASCII data-flow diagram"),
    ("evidence", lambda md: "### Evidence" in md and "Untrusted source" in md, "complete evidence"),
    ("manual_repro", lambda md: "Manual steps" in md, "manual reproduction steps"),
    ("poc_script", lambda md: "PoC script" in md, "runnable PoC script"),
    ("confirmation", lambda md: "Confirmation — proof of issue" in md, "confirmation proof section"),
    ("fixes", lambda md: "#### Fix 1" in md, "at least one concrete fix"),
    ("fix_test", lambda md: "Regression test for the fix" in md, "fix ships a test"),
    ("fix_proof", lambda md: "Proof the fix works" in md, "fix ships a lab proof"),
    ("fix_metrics", lambda md: "Metrics (before → after)" in md, "fix ships before/after metrics"),
    ("verify_action", lambda md: "verifyfix:" in md or "Apply" in md, "one-click apply&verify action"),
]


def report_quality(markdown: str) -> Dict[str, Any]:
    """Score a generated report's completeness against the quality rubric."""
    md = markdown or ""
    checks = {}
    passed = 0
    for key, fn, _desc in _RUBRIC:
        ok = bool(fn(md))
        checks[key] = ok
        passed += 1 if ok else 0
    total = len(_RUBRIC)
    return {"score_pct": round(100 * passed / total, 1), "passed": passed,
            "total": total, "checks": checks,
            "missing": [d for k, _f, d in _RUBRIC if not checks[k]]}


# ---------------------------------------------------------------------------
# Scorecard rendering
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Headless runners
# ---------------------------------------------------------------------------
def run_recon_findings(repo_dir: str, language: Optional[str] = None,
                       apply_tier0: bool = True) -> List[Dict[str, Any]]:
    """Deterministic Phase-1 discovery on a local repo dir (no AI / no Docker).

    Runs the pure-Python detector battery (grep patterns, methodology patterns, high-yield
    discovery) and the tier-0 false-positive prefilter, exactly as the pipeline seeds
    Phase 1. This lets us measure DISCOVERY recall + static FP-elimination deterministically
    and reproducibly. (Lab-proof confirmation still requires a full scan.)
    """
    from pathlib import Path as _P
    from backend.pipeline import detect_language, run_grep_patterns, run_advanced_patterns
    from backend.discovery_engine import run_high_yield_discovery
    dest = _P(repo_dir)
    primary = language or detect_language(dest)
    # Run the pattern detectors for EVERY language actually present in the tree, not just
    # the single primary language. Single-language detection is a real false-negative
    # source for polyglot repos; the benchmark should exercise full coverage.
    _ext_lang = {".py": "python", ".rb": "ruby/rails", ".js": "node", ".ts": "node",
                 ".java": "java", ".php": "php", ".go": "go",
                 ".c": "c/cpp", ".cc": "c/cpp", ".cpp": "c/cpp", ".h": "c/cpp", ".hpp": "c/cpp"}
    langs = {primary}
    try:
        for p in dest.rglob("*"):
            if p.is_file() and p.suffix.lower() in _ext_lang:
                langs.add(_ext_lang[p.suffix.lower()])
    except Exception:
        pass
    findings: List[Dict[str, Any]] = []
    for lang in langs:
        for fn in (lambda l=lang: run_grep_patterns(dest, 0, l),
                   lambda l=lang: run_advanced_patterns(dest, 0, l)):
            try:
                findings.extend(fn() or [])
            except Exception:
                pass
    try:
        hy, _meta = run_high_yield_discovery(dest, primary)
        findings.extend(hy or [])
    except Exception:
        pass
    try:
        from backend.analyzers.high_severity import collect_high_severity
        from backend.severity_policy import apply_severity_policy
        from backend.analyzers.test_oracles import collect_test_oracles
        hs, _tr = collect_high_severity(dest, primary)
        findings.extend(hs or [])
        findings.extend(collect_test_oracles(dest, primary) or [])
        findings = apply_severity_policy(findings)
    except Exception:
        pass
    # Generated evidence under ``.lotus`` is platform metadata, not target code.
    # Excluding it here prevents a previous audit's trace from contaminating a
    # subsequent benchmark (and mirrors the production scan boundary).
    from backend.finding_utils import deduplicate_observations, is_generated_audit_artifact
    findings = [f for f in findings if not is_generated_audit_artifact(f.get("file"))]
    # Detectors intentionally overlap.  Collapse same-location/same-class
    # observations while retaining all detector provenance for diagnostics.
    findings = deduplicate_observations(findings)
    if apply_tier0:
        try:
            from backend.tier0_filter import tier0_prefilter
            kept, _dropped = tier0_prefilter(findings)
            findings = kept
        except Exception:
            pass
    return findings


def benchmark_repo_recon(repo_dir: str, manifest_path: str,
                         language: Optional[str] = None) -> Tuple[ScoreResult, List[Dict[str, Any]]]:
    """Deterministic recon-mode benchmark: run Phase-1 discovery on a local clone and score
    the leads against the manifest. Returns (ScoreResult, findings)."""
    manifest = load_manifest(manifest_path)
    t0 = time.perf_counter()
    findings = run_recon_findings(repo_dir, language=language or manifest.language or None)
    res = score(findings, manifest, report_eligible_only=False)
    res._elapsed_s = round(time.perf_counter() - t0, 2)  # type: ignore[attr-defined]
    return res, findings


def collect_db_findings(repo_id: int, db_factory, finding_cls) -> List[Dict[str, Any]]:
    """Collect persisted findings for a scanned repo (full-scan mode)."""
    db = db_factory()
    try:
        rows = db.query(finding_cls).filter(finding_cls.repo_id == repo_id).all()
        return [{
            "title": r.title, "cvss": r.cvss, "status": r.status,
            "report_eligible": r.report_eligible, "description": r.description,
            "ai_response": r.ai_response,
        } for r in rows]
    finally:
        db.close()


def measure_compounding(repo_dir: str, manifest_path: str,
                        language: Optional[str] = None) -> Dict[str, Any]:
    """Run recon twice. Delta in learned-skills / recall / wall-clock is the compounding signal.

    Recon itself does not write skills (that's a full-scan behavior). On a cold skills dir
    the delta is expected to be 0 — that's an honest measurement, not a failure. After a
    real scan that persisted skills, run 2 should show skill growth and (ideally) faster
    or higher-recall discovery.
    """
    manifest = load_manifest(manifest_path)
    lang = language or manifest.language or None
    skills_before = count_learned_skills()
    t0 = time.perf_counter()
    f1 = run_recon_findings(repo_dir, language=lang)
    r1 = score(f1, manifest, report_eligible_only=False)
    t1 = time.perf_counter() - t0
    t0 = time.perf_counter()
    f2 = run_recon_findings(repo_dir, language=lang)
    r2 = score(f2, manifest, report_eligible_only=False)
    t2 = time.perf_counter() - t0
    skills_after = count_learned_skills()
    r1r, r2r = r1.recall, r2.recall
    return {
        "skills_before": skills_before,
        "skills_after": skills_after,
        "skills_delta": skills_after - skills_before,
        "recall_1": r1r,
        "recall_2": r2r,
        "recall_delta": None if r1r is None or r2r is None else round(r2r - r1r, 3),
        "time_1": round(t1, 2),
        "time_2": round(t2, 2),
        "time_delta": round(t2 - t1, 2),
        "result": r2,
        "findings": f2,
    }


def count_learned_skills(skills_dir: Optional[str] = None) -> int:
    """Count learned skill files (for compounding measurement)."""
    base = skills_dir or os.environ.get(
        "LOTUS_SKILLS_DIR",
        str(Path(__file__).resolve().parent.parent / "data" / "skills"))
    learned = Path(base) / "learned"
    if not learned.is_dir():
        return 0
    return len([p for p in learned.glob("*.md")])


def _grade(f1: Optional[float]) -> str:
    if f1 is None:
        return "N/A"
    return ("A" if f1 >= 0.9 else "B" if f1 >= 0.75 else "C" if f1 >= 0.6
            else "D" if f1 >= 0.4 else "F")


def _fmt(v: Any) -> str:
    return "n/a" if v is None else str(v)


def render_scorecard(result: ScoreResult, *, report_q: Optional[Dict] = None,
                     compounding: Optional[Dict] = None, elapsed_s: Optional[float] = None) -> str:
    r = result
    elapsed = elapsed_s if elapsed_s is not None else getattr(r, "_elapsed_s", None)
    lines = [
        f"# Bug-Discovery Quality Scorecard — {r.repo}",
        "",
        f"_Manifest completeness: **{r.completeness}**"
        + (f" · wall-clock: {elapsed:.1f}s" if elapsed is not None else "") + "_",
        "",
        "## Detection quality (vs labeled ground truth)",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Grade (by F1) | **{_grade(r.f1)}** |",
        f"| Precision | {_fmt(r.precision)} |",
        f"| Recall | {_fmt(r.recall)} |",
        f"| F1 | {_fmt(r.f1)} |",
        f"| True positives | {r.tp} / {r.n_labeled_tp} labeled |",
        f"| False negatives (missed) | {r.fn} |",
        f"| False positives | {r.fp} |",
        f"| Known-safe over-claims | {r.known_safe_violations} |",
        f"| Over-escalations (latent→RCE) | {r.over_escalations} |",
        f"| Under-escalations (real→unproven) | {r.under_escalations} |",
        f"| Confirmation rate (lab-proven TPs) | {_fmt(r.confirmation_rate)} |",
        "",
    ]
    if r.tp and (r.confirmation_rate == 0 or r.confirmation_rate == 0.0):
        lines += [
            "> _Confirmation rate is 0 in recon mode. Leads are unproven until a full lab scan._",
            "",
        ]
    if r.surface_only:
        lines += [
            "> _Surface-only: this manifest has no labeled true-positives or known-safe "
            "items. Precision/recall are **not** reported (they would be vacuously 1.0). "
            "Populate `ground_truth` from advisories or confirmed findings before scoring._",
            "",
        ]
    elif r.completeness == "partial":
        lines += [
            "> _Partial manifest: recall is over KNOWN true-positives and precision reflects "
            "known-safe over-claims; unlabeled report-eligible findings are listed for review, "
            "not counted as false positives._",
            "",
        ]
    if r.missed:
        lines += ["### Missed bugs (false negatives)", ""]
        for m in r.missed:
            lines.append(f"- `{m['class']}` in `{m['file']}`"
                         + (f":{m['line']}" if m.get('line') else "")
                         + (f" — {m['notes']}" if m.get('notes') else ""))
        lines.append("")
    if r.safe_violations:
        lines += ["### Known-safe over-claims (precision failures)", ""]
        for s in r.safe_violations:
            lines.append(f"- `{s['file']}` — reported \"{s['finding']}\" but: {s['why']}")
        lines.append("")
    if r.false_positives:
        header = "Unlabeled report-eligible findings (review)" if r.completeness == "partial" else "False positives"
        lines += [f"### {header}", ""]
        for fp in r.false_positives[:25]:
            lines.append(f"- `{fp.get('class')}` — {fp.get('finding')} (`{fp.get('file')}`"
                         + (f":{fp.get('line')}" if fp.get('line') else "") + ")")
        lines.append("")
    if r.by_class:
        lines += ["### By bug class", "", "| Class | TP | FP | FN |", "|-------|----|----|----|"]
        for cls, c in sorted(r.by_class.items()):
            lines.append(f"| {cls} | {c['tp']} | {c['fp']} | {c['fn']} |")
        lines.append("")
    if report_q:
        lines += [
            "## Report quality (completeness rubric)",
            "",
            f"**{report_q['score_pct']}%** ({report_q['passed']}/{report_q['total']} checks).",
            "",
        ]
        if report_q["missing"]:
            lines.append("Missing: " + ", ".join(report_q["missing"]))
            lines.append("")
    if compounding:
        lines += [
            "## Skill compounding (run 1 → run 2)",
            "",
            "| Metric | Run 1 | Run 2 | Δ |",
            "|--------|-------|-------|---|",
            f"| Learned skills | {compounding.get('skills_before', 0)} | {compounding.get('skills_after', 0)} | +{compounding.get('skills_delta', 0)} |",
            f"| Recall | {_fmt(compounding.get('recall_1'))} | {_fmt(compounding.get('recall_2'))} | {_fmt(compounding.get('recall_delta'))} |",
            f"| Wall-clock (s) | {_fmt(compounding.get('time_1'))} | {_fmt(compounding.get('time_2'))} | {_fmt(compounding.get('time_delta'))} |",
            "",
        ]
        if not compounding.get("skills_delta"):
            lines += [
                "_Recon does not persist learned skills, so Δ=0 is expected here. "
                "Skill growth and recall lift are full-scan signals._",
                "",
            ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Target resolution + public runner
# ---------------------------------------------------------------------------
_SEEDED_NAMES = {"seeded-fixture", "seeded_fixture", "seeded", "fixture"}
_TARGET_ALIASES = {
    "pdf-reader": ["pdf-reader", "pdf_reader", "yob-pdf-reader"],
    "blazingmq": ["blazingmq", "bloomberg-blazingmq"],
    "seekdb": ["seekdb", "oceanbase-seekdb"],
}


def fixture_dir() -> Path:
    return Path(__file__).resolve().parent / "benchmark_data" / "seeded_fixture"


def e2e_targets_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "e2e_targets"


def list_manifest_ids() -> List[str]:
    return sorted(p.stem for p in manifest_dir().glob("*.json"))


def resolve_target(name: str) -> Tuple[Path, Path]:
    """Return (repo_dir, manifest_path).

    Raises ValueError for unknown names, FileNotFoundError if an OSS clone is missing.
    The seeded fixture is always on-disk next to this module.
    """
    raw = (name or "").strip()
    slug = raw.lower().replace("_", "-")
    md = manifest_dir()
    if slug in _SEEDED_NAMES:
        return fixture_dir(), md / "seeded_fixture.json"
    manifest = None
    for candidate in (raw, slug, slug.replace("-", "_"), raw.replace("-", "_")):
        p = md / f"{candidate}.json"
        if p.exists():
            manifest = p
            break
    if manifest is None:
        raise ValueError(f"Unknown quality-benchmark target '{name}'. Known: {list_manifest_ids()}")
    repo_key = manifest.stem.lower().replace("_", "-")
    aliases = _TARGET_ALIASES.get(repo_key, [manifest.stem, repo_key, manifest.stem.replace("-", "_")])
    roots = [e2e_targets_dir(), Path.cwd() / "data" / "e2e_targets"]
    for root in roots:
        for alias in aliases:
            cand = root / alias
            if cand.is_dir():
                return cand, manifest
    raise FileNotFoundError(
        f"Clone for '{manifest.stem}' not found under data/e2e_targets/ (tried {aliases}). "
        f"The seeded fixture is always available as target=seeded_fixture."
    )


def available_targets() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for mid in list_manifest_ids():
        try:
            repo, man = resolve_target(mid)
            out.append({"id": mid, "available": True, "repo_dir": str(repo), "manifest": str(man)})
        except FileNotFoundError as e:
            out.append({"id": mid, "available": False, "reason": str(e)})
        except ValueError as e:
            out.append({"id": mid, "available": False, "reason": str(e)})
    return out


def run_quality_benchmark(target: str = "seeded_fixture", *,
                          compound: bool = True,
                          language: Optional[str] = None) -> Dict[str, Any]:
    """Run recon-mode scoring for one target. Returns a JSON-serializable payload.

    This measures Phase-1 discovery + tier-0 FP elimination against labeled ground
    truth. Lab-proof confirmation still requires a full scan (AI keys + Docker).
    """
    repo_dir, manifest_path = resolve_target(target)
    manifest = load_manifest(str(manifest_path))
    compounding: Optional[Dict[str, Any]] = None
    t0 = time.perf_counter()
    if compound:
        raw = measure_compounding(str(repo_dir), str(manifest_path), language=language)
        res: ScoreResult = raw["result"]
        findings = raw["findings"]
        compounding = {k: v for k, v in raw.items() if k not in ("result", "findings")}
    else:
        res, findings = benchmark_repo_recon(str(repo_dir), str(manifest_path), language=language)
    elapsed = round(time.perf_counter() - t0, 2)
    res._elapsed_s = elapsed  # type: ignore[attr-defined]
    md = render_scorecard(res, compounding=compounding, elapsed_s=elapsed)
    return {
        "target": manifest.repo,
        "mode": "recon",
        "note": (
            "Labeled TP/FP/FN vs ground truth (recon leads, not lab-confirmed). "
            "GET /api/benchmark/metrics is a conversion-rate proxy and is not precision/recall."
        ),
        "grade": _grade(res.f1),
        "elapsed_s": elapsed,
        "n_findings": len(findings),
        "surface_only": res.surface_only,
        "result": res.to_dict(),
        "compounding": compounding,
        "scorecard_md": md,
        "manifest": str(manifest_path),
        "repo_dir": str(repo_dir),
    }


def _cli(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        description="Lotus bug-discovery quality benchmark (labeled precision/recall).")
    p.add_argument("--target", default="seeded_fixture",
                   help="seeded_fixture | pdf-reader | blazingmq | seekdb")
    p.add_argument("--all", action="store_true",
                   help="Run every target whose clone (or seeded fixture) is present.")
    p.add_argument("--compound", action="store_true", default=True)
    p.add_argument("--no-compound", action="store_false", dest="compound")
    p.add_argument("--out", default="",
                   help="Write concatenated markdown scorecard(s) to this path.")
    args = p.parse_args(argv)
    names = list_manifest_ids() if args.all else [args.target]
    cards: List[str] = []
    skips: List[str] = []
    status = 0
    for name in names:
        try:
            payload = run_quality_benchmark(name, compound=args.compound)
        except FileNotFoundError as e:
            print(f"SKIP {name}: {e}")
            skips.append(f"- `{name}`: {e}")
            continue
        except ValueError as e:
            print(f"ERR  {name}: {e}")
            status = 2
            continue
        print(payload["scorecard_md"])
        print()
        cards.append(payload["scorecard_md"])
    if args.out and (cards or skips):
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "# Lotus bug-discovery quality scorecards\n\n"
            "Recon-mode (Phase-1 detectors + tier-0 prefilter) against labeled "
            "ground truth. Distinct from `GET /api/benchmark/metrics`, which is a "
            "conversion-rate proxy and cannot report false negatives.\n\n"
            "OSS clones under `data/e2e_targets/` are scored when present; "
            "the seeded fixture is always runnable. Empty-GT repos are **surface-only** "
            "(precision/recall are not reported as 1.0).\n\n"
            "## Ground-truth doctrine (no fabricated CVEs)\n\n"
            "- **seeded_fixture** — complete labels. `os.system` + `eval` in "
            "`app/exec_handler.py` and Ruby `instance_eval` in `lib/parser.rb` must be "
            "found; `tests/` and `vendor/` lookalikes must not.\n"
            "- **pdf-reader** — no CVEs. PR #567 (`Page#ancestors` loop) and issue #450 "
            "(tokenizer hang) are DoS-only: score **latent**, never RCE-report-eligible.\n"
            "- **blazingmq** — no public CVE. PR #1582 fuzz crash in `bmqp_event.h` "
            "`Event::initialize` is unreachable in production (framing layer). Label "
            "**known_safe**: a high-quality audit must not report it.\n"
            "- **seekdb** — template, empty `ground_truth`. Surface-only until advisories "
            "or confirmed findings are labeled.\n\n"
            "Run: `PYTHONPATH=. python -m backend.benchmark_quality --all --out docs/QUALITY_SCORECARD.md`\n"
            "API: `GET /api/benchmark/quality?target=seeded_fixture`\n\n"
        )
        if skips:
            header += "## Skipped targets\n\n" + "\n".join(skips) + "\n\n---\n\n"
        else:
            header += "---\n\n"
        outp.write_text(header + "\n\n---\n\n".join(cards) + "\n")
        print(f"Wrote {outp}")
    return status


if __name__ == "__main__":
    raise SystemExit(_cli())
