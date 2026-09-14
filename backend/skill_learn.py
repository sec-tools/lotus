"""Propose, evaluate uniqueness, and ingest earned skills.

Confirmed findings do not automatically mint a new learned skill. Each candidate
is compared against lotus-core (platform default) and already-learned skills.
Overlaps strengthen the existing skill (or a learned overlay of a default skill).
A new learned skill is written only when the proposal is unique.

AI (`AITask.SKILL_SYNTHESIS`) is used when the heuristic decision is ambiguous
or we are about to create a new file while similar skills exist. Tests and
offline scans fall back to the heuristic.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from backend import skills as skills_mod

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "for", "via", "with",
    "from", "into", "by", "at", "is", "its", "skill", "learned", "audit", "when",
    "user", "input", "without", "using", "that", "this", "over", "under",
}

BUG_FAMILIES: Dict[str, Tuple[str, ...]] = {
    "command_injection": (
        "command injection", "os.system", "subprocess", "shell=true", "rce",
        "kernel.system", "popen", "backtick", "cmdi",
    ),
    "sql_injection": (
        "sql injection", "sqli", "raw sql", "execute(", "f-string sql",
        "string concat sql",
    ),
    "xss": ("xss", "cross-site script", "innerhtml", "dangerouslysetinnerhtml"),
    "path_traversal": ("path traversal", "directory traversal", "../", "zip slip"),
    "ssrf": ("ssrf", "server-side request"),
    "xxe": ("xxe", "xml external"),
    "deserialization": (
        "deserial", "pickle.loads", "yaml.load", "marshal.load", "objectinputstream",
    ),
    "authz": (
        "authz", "authorization", "idor", "missing middleware", "skip_before_action",
        "guard bypass",
    ),
    "ssti": ("ssti", "template injection"),
    "crypto": ("jwt", "alg:none", "weak secret", "hardcoded secret"),
}

PROCESS_KINDS = {"methodology", "gating", "discovery"}
SKIP_NAME_HINTS = ("audit-retro", "disprove-", "readme")
BROAD_FAMILY_COUNT = 3

LEARNED_STRONG = 0.50
CORE_STRONG = 0.58
CREATE_SKIP_AI = 0.22
STRONG_SKIP_AI = 0.70
AI_BAND_LOW = 0.28


def _sk(*names: str):
    for n in names:
        if hasattr(skills_mod, n):
            return getattr(skills_mod, n)
    raise AttributeError(f"backend.skills missing any of {names}")


def _platform_home() -> Path:
    fn = getattr(skills_mod, "get_platform_home", None) or getattr(skills_mod, "get_platform_home")
    return fn()


def _learned_dir() -> Path:
    fn = getattr(skills_mod, "get_learned_dir", None) or getattr(skills_mod, "get_learned_dir")
    return fn()


def _tokens(text: str) -> Set[str]:
    words = re.findall(r"[a-z0-9+]{3,}", (text or "").lower())
    return {w for w in words if w not in STOPWORDS}


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _families(text: str) -> Set[str]:
    blob = (text or "").lower()
    hit = set()
    for fam, needles in BUG_FAMILIES.items():
        if any(n in blob for n in needles):
            hit.add(fam)
    return hit


def _parse_frontmatter(text: str) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    if not text.startswith("---"):
        return meta
    end = text.find("\n---", 3)
    if end < 0:
        return meta
    for line in text[3:end].splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        meta[k.strip()] = v.strip().strip('"').strip("'")
    return meta


def _heading_title(text: str, fallback: str) -> str:
    for line in text.splitlines()[:40]:
        s = line.strip()
        if s.startswith("# Skill:"):
            return s.split(":", 1)[1].strip()
        if s.startswith("# Skill:"):
            return s.split(":", 1)[1].strip()
    return fallback


def _declared_languages(meta: Dict[str, str], body: str) -> Set[str]:
    raw = " ".join([meta.get("language") or "", meta.get("languages") or ""])
    m = re.search(r"\*\*Language\*\*:\s*(.+)", body)
    if m:
        raw += " " + m.group(1)
    found = set(re.findall(
        r"(python|ruby|java|javascript|typescript|go|golang|php|c\+\+|cpp|c/cpp|rust|elixir|kotlin|swift)",
        raw.lower(),
    ))
    aliases = {
        "golang": "go", "c++": "c/cpp", "cpp": "c/cpp",
        "javascript": "js", "typescript": "js",
    }
    return {aliases.get(lang, lang) for lang in found}


def _lang_norm(language: str) -> str:
    t = (language or "").lower().strip()
    if t in ("javascript", "typescript", "node", "js"):
        return "js"
    if t in ("c", "c++", "cpp", "c/cpp"):
        return "c/cpp"
    if t in ("golang",):
        return "go"
    if t in ("ruby", "rails", "ruby/rails"):
        return "ruby"
    return t.split("/")[0] if t else ""


def _langs_compatible(finding_lang: str, skill_langs: Set[str]) -> bool:
    fl = _lang_norm(finding_lang)
    if not fl or fl in ("unknown", "any"):
        return True
    if not skill_langs:
        return True
    if fl in skill_langs:
        return True
    if len(skill_langs) >= 3:
        return True
    return False


def _kind_for_path(path: Path) -> str:
    parent = path.parent.name.lower()
    name = path.name.lower()
    if parent == "learned":
        return "learned"
    if parent in PROCESS_KINDS:
        return parent
    if parent in ("bug-classes", "bug-classes"):
        return "bug-class"
    if name.startswith("disprove-") or "disprove" in name:
        return "disprove"
    if name.startswith("audit-retro") or "retrospective" in name:
        return "retrospective"
    return parent or "general"


@dataclass
class CatalogEntry:
    path: Path
    skill_id: str
    title: str
    pack: str
    kind: str
    excerpt: str
    tokens: Set[str] = field(default_factory=set)
    families: Set[str] = field(default_factory=set)
    languages: Set[str] = field(default_factory=set)
    extends: str = ""
    broad: bool = False

    @property
    def merge_target(self) -> bool:
        if self.kind in PROCESS_KINDS or self.kind in ("disprove", "retrospective"):
            return False
        low = self.path.name.lower()
        if any(h in low for h in SKIP_NAME_HINTS):
            return False
        return True


def _skill_id_for(path: Path, meta: Dict[str, str]) -> str:
    if meta.get("id"):
        return meta["id"]
    stem = path.stem
    if "--" in stem:
        return stem.rsplit("--", 1)[0]
    return stem


def _iter_catalog_paths() -> List[Path]:
    gather = _sk("_gather_skill_files", "_gather_skill_files")
    files: List[Path] = list(gather())
    home = _platform_home()
    extras = [
        home / "methodology",
        home / "gating",
        home / "discovery",
        home / "bug-classes",
        home / "methodology",
        home / "gating",
        home / "discovery",
        home / "bug-classes",
        _learned_dir(),
    ]
    seen = {p.resolve() for p in files}
    for d in extras:
        try:
            if not d.exists():
                continue
            for f in sorted(d.glob("*.md")):
                if f.name.lower() == "readme.md":
                    continue
                if f.resolve() not in seen:
                    files.append(f)
                    seen.add(f.resolve())
        except Exception:
            continue
    return files


def catalog_skills() -> List[CatalogEntry]:
    entries: List[CatalogEntry] = []
    for path in _iter_catalog_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        meta = _parse_frontmatter(text)
        title = _heading_title(text, path.stem.replace("-", " "))
        excerpt = text[:1800]
        kind = _kind_for_path(path)
        pack = meta.get("pack") or (
            "learned" if kind == "learned" or "learned" in path.parts else "lotus-core"
        )
        fams = _families(title + "\n" + excerpt)
        entries.append(CatalogEntry(
            path=path,
            skill_id=_skill_id_for(path, meta),
            title=title,
            pack=pack,
            kind=kind,
            excerpt=excerpt,
            tokens=_tokens(title + " " + excerpt[:800]),
            families=fams,
            languages=_declared_languages(meta, text),
            extends=(meta.get("extends") or "").strip(),
            broad=len(fams) >= BROAD_FAMILY_COUNT,
        ))
    return entries


def _finding_blob(finding: dict, language: str) -> str:
    return "\n".join([
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("ai_analysis") or finding.get("ai_response") or ""),
        str(finding.get("attack_vector") or ""),
        str(finding.get("file") or finding.get("source_file") or ""),
        language,
    ])


def _score(finding: dict, language: str, entry: CatalogEntry) -> float:
    title_toks = _tokens(str(finding.get("title") or ""))
    body_toks = _tokens(_finding_blob(finding, language))
    title_j = _jaccard(title_toks, _tokens(entry.title))
    body_j = _jaccard(body_toks, entry.tokens)
    fams = _families(_finding_blob(finding, language))
    fam_bonus = 0.25 if fams and fams & entry.families else 0.0
    slug_fn = _sk("_slug", "_slug")
    fslug = slug_fn(finding.get("title") or "unknown")
    slug_bonus = 0.0
    if fslug and (fslug == entry.skill_id or fslug in entry.skill_id or entry.skill_id in fslug):
        if min(len(fslug), len(entry.skill_id)) >= 8:
            slug_bonus = 0.20
    lang_bonus = 0.05 if _langs_compatible(language, entry.languages) and entry.languages else 0.0
    score = 0.45 * title_j + 0.30 * body_j + fam_bonus + slug_bonus + lang_bonus
    if entry.broad:
        score *= 0.72
    if entry.kind in PROCESS_KINDS:
        score *= 0.4
    return min(1.0, score)


def _overlays_by_parent(catalog: Sequence[CatalogEntry]) -> Dict[str, CatalogEntry]:
    out: Dict[str, CatalogEntry] = {}
    for e in catalog:
        if e.extends:
            out[e.extends] = e
        if e.skill_id.startswith("extends-"):
            out[e.skill_id[len("extends-"):]] = e
    return out


def _rank(
    finding: dict, language: str, catalog: Sequence[CatalogEntry], *, limit: int = 8,
) -> List[Tuple[float, CatalogEntry]]:
    ranked: List[Tuple[float, CatalogEntry]] = []
    overlays = _overlays_by_parent(catalog)
    for e in catalog:
        if not e.merge_target:
            continue
        ranked.append((_score(finding, language, e), e))
    ranked.sort(key=lambda x: x[0], reverse=True)
    remapped: List[Tuple[float, CatalogEntry]] = []
    seen = set()
    for sc, e in ranked:
        target = e
        if e.kind != "learned" and e.skill_id in overlays:
            target = overlays[e.skill_id]
        key = str(target.path.resolve())
        if key in seen:
            continue
        seen.add(key)
        remapped.append((sc, target))
        if len(remapped) >= limit:
            break
    return remapped


def _heuristic_decision(
    finding: dict,
    language: str,
    ranked: Sequence[Tuple[float, CatalogEntry]],
) -> Dict[str, Any]:
    slug_fn = _sk("_slug", "_slug")
    find_fn = _sk("_find_existing_skill", "_find_existing_skill")
    slug = slug_fn(finding.get("title") or "unknown")
    existing = find_fn(slug)
    if existing is not None:
        return {
            "action": "strengthen",
            "target_path": existing,
            "target_id": slug,
            "reason": "exact learned slug match",
            "confidence": 0.99,
            "source": "heuristic",
        }
    if not ranked:
        return {
            "action": "create",
            "target_path": None,
            "target_id": "",
            "reason": "no comparable skills in the register",
            "confidence": 0.9,
            "source": "heuristic",
        }
    best_score, best = ranked[0]
    learned_like = best.kind == "learned" or best.pack == "learned" or bool(best.extends)
    core_ok = (
        best.kind == "bug-class"
        and not best.broad
        and _langs_compatible(language, best.languages)
    )
    if learned_like and best_score >= LEARNED_STRONG:
        return {
            "action": "strengthen",
            "target_path": best.path,
            "target_id": best.skill_id,
            "reason": f"overlaps learned skill {best.skill_id} (score {best_score:.2f})",
            "confidence": best_score,
            "source": "heuristic",
        }
    if core_ok and best_score >= CORE_STRONG:
        return {
            "action": "strengthen",
            "target_path": best.path,
            "target_id": best.skill_id,
            "reason": f"overlaps default skill {best.skill_id} (score {best_score:.2f})",
            "confidence": best_score,
            "source": "heuristic",
        }
    return {
        "action": "create",
        "target_path": None,
        "target_id": best.skill_id,
        "reason": f"distinct from nearest skill {best.skill_id} (score {best_score:.2f})",
        "confidence": 1.0 - best_score,
        "source": "heuristic",
        "nearest_score": best_score,
    }


def _needs_ai(decision: Dict[str, Any], ranked: Sequence[Tuple[float, CatalogEntry]]) -> bool:
    """Call AI when uniqueness is not already decided by an exact learned slug.

    Any non-empty register means a create/strengthen choice should be checked,
    unless we already matched a learned slug at ~1.0 confidence.
    """
    if float(decision.get("confidence") or 0) >= 0.99:
        return False
    if not ranked:
        return False
    if decision["action"] == "create":
        return True
    if decision["action"] == "strengthen" and float(decision.get("confidence") or 0) < STRONG_SKIP_AI:
        return True
    return False


def _parse_ai_decision(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    obj = None
    try:
        from backend.audit_planner import _extract_json_object
        obj = _extract_json_object(raw if isinstance(raw, str) else "")
    except Exception:
        obj = None
    if not isinstance(obj, dict):
        try:
            obj = json.loads(raw)
        except Exception:
            return None
    if not isinstance(obj, dict):
        return None
    action = str(obj.get("action") or obj.get("decision") or "").strip().lower()
    if action in ("merge", "overlay", "update"):
        action = "strengthen"
    if action not in ("strengthen", "create"):
        return None
    look = obj.get("look_for") or obj.get("look_for") or []
    heur = obj.get("heuristic") or obj.get("heuristics") or []
    variant = obj.get("variant") or obj.get("variants") or []
    if not isinstance(look, list):
        look = [look] if look else []
    if not isinstance(heur, list):
        heur = [heur] if heur else []
    if not isinstance(variant, list):
        variant = [variant] if variant else []
    return {
        "action": action,
        "target_id": str(obj.get("target_id") or obj.get("skill_id") or "").strip(),
        "reason": str(obj.get("reason") or obj.get("rationale") or "ai uniqueness check"),
        "confidence": float(obj.get("confidence") or 0.7),
        "look_for": [str(x) for x in look[:8] if str(x).strip()],
        "heuristic": [str(x) for x in heur[:8] if str(x).strip()],
        "variant": [str(x) for x in variant[:8] if str(x).strip()],
        "source": "ai",
    }


def _ai_uniqueness_prompt(
    finding: dict,
    language: str,
    repo_source: str,
    ranked: Sequence[Tuple[float, CatalogEntry]],
) -> str:
    cands = []
    for sc, e in ranked[:8]:
        cands.append({
            "id": e.skill_id,
            "pack": e.pack,
            "kind": e.kind,
            "title": e.title,
            "score": round(sc, 3),
            "extends": e.extends,
            "excerpt": e.excerpt[:400],
        })
    proposal = {
        "title": finding.get("title"),
        "language": language,
        "cvss": finding.get("cvss"),
        "description": (finding.get("description") or "")[:500],
        "file": finding.get("file"),
        "line": finding.get("line"),
        "repo": repo_source,
        "families": sorted(_families(_finding_blob(finding, language))),
    }
    return (
        "You evaluate whether a newly earned security-audit SKILL is unique.\n"
        "Compare the proposal against the skill register (platform default lotus-core "
        "and already-learned skills).\n"
        "If it overlaps an existing skill, strengthen that skill instead of creating a duplicate.\n"
        "If it is a genuinely new bug-class / sink / language-specific pattern, create it.\n"
        "Do NOT treat methodology/gating/discovery process docs as merge targets unless "
        "the proposal is itself a process skill.\n"
        "Broad catalogs that list many unrelated bug families should usually NOT absorb "
        "a specific new finding — prefer create unless the finding adds only evidence "
        "to that catalog.\n"
        "Never mutate lotus-core; a strengthen of a default skill becomes a learned overlay.\n"
        "No exploit payloads.\n"
        "Return ONLY JSON with keys:\n"
        '  action: "strengthen" | "create"\n'
        "  target_id: existing skill id when strengthening, else empty string\n"
        "  reason: short rationale\n"
        "  confidence: 0-1\n"
        "  look_for: string[] extra detection bullets\n"
        "  heuristic: string[] extra hunt heuristics\n"
        "  variant: string[] related variants\n\n"
        f"proposal={json.dumps(proposal, default=str)}\n"
        f"register={json.dumps(cands, default=str)}\n"
    )


def _resolve_target(target_id: str, catalog: Sequence[CatalogEntry]) -> Optional[CatalogEntry]:
    if not target_id:
        return None
    tid = target_id.strip()
    overlays = _overlays_by_parent(catalog)
    for e in catalog:
        if e.skill_id == tid or e.path.stem == tid or e.path.name == tid:
            if e.kind != "learned" and e.skill_id in overlays:
                return overlays[e.skill_id]
            return e
        if e.extends == tid:
            return e
    for e in catalog:
        if tid in e.skill_id or e.skill_id in tid:
            return e
    return None


def _evidence_fingerprint(finding: dict, repo_source: str) -> str:
    title = str(finding.get("title") or "").strip()
    f = str(finding.get("file") or finding.get("source_file") or "").strip()
    line = str(finding.get("line") or finding.get("source_line") or "").strip()
    return f"{title}|{f}|{line}|{repo_source}"


def _evidence_block(
    finding: dict,
    language: str,
    repo_source: str,
    extras: Optional[Dict[str, List[str]]] = None,
) -> str:
    extras = extras or {}
    ts = datetime.utcnow().isoformat() + "Z"
    fp = _evidence_fingerprint(finding, repo_source)
    lines = [
        f"### {finding.get('title') or 'Finding'} ({ts})",
        f"- fingerprint: `{fp}`",
        f"- repo: `{repo_source}`",
        f"- language: `{language}`",
        f"- cvss: `{finding.get('cvss', '')}`",
        f"- file: `{finding.get('file', '')}:{finding.get('line', '')}`",
        f"- tool: `{finding.get('tool', '')}`",
    ]
    desc = (finding.get("description") or "")[:400]
    if desc:
        lines.append(f"- notes: {desc}")
    for item in extras.get("look_for") or []:
        lines.append(f"- look for: {item}")
    for item in extras.get("heuristic") or []:
        lines.append(f"- heuristic: {item}")
    for item in extras.get("variant") or []:
        lines.append(f"- variant: {item}")
    return "\n".join(lines) + "\n"


def _under_platform(path: Path) -> bool:
    try:
        path.resolve().relative_to(_platform_home().resolve())
        return True
    except Exception:
        return False


def _is_learned_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(_learned_dir().resolve())
        return True
    except Exception:
        return False


def _append_section(path: Path, heading: str, block: str) -> None:
    save_rev = _sk("_save_revision", "_save_revision")
    old = path.read_text(encoding="utf-8")
    try:
        save_rev(path, old)
    except Exception:
        pass
    if heading in old:
        new = old.rstrip() + "\n" + block + "\n"
    else:
        new = old.rstrip() + f"\n\n{heading}\n\n" + block + "\n"
    path.write_text(new, encoding="utf-8")


def _write_overlay(
    parent: CatalogEntry,
    finding: dict,
    language: str,
    repo_source: str,
    extras: Optional[Dict[str, List[str]]] = None,
) -> Path:
    learned = _learned_dir()
    learned.mkdir(parents=True, exist_ok=True)
    dest = learned / f"extends-{parent.skill_id}.md"
    if dest.exists():
        fp = _evidence_fingerprint(finding, repo_source)
        existing = dest.read_text(encoding="utf-8")
        if fp not in existing:
            _append_section(dest, "## Compounded evidence", _evidence_block(
                finding, language, repo_source, extras,
            ))
        return dest
    title = parent.title or parent.skill_id
    overlay_id = f"extends-{parent.skill_id}"
    md = f"""---
pack: learned
id: {overlay_id}
extends: {parent.skill_id}
role: overlay
title: {json.dumps(title + " — field evidence")}
language: {language}
source_repo: {json.dumps(repo_source)}
learned_at: {datetime.utcnow().isoformat()}Z
---

# Skill: {title} — field evidence
# Skill: {title} — field evidence

This learned overlay strengthens `{parent.skill_id}` ({parent.pack}) without duplicating lotus-core doctrine.

## Compounded evidence

{_evidence_block(finding, language, repo_source, extras)}
"""
    dest.write_text(md, encoding="utf-8")
    prune = getattr(skills_mod, "_prune_learned_skills", None) or getattr(
        skills_mod, "_prune_learned_skills", None,
    )
    if callable(prune):
        try:
            prune()
        except Exception:
            pass
    return dest


def _record_patterns(finding: dict, language: str) -> None:
    try:
        from backend.discovery_engine import extract_patterns_from_finding, save_pattern_to_db
        pat = extract_patterns_from_finding(finding, language=language)
        if pat and pat.get("regex"):
            save_pattern_to_db(pat)
    except Exception:
        pass


def strengthen_skill(
    target: CatalogEntry,
    finding: dict,
    language: str,
    repo_source: str,
    extras: Optional[Dict[str, List[str]]] = None,
) -> Tuple[str, bool]:
    """Append evidence. Returns (path, overlay_used). Never mutates BYOS or lotus-core."""
    _record_patterns(finding, language)
    fp = _evidence_fingerprint(finding, repo_source)
    path = target.path
    learned = _is_learned_path(path) or target.kind == "learned" or bool(target.extends)
    if learned and _under_platform(path):
        try:
            if fp in path.read_text(encoding="utf-8"):
                return str(path), False
        except Exception:
            pass
        _append_section(path, "## Compounded evidence", _evidence_block(
            finding, language, repo_source, extras,
        ))
        return str(path), False
    overlay = _write_overlay(target, finding, language, repo_source, extras)
    return str(overlay), True


def evaluate_skill_proposal(
    finding: dict,
    *,
    language: str = "unknown",
    repo_source: str = "",
    ai_call: Optional[Callable[..., Any]] = None,
    catalog: Optional[List[CatalogEntry]] = None,
) -> Dict[str, Any]:
    catalog = catalog if catalog is not None else catalog_skills()
    ranked = _rank(finding, language, catalog)
    decision = _heuristic_decision(finding, language, ranked)
    extras: Dict[str, List[str]] = {"look_for": [], "heuristic": [], "variant": []}
    used_ai = False
    if ai_call is not None and _needs_ai(decision, ranked):
        try:
            raw = ai_call(_ai_uniqueness_prompt(finding, language, repo_source, ranked))
            parsed = _parse_ai_decision(raw if isinstance(raw, str) else "")
        except Exception:
            parsed = None
        if parsed:
            used_ai = True
            extras["look_for"] = parsed.get("look_for") or []
            extras["heuristic"] = parsed.get("heuristic") or []
            extras["variant"] = parsed.get("variant") or []
            if parsed["action"] == "strengthen":
                target = _resolve_target(parsed.get("target_id") or "", catalog)
                if target is None and ranked:
                    target = ranked[0][1]
                if target is not None and target.merge_target:
                    decision = {
                        "action": "strengthen",
                        "target_path": target.path,
                        "target_id": target.skill_id,
                        "reason": parsed.get("reason") or decision["reason"],
                        "confidence": parsed.get("confidence") or decision.get("confidence"),
                        "source": "heuristic+ai",
                        "target_entry": target,
                    }
            elif parsed["action"] == "create":
                if decision["action"] != "strengthen" or decision.get("confidence", 0) < 0.99:
                    decision = {
                        "action": "create",
                        "target_path": None,
                        "target_id": parsed.get("target_id") or "",
                        "reason": parsed.get("reason") or decision["reason"],
                        "confidence": parsed.get("confidence") or decision.get("confidence"),
                        "source": "heuristic+ai",
                    }
    if decision["action"] == "strengthen" and "target_entry" not in decision:
        if ranked and decision.get("target_path"):
            for _sc, e in ranked:
                if e.path == decision["target_path"] or e.skill_id == decision.get("target_id"):
                    decision["target_entry"] = e
                    break
        if "target_entry" not in decision:
            found = _resolve_target(str(decision.get("target_id") or ""), catalog)
            if found:
                decision["target_entry"] = found
            elif decision.get("target_path"):
                decision["target_entry"] = CatalogEntry(
                    path=Path(decision["target_path"]),
                    skill_id=str(decision.get("target_id") or Path(decision["target_path"]).stem),
                    title=str(finding.get("title") or ""),
                    pack="learned",
                    kind="learned",
                    excerpt="",
                )
    decision["extras"] = extras
    decision["used_ai"] = used_ai
    decision["candidates"] = [
        {"id": e.skill_id, "score": round(sc, 3), "title": e.title} for sc, e in ranked[:6]
    ]
    return decision


def ingest_learned_skill(
    finding: dict,
    language: str = "unknown",
    repo_source: str = "",
    ai_call: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Evaluate uniqueness then strengthen an existing skill or create a new learned one."""
    write_new = _sk("_write_learned_skill_file", "_write_learned_skill_file")
    catalog = catalog_skills()
    decision = evaluate_skill_proposal(
        finding, language=language, repo_source=repo_source,
        ai_call=ai_call, catalog=catalog,
    )
    extras = decision.get("extras") or {}
    if decision.get("action") == "strengthen":
        target = decision.get("target_entry")
        if target is None and decision.get("target_path"):
            target = CatalogEntry(
                path=Path(decision["target_path"]),
                skill_id=str(decision.get("target_id") or Path(decision["target_path"]).stem),
                title=str(finding.get("title") or ""),
                pack="learned",
                kind="learned",
                excerpt="",
            )
        if target is not None:
            path, overlay = strengthen_skill(
                target, finding, language, repo_source, extras,
            )
            return {
                "action": "strengthen",
                "path": path,
                "target_id": decision.get("target_id") or target.skill_id,
                "reason": decision.get("reason") or "",
                "source": decision.get("source") or "heuristic",
                "created": False,
                "overlay": overlay,
                "used_ai": bool(decision.get("used_ai")),
                "candidates": decision.get("candidates") or [],
            }
    path = write_new(finding, language=language, repo_source=repo_source)
    return {
        "action": "create",
        "path": path,
        "target_id": "",
        "reason": decision.get("reason") or "unique versus skill register",
        "source": decision.get("source") or "heuristic",
        "created": True,
        "overlay": False,
        "used_ai": bool(decision.get("used_ai")),
        "candidates": decision.get("candidates") or [],
    }


# ---------------------------------------------------------------------------
# Compatibility aliases (single naming scheme for callers + internal mix)
# ---------------------------------------------------------------------------
PROCESS_KINDS = PROCESS_KINDS
SKIP_NAME_HINTS = SKIP_NAME_HINTS
BROAD_FAMILY_COUNT = BROAD_FAMILY_COUNT
LEARNED_STRONG = LEARNED_STRONG
CORE_STRONG = CORE_STRONG
CREATE_SKIP_AI = CREATE_SKIP_AI
STRONG_SKIP_AI = STRONG_SKIP_AI
AI_BAND_LOW = AI_BAND_LOW
_sk = _sk
_platform_home = _platform_home
_learned_dir = _learned_dir
_parse_frontmatter = _parse_frontmatter
_heading_title = _heading_title
_kind_for_path = _kind_for_path
_declared_languages = _declared_languages
_langs_compatible = _langs_compatible
_finding_blob = _finding_blob
_jaccard = _jaccard
_score = _score
_overlays_by_parent = _overlays_by_parent
_rank = _rank
_heuristic_decision = _heuristic_decision
_needs_ai = _needs_ai
_ai_uniqueness_prompt = _ai_uniqueness_prompt
_parse_ai_decision = _parse_ai_decision
_resolve_target = _resolve_target
catalog_skills = catalog_skills
ingest_learned_skill = ingest_learned_skill
CatalogEntry.merge_target = CatalogEntry.merge_target

