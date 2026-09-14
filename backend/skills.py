"""
Lotus Skills System - Emergent Knowledge from Confirmed Findings

Each AI-confirmed finding is modeled, synthesized, and distilled into a
reusable markdown "skill" file stored on disk.  These skills are loaded as
context in Phase 2 discovery so that every subsequent audit benefits from
prior discoveries - the system compounds over time.

Skill files live in LOTUS_SKILLS_DIR (default: ./data/skills/).  In
production the directory is volume-mounted and also bind-mounted into lab
pods so scanners can read them.

Bring-your-own-skills (BYOS) can point the *doctrine* root (lotus-core) at
any directory and switch it back. Learned skills are immortal: they always
live under the platform skills home (`LOTUS_PLATFORM_SKILLS_HOME` or the
skills dir that was active before the first swap) and survive restarts,
doctrine swaps, and platform upgrades.
"""

import os
import re
import json
import hashlib
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable

try:  # POSIX deployments support advisory locks across API worker processes.
    import fcntl
except ImportError:  # pragma: no cover - atomic replacement remains safe fallback.
    fcntl = None

def _initial_skills_dir() -> Path:
    explicit = os.environ.get("LOTUS_SKILLS_DIR", "").strip()
    data_home = os.environ.get("LOTUS_DATA_DIR", "").strip() or "./data"
    return Path(explicit).expanduser() if explicit else Path(data_home).expanduser() / "skills"


SKILLS_DIR = _initial_skills_dir()

# Captured at import (and reset in tests) so BYOS never redefines platform home.
_BOOT_HOME: Path = Path(SKILLS_DIR).resolve()
# Pinned on first BYOS swap so learned skills never follow the doctrine root.
_PLATFORM_HOME: Optional[Path] = None
_PREVIOUS_SKILLS_DIR: Optional[Path] = None
_STATE_LOCK = threading.RLock()
_RESTORE_STATUS: Dict[str, Any] = {}


def get_skills_dir() -> Path:
    """Return the current (active doctrine) skills directory path."""
    return SKILLS_DIR


def get_platform_home() -> Path:
    """Durable platform skills home (learned skills + pattern DB live here)."""
    env = os.environ.get("LOTUS_PLATFORM_SKILLS_HOME", "").strip()
    if env:
        return Path(env).resolve()
    if _PLATFORM_HOME is not None:
        return _PLATFORM_HOME
    return Path(_BOOT_HOME).resolve()


def get_learned_dir() -> Path:
    """Directory where write_skill() persists compounding knowledge."""
    env = os.environ.get("LOTUS_LEARNED_DIR", "").strip()
    if env:
        return Path(env).resolve()
    return get_platform_home() / "learned"


def get_previous_skills_dir() -> Optional[Path]:
    return _PREVIOUS_SKILLS_DIR


def skills_roots() -> Dict[str, Any]:
    """Inspectable map of every skills root the platform is using."""
    prev = _PREVIOUS_SKILLS_DIR
    home = get_platform_home()
    active = Path(SKILLS_DIR).resolve()
    return {
        "active": str(active),
        "platform_home": str(home),
        "learned_dir": str(get_learned_dir()),
        "previous": str(prev) if prev else None,
        "swapped": str(active) != str(home),
        "can_restore": bool(prev) or str(active) != str(home),
        "restore": dict(_RESTORE_STATUS),
    }


def reset_skills_runtime() -> None:
    """Test helper: drop pinned BYOS state without touching files."""
    global _PLATFORM_HOME, _PREVIOUS_SKILLS_DIR, _BOOT_HOME, _RESTORE_STATUS
    _RESTORE_STATUS = {}
    _PLATFORM_HOME = None
    _PREVIOUS_SKILLS_DIR = None
    _BOOT_HOME = Path(SKILLS_DIR).resolve()


def _reload_pack_registry(root: Path) -> None:
    try:
        import backend.skill_packs as _sp
        _sp.SKILLS_DIR = root
        os.environ["LOTUS_SKILLS_DIR"] = str(root)
        _sp.get_registry(force_reload=True)
    except Exception:
        pass


def set_skills_dir(new_path: str, *, pin_previous: bool = True) -> Path:
    """Point lotus-core (doctrine) at a new directory. Learned skills stay put.

    The first swap pins the then-current directory as the platform home so
    `learned/` never moves. Switch-back uses restore_previous_skills_dir().
    """
    global SKILLS_DIR, _PLATFORM_HOME, _PREVIOUS_SKILLS_DIR, _RESTORE_STATUS
    p = Path(new_path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    current = Path(SKILLS_DIR).resolve()
    if _PLATFORM_HOME is None:
        # Always pin to process-boot home, never to a BYOS path already in SKILLS_DIR.
        _PLATFORM_HOME = Path(_BOOT_HOME).resolve()
    if pin_previous and current != p:
        _PREVIOUS_SKILLS_DIR = current
    SKILLS_DIR = p
    os.environ["LOTUS_SKILLS_DIR"] = str(p)
    get_learned_dir().mkdir(parents=True, exist_ok=True)
    _reload_pack_registry(p)
    _RESTORE_STATUS = {"status": "selected", "configured": str(p), "effective": str(p), "fallback": False, "warning": ""}
    return SKILLS_DIR


def restore_previous_skills_dir() -> Path:
    """Frictionless switch-back to the previous doctrine root."""
    prev = _PREVIOUS_SKILLS_DIR
    if prev is None:
        return set_skills_dir(str(get_platform_home()), pin_previous=False)
    return set_skills_dir(str(prev), pin_previous=True)


def restore_platform_skills_dir() -> Path:
    """Point doctrine back at the pinned platform home."""
    return set_skills_dir(str(get_platform_home()), pin_previous=True)


def apply_persisted_skills_dirs(active: str = "", previous: str = "") -> Path:
    """Resolve saved doctrine in this runtime without creating missing host paths.

    The database's configured pointers remain unchanged. Unavailable doctrine
    falls back to the deployment's boot home; learned files always stay on the
    platform home and must be writable independently of read-only doctrine.
    """
    global _PREVIOUS_SKILLS_DIR, _PLATFORM_HOME, _RESTORE_STATUS
    configured = active.strip()
    fallback = Path(_BOOT_HOME).resolve()
    if _PLATFORM_HOME is None:
        _PLATFORM_HOME = fallback
    _PREVIOUS_SKILLS_DIR = Path(previous).expanduser().resolve() if previous else None
    selected = fallback
    warning = ""
    if configured:
        try:
            candidate = Path(configured).expanduser().resolve()
            if not candidate.is_dir() or not os.access(candidate, os.R_OK | os.X_OK):
                raise OSError("saved directory is absent or unreadable")
            selected = candidate
        except (OSError, ValueError, RuntimeError):
            warning = ("Saved skills directory is unavailable in this runtime. "
                       "Using the deployment skills directory; the saved selection is preserved. "
                       "Mount the custom directory here or select an existing directory in Settings.")
    _RESTORE_STATUS = {"status": "fallback" if warning else "restored" if configured else "default",
                       "configured": active, "effective": str(selected),
                       "fallback": bool(warning), "warning": warning}
    status = dict(_RESTORE_STATUS)
    # Only the explicit deployment home may be created. Never recreate a
    # persisted source-machine directory merely because a database moved.
    if selected == fallback:
        selected.mkdir(parents=True, exist_ok=True)
    learned = get_learned_dir()
    try:
        learned.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=learned):
            pass
    except OSError as exc:
        _RESTORE_STATUS = {**status, "status": "error", "effective": str(Path(SKILLS_DIR).resolve()),
                           "warning": "Platform learned-skills directory is not writable; check the deployment data-volume permissions."}
        raise OSError(_RESTORE_STATUS["warning"]) from exc
    set_skills_dir(str(selected), pin_previous=False)
    _RESTORE_STATUS = status
    return SKILLS_DIR


def _ensure_dir():
    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    get_learned_dir().mkdir(parents=True, exist_ok=True)


def _slug(text: str) -> str:
    """Create a filename-safe slug from a title."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.lower()).strip("-")
    return s[:80] if s else "untitled"


# ---------------------------------------------------------------------------
# Write a skill from a confirmed finding
# ---------------------------------------------------------------------------

def _find_existing_skill(slug: str) -> Optional[Path]:
    """Check learned/ then doctrine root for a skill with a similar slug."""
    _ensure_dir()
    for base in (get_learned_dir(), SKILLS_DIR / "learned", SKILLS_DIR):
        if not base.exists():
            continue
        for f in base.glob("*.md"):
            name_part = f.stem.rsplit("--", 1)[0] if "--" in f.stem else f.stem
            if name_part == slug:
                return f
    return None


def _revisions_dir() -> Path:
    return get_platform_home() / ".revisions"


def _save_revision(filepath: Path, old_content: str):
    """Save the old content as a revision before overwriting."""
    rev_dir = _revisions_dir()
    rev_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rev_file = rev_dir / f"{filepath.stem}--rev-{ts}.md"
    rev_file.write_text(old_content, encoding="utf-8")
    return str(rev_file)


_LEARNED_SKILLS_CAP = int(os.environ.get("LOTUS_MAX_LEARNED_SKILLS", "800"))


def _prune_learned_skills(cap: Optional[int] = None) -> int:
    """Bound the learned/ directory so prompt context and disk don't grow without limit.

    Keeps the `cap` most-recently-modified skills; older ones are ARCHIVED into
    .revisions/ (renamed, not deleted) so learned knowledge is never lost irrecoverably.
    Returns the number of skills archived.
    """
    cap = cap or _LEARNED_SKILLS_CAP
    archived = 0
    try:
        learned_dir = get_learned_dir()
        files = [p for p in learned_dir.glob("*.md") if p.is_file()]
        if len(files) <= cap:
            return 0
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        rev_dir = _revisions_dir()
        rev_dir.mkdir(parents=True, exist_ok=True)
        for p in files[cap:]:
            try:
                p.rename(rev_dir / f"pruned--{p.name}")
            except Exception:
                try:
                    p.unlink()
                except Exception:
                    continue
            archived += 1
    except Exception:
        pass
    return archived


def write_skill(
    finding: dict,
    language: str = "unknown",
    repo_source: str = "",
    ai_call: Optional[Callable[..., Any]] = None,
) -> str:
    """Distill a confirmed finding into a reusable skill, with uniqueness checks.

    Proposes a learned skill, compares it against lotus-core and existing learned
    skills (heuristic always; AI when the decision is ambiguous or we are about
    to create a new file), then either strengthens the matching skill or writes
    a new learned skill. Lotus-core files are never mutated — overlaps land in
    a learned overlay. Returns the path of the created or updated file.
    """
    from backend.skill_learn import ingest_learned_skill
    return ingest_learned_skill(
        finding, language=language, repo_source=repo_source, ai_call=ai_call,
    )["path"]


def _write_learned_skill_file(finding: dict, language: str = "unknown", repo_source: str = "") -> str:
    """Primitive: write or slug-replace a learned skill file. No uniqueness eval."""
    _ensure_dir()
    learned_dir = get_learned_dir()
    learned_dir.mkdir(parents=True, exist_ok=True)
    slug = _slug(finding.get("title", "unknown"))
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    # Check for existing skill with same slug
    existing = _find_existing_skill(slug)
    if existing:
        # Save old version as revision
        old_content = existing.read_text(encoding="utf-8")
        _save_revision(existing, old_content)
        filepath = existing  # Update in place
    else:
        filepath = learned_dir / f"{slug}--{ts}.md"

    source_title = " ".join(str(finding.get("title") or "").split())[:180]
    if not source_title or source_title.lower() in {"unknown", "untitled", "finding", "lead", "security issue"}:
        source_title = f"{finding.get('tool') or 'source'} observation in {finding.get('file') or 'recorded code'}"
    title = "Validate " + source_title
    cvss = float(finding.get("cvss", 0.0) or 0.0)
    tool = finding.get("tool", "unknown")
    description = finding.get("description", "")
    ai_analysis = finding.get("ai_analysis", "")
    attack_vector = finding.get("attack_vector", "")
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    technique = finding.get("discovery_technique") or tool
    qualification = finding.get("qualification") or "UNVERIFIED"

    severity = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"

    detection_regex = ""
    try:
        from backend.discovery_engine import extract_patterns_from_finding, save_pattern_to_db
        pat = extract_patterns_from_finding(finding, language=language)
        if pat and pat.get("regex"):
            detection_regex = pat["regex"]
            save_pattern_to_db(pat)
    except Exception:
        pass

    md = f"""---
pack: learned
id: {slug}
title: {json.dumps(title)}
language: {language}
cvss: {cvss}
tool: {tool}
technique: {technique}
qualification: {qualification}
scope: pattern-with-source-observation
source_repo: {json.dumps(repo_source)}
source_file: {json.dumps(file_path)}
source_line: {line}
learned_at: {datetime.utcnow().isoformat()}Z
detection_regex: {json.dumps(detection_regex)}
---

# Skill: {title}

## Scope and prerequisites
This is a reusable investigation method derived from a recorded observation in `{repo_source or 'an unspecified source'}`.
Recorded verdict: `{qualification}`. This file does not independently verify that verdict or prove a vulnerability in another repository.
Identify the current entry point, attacker permissions, target revision and deployment configuration before applying the pattern.

## Metadata
- **Severity**: {severity} (CVSS {cvss})
- **Category**: learned
- **Language**: {language}
- **Source Repo**: {repo_source}
- **Detection Tool**: {tool}
- **Technique**: {technique}
- **Learned**: {datetime.utcnow().isoformat()}Z

## What to Look For
{_derive_pattern(title, description, ai_analysis)}

## Vulnerability Pattern
- **File**: `{file_path}:{line}`
- **Attack Vector**: {attack_vector or 'See analysis below'}
- **Reported Cause / Observation**: {finding.get('root_cause') or description or 'Not recorded; determine from current source and evidence.'}

## Detection Heuristic
When auditing a {language} application, check for:
{_derive_heuristic(title, description, tool)}
{f'- Regex: `{detection_regex}`' if detection_regex else ''}

## AI Analysis
{ai_analysis or '_No analysis recorded; absence of analysis is not confirmation._'}

## How to Validate
1. Identify the current entry point and the attacker's actual permissions.
2. Trace the current data flow and inspect validation, authorization and intended capabilities.
3. Test the claimed trust-boundary crossing with a bounded oracle and a negative control in an authorized isolated lab.
4. Record target-bound evidence; unreachable input, enforced controls or an intended trusted operation can refute the hypothesis. Tool matches and AI text alone do not confirm it.

## Remediation Pattern
{_derive_remediation(title, description)}

---
*Auto-generated by Lotus Skills System (learned pack)*
"""
    filepath.write_text(md, encoding="utf-8")
    # Keep the learned corpus bounded (archives oldest to .revisions/).
    _prune_learned_skills()
    return str(filepath)


def write_disprove_skill(
    item: dict,
    language: str = "unknown",
    repo_source: str = "",
) -> str:
    """Persist an honest DISPROVE so the next audit does not re-promote the lead."""
    _ensure_dir()
    learned_dir = get_learned_dir()
    learned_dir.mkdir(parents=True, exist_ok=True)
    title = item.get("title") or item.get("sql") or "disprove"
    scope_id = hashlib.sha256(str(repo_source or "").strip().rstrip("/").encode()).hexdigest()[:12]
    slug = _slug("disprove-" + str(title))[:60] + "-" + scope_id
    existing = _find_existing_skill(slug)
    filepath = existing if existing else learned_dir / f"{slug}--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.md"
    if existing:
        try:
            _save_revision(existing, existing.read_text(encoding="utf-8"))
        except Exception:
            pass
    verdict = item.get("verdict") or "DISPROVE"
    sql = item.get("sql") or item.get("command") or ""
    err = item.get("error") or item.get("execute_error") or item.get("select_error") or ""
    extra = {k: item.get(k) for k in item if k not in ("title", "sql", "verdict")}
    md = f"""---
pack: learned
id: {slug}
title: {json.dumps(str(title)[:160])}
language: {language}
qualification: DISPROVE
scope: repository
source_repo: {json.dumps(repo_source)}
learned_at: {datetime.utcnow().isoformat()}Z
verdict: {json.dumps(verdict)}
---

# Skill: Review negative validation — {title}

## Metadata
- **Category**: learned / negative-memory
- **Language**: {language}
- **Source Repo**: {repo_source}

## What failed the gates
This is a recorded negative observation for `{repo_source or 'an unspecified source'}`, not proof about another target.
Do **not** report statement success as security impact; a failed command or unavailable lab is inconclusive.

- Command: `{sql}`
- Verdict: `{verdict}`
- Error / measurement: `{err}`
- Extra: `{json.dumps(extra, default=str)[:1200]}`

## How to avoid wasting the next audit
Recheck the current source, configuration and oracle before applying this history.
Never suppress current validation based only on a matching title or language.
Measure the claimed state change with an appropriate positive oracle and negative control.
"""
    filepath.write_text(md, encoding="utf-8")
    _prune_learned_skills()
    return str(filepath)


def write_retrospective_skill(
    plan: dict,
    *,
    language: str = "unknown",
    repo_source: str = "",
    proven: Optional[List[dict]] = None,
    disproven: Optional[List[dict]] = None,
    lab_status: Optional[dict] = None,
    fix_results: Optional[List[dict]] = None,
) -> str:
    """Record scoped audit observations, without turning setup or advice into proof."""
    _ensure_dir()
    learned_dir = get_learned_dir()
    learned_dir.mkdir(parents=True, exist_ok=True)
    host = ""
    try:
        host = Path(str(repo_source)).name or str(repo_source).rstrip("/").split("/")[-1]
    except Exception:
        host = "repo"
    scope_id = hashlib.sha256(str(repo_source or "").strip().rstrip("/").encode()).hexdigest()[:12]
    # Basenames and languages do not identify a repository. Never overwrite
    # another owner's equally named repository retrospective.
    slug = _slug(f"audit-retro-{host or language}")[:60] + "-" + scope_id
    existing = _find_existing_skill(slug)
    filepath = existing if existing else learned_dir / f"{slug}--{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.md"
    if existing:
        try:
            _save_revision(existing, existing.read_text(encoding="utf-8"))
        except Exception:
            pass
    proven = proven or []
    disproven = disproven or []
    lab_status = lab_status or {}
    fix_results = fix_results or []
    proven_lines = "\n".join(
        f"- {p.get('title') or 'Untitled observation'} — recorded verdict: "
        f"{p.get('qualification') or p.get('status') or 'not supplied'}"
        for p in proven[:20] if isinstance(p, dict)
    ) or "- No positive validation outcome recorded. This is not a clean-code verdict."
    disprove_lines = "\n".join(
        f"- {d.get('title')}: {d.get('verdict')}" for d in disproven[:20]
    ) or "- No negative validation outcome recorded."
    fix_lines = "\n".join(
        f"- {f.get('title', 'fix')}: {f.get('quality')} {f.get('verdict', '')[:160]}"
        for f in fix_results[:10]
    ) or "- none attempted"
    app_type = str(plan.get("app_type") or "unknown")
    method = {
        "cli-tool": "Review CLI input and dependency boundaries",
        "library": "Review library input boundaries",
        "api-service": "Review API deployment and access boundaries",
        "web-app": "Review web entry points and deployment",
    }.get(app_type, "Review audit setup and coverage")
    title = f"{method}: {host or language}"
    lab_observation = ("A healthy lab was reported; this alone proves no vulnerability."
        if lab_status.get("healthy") is True else
        "A healthy lab was not recorded. Planned commands below are not a successful setup recipe.")
    md = f"""---
pack: learned
id: {slug}
title: {json.dumps(title)}
language: {language}
qualification: RETROSPECTIVE
scope: repository
source_repo: {json.dumps(repo_source)}
source_identity: {json.dumps(scope_id)}
lab_strategy: {json.dumps(plan.get("lab_strategy"))}
learned_at: {datetime.utcnow().isoformat()}Z
---

# Skill: {title}

## Scope and prerequisites
- Historical source: `{repo_source or 'not recorded'}`. Match the complete repository identity, revision and configuration before reusing observations.
- Language: `{language}`; application type: `{app_type}`. Neither is a repository identity.
- Review the current checkout and available runtime first. Do not run stored commands or suppress a new lead because of this note.

## Recorded setup and limits
{lab_observation}

- Strategy: `{plan.get("lab_strategy")}`
- App type: `{app_type}`
- Stacks: `{', '.join(plan.get('languages') or [language])}`
- Lab status: `{lab_status.get("status")} healthy={lab_status.get("healthy")} kind={lab_status.get("lab_kind")}`
- Start: `{plan.get("start_command")}`
- Smoke: `{plan.get("smoke_test")}`
- Install steps: {json.dumps(plan.get("install_steps") or [])[:1500]}
- Notes: {json.dumps(plan.get("notes") or [])[:800]}

## Recorded validation outcomes
These are audit-supplied observations, not independently verified proof. A current finding still requires its own signed, target-bound evidence.
{proven_lines}

## Historical negative results
Negative results apply only to the tested target, configuration and oracle. Revalidate after changes; a missing lab or failed command is inconclusive.
{disprove_lines}

## Fix verification
{fix_lines}

## Reuse
Use the recorded gaps to plan current checks. Confirm setup from current repository documentation,
then test a bounded hypothesis with a positive oracle and a negative control. A successful startup,
language match or generated analysis does not establish exploitability or guarantee new findings.
"""
    filepath.write_text(md, encoding="utf-8")
    _prune_learned_skills()
    return str(filepath)


def _context_scope(content: str) -> str:
    """Keep provenance and evidence limits attached when selecting short excerpts."""
    metadata = {}
    # RAG documents prepend a title/category before the original frontmatter.
    frontmatter = re.search(r"(?:\A|\n)---\n(.*?)\n---(?:\n|\Z)", content[:4096], re.S)
    if frontmatter:
        for line in frontmatter.group(1).splitlines():
            key, separator, value = line.partition(":")
            if separator and key in {"source_repo", "qualification"}:
                try:
                    metadata[key] = json.loads(value)
                except (ValueError, TypeError):
                    metadata[key] = value.strip()
    source = " ".join(str(metadata.get("source_repo") or "not recorded").split())[:300]
    qualification = " ".join(str(metadata.get("qualification") or "methodology").split())[:60]
    return (f"Historical source: {source}; record type: {qualification}. "
            "Use as investigation context, not evidence about the current target. "
            "Recheck prerequisites and require current target-bound proof; do not execute stored commands.\n")


def _derive_pattern(title: str, desc: str, analysis: str) -> str:
    """Extract the vulnerability pattern for future detection."""
    t = title.lower()
    patterns = []
    if "sql" in t and "inject" in t:
        patterns.append("- String concatenation in SQL queries instead of parameterized statements")
        patterns.append("- User input flowing into raw SQL or ORM `.where()` with interpolation")
    elif "xss" in t or "cross-site" in t:
        patterns.append("- User input rendered in HTML without escaping")
        patterns.append("- Template variables output with `|safe` or `{!! !!}` or `dangerouslySetInnerHTML`")
    elif "command" in t and "inject" in t:
        patterns.append("- User input passed to `system()`, `exec()`, `subprocess.run(shell=True)`")
        patterns.append("- Unsanitized parameters in shell command construction")
    elif "path" in t and "travers" in t:
        patterns.append("- User-supplied file paths with `../` sequences not stripped")
        patterns.append("- File operations without path canonicalization")
    elif "ssrf" in t:
        patterns.append("- User-controlled URLs passed to HTTP client without allowlist")
        patterns.append("- Internal service endpoints reachable via URL parameter")
    elif "deserializ" in t:
        patterns.append("- Untrusted data passed to `pickle.loads()`, `yaml.load()`, `unserialize()`")
        patterns.append("- Object instantiation from user-controlled class names")
    elif any(k in t for k in ("secret", "key", "credential", "password", "token")):
        patterns.append("- Hardcoded secrets, API keys, or passwords in source code")
        patterns.append("- Credentials in config files, environment defaults, or test fixtures")
    else:
        patterns.append(f"- {title}: Review code for this vulnerability class")
        patterns.append(f"- Look for patterns matching: {desc[:200]}")
    return "\n".join(patterns)


def _derive_root_cause(title: str, desc: str) -> str:
    t = title.lower()
    if "sql" in t:
        return "Unsanitized user input concatenated into SQL query string"
    elif "xss" in t:
        return "User-controlled data rendered in HTML response without output encoding"
    elif "command" in t:
        return "User input embedded in OS command without proper escaping"
    elif "path" in t:
        return "Insufficient path validation allows directory traversal"
    elif "ssrf" in t:
        return "User-controlled URL not validated against allowlist"
    return f"Security control bypass or missing validation: {desc[:150]}"


def _derive_heuristic(title: str, desc: str, tool: str) -> str:
    lines = [f"- Run `{tool}` against the codebase for similar patterns"]
    t = title.lower()
    if "sql" in t:
        lines.append("- `grep -rn 'execute\\|raw\\|where.*#\\{' --include='*.rb' --include='*.py'`")
    elif "xss" in t:
        lines.append("- `grep -rn 'innerHTML\\|dangerouslySet\\|\\|safe\\|html_safe' --include='*.js' --include='*.erb'`")
    elif "command" in t:
        lines.append("- `grep -rn 'system\\|exec\\|popen\\|subprocess' --include='*.py' --include='*.rb'`")
    lines.append(f"- Search for the same pattern in other files and controllers")
    return "\n".join(lines)


def _derive_remediation(title: str, desc: str) -> str:
    """Ranked remediation for learned skills  - delegates to fix_suggestions engine."""
    try:
        from backend.fix_suggestions import propose_fixes
        block = propose_fixes({"title": title, "description": desc})
        lines = []
        for opt in block.get("options") or []:
            lines.append(
                f"{opt['rank']}. **{opt['title']}** "
                f"(effort {opt['effort']}, residual risk {opt['residual_risk']}/10, "
                f"perf {opt['performance_impact']})"
            )
            lines.append(f"   {opt['approach']}")
            for t in (opt.get("tradeoffs") or [])[:2]:
                lines.append(f"   - Trade-off: {t}")
        return "\n".join(lines) if lines else "- Review and patch the affected code path"
    except Exception:
        t = title.lower()
        if "sql" in t:
            return "- Use parameterized queries / prepared statements\n- Use ORM methods that auto-escape\n- Apply input validation on query parameters"
        elif "xss" in t:
            return "- Apply context-aware output encoding\n- Use Content-Security-Policy headers\n- Avoid rendering raw HTML from user input"
        elif "command" in t:
            return "- Avoid shell=True; use subprocess with argument lists\n- Validate and allowlist permitted commands\n- Use language-native APIs instead of shell commands"
        elif "path" in t:
            return "- Canonicalize paths and verify they stay within allowed directories\n- Reject inputs containing `..` sequences\n- Use chroot or container isolation for file operations"
        return "- Review and patch the affected code path\n- Add input validation/sanitization\n- Apply defense-in-depth controls"


# ---------------------------------------------------------------------------
# Read skills for context injection
# ---------------------------------------------------------------------------

# Qualification doctrine is a safety invariant, not an optional relevance
# result.  A large learned/discovery corpus can otherwise consume the
# ``max_skills`` window and omit the Devil's-Advocate/verification rules
# that prevent an AI assertion from becoming a published Finding.
MANDATORY_SKILL_NAMES = frozenset({
    "triage-prioritization.md",
    "hypothesis-qualification.md",
    "false-positive-patterns.md",
})

# Relevance digests use the remaining context after enabled qualification
# doctrine. Mandatory bodies stay intact before the downstream 12k merge cap;
# ordinary digests and RAG excerpts are bounded and may omit later sections.
# Direct context prioritizes bounded excerpts of applicable skills (title,
# metadata, doctrine and leading discovery vectors). RAG can add selected
# excerpts; the global and downstream merge budgets can omit eligible skills.
_DOCTRINE_DIGEST_CHARS = 1300
_DOCTRINE_CATEGORIES = ("methodology", "gating", "discovery", "bug-classes")


def _collect_enabled_skills(
    custom_path: Optional[str] = None,
) -> List[Tuple[str, str, str]]:
    """Return ``(filename, content, category)`` for every enabled skill file."""
    _ensure_dir()
    all_files = _gather_skill_files()

    if custom_path:
        custom = Path(custom_path)
        if custom.is_dir():
            extras = list(custom.rglob("*.md"))
            all_files = extras + all_files

    skill_state = load_skills_state()
    out: List[Tuple[str, str, str]] = []
    seen_names: set = set()
    for f in all_files:
        if f.name in seen_names:
            continue
        seen_names.add(f.name)
        if not skill_state.get(f.name, True):
            continue
        try:
            content = f.read_text(encoding="utf-8")
            category = f.parent.name if f.parent != SKILLS_DIR else "general"
            out.append((f.name, content, category))
        except Exception:
            continue
    return out


def select_skills_for_profile(
    items: List[Tuple[str, str, str]],
    profile: Optional["RepoProfile"],
    max_skills: int = 50,
) -> List[Tuple[str, str, str]]:
    """Applicability-driven selection + ranking of ``(filename, content, category)``.

    * Mandatory qualification doctrine is always pinned first.
    * Methodology / gating (cross-cutting) and learned (memory) always apply.
    * Discovery / bug-class skills must be universal or match the repo profile
      by declared language, stack, or signal (see ``skill_applicability``).
    * Remaining skills are ranked by relevance score, then pack priority.
    """
    from backend.skill_applicability import parse_skill_metadata, score_skill, skill_applies

    priority_order = ["learned", "discovery", "bug-classes", "gating", "methodology"]
    cat_rank = {c: i for i, c in enumerate(priority_order)}

    scored: List[Tuple[float, int, str, Tuple[str, str, str]]] = []
    mandatory: List[Tuple[str, str, str]] = []
    for item in items:
        name, content, category = item
        if name in MANDATORY_SKILL_NAMES:
            mandatory.append(item)
            continue
        meta = parse_skill_metadata(content, category)
        applies, _reasons = skill_applies(meta, profile)
        if not applies:
            continue
        scored.append((-score_skill(meta, profile), cat_rank.get(category, 9), name, item))
    scored.sort(key=lambda t: (t[0], t[1], t[2]))
    mandatory.sort(key=lambda it: it[0])

    selected = list(mandatory)
    selected.extend(t[3] for t in scored)
    return selected[: max(1, int(max_skills or 1))]


def load_skills(
    language: Optional[str] = None,
    max_skills: int = 50,
    custom_path: Optional[str] = None,
    repo_profile: Optional["RepoProfile"] = None,
) -> str:
    """Load skill files from enabled packs (+ optional custom path) as prompt context.

    Selection is applicability-driven: ``repo_profile`` (built for Phase 2
    by ``skill_applicability.profile_repo``) or, for legacy callers, the single
    ``language`` string decides which discovery / bug-class skills apply.
    Methodology, gating and learned skills are cross-cutting. Enabled mandatory
    qualification bodies precede relevance digests. Selection count, this
    loader's budget and the later merge budget can omit eligible skills.
    """
    from backend.skill_applicability import profile_from_language

    profile = repo_profile if repo_profile is not None else profile_from_language(language)
    skills = _collect_enabled_skills(custom_path)
    if not skills:
        return ""

    TOKEN_BUDGET = 60000
    selected = select_skills_for_profile(skills, profile, max_skills=max_skills)
    parts = ["## Learned Skills & Methodology from Prior Audits\n"]
    char_count = len(parts[0])

    for name, content, category in selected:
        if char_count >= TOKEN_BUDGET:
            break
        if name in MANDATORY_SKILL_NAMES:
            # Validation rules live after discovery examples in these files.
            # A leading digest loses them, and RAG excerpts are also truncated.
            chunk = content[: TOKEN_BUDGET - char_count]
            parts.extend((chunk, ""))
            char_count += len(chunk) + 1
            continue
        lines = content.split("\n")
        if category in _DOCTRINE_CATEGORIES:
            summary_lines = []
            used = 0
            for line in lines[:160]:
                if line.startswith("---") and len(summary_lines) > 5:
                    break
                if used + len(line) + 1 > _DOCTRINE_DIGEST_CHARS and len(summary_lines) > 6:
                    break
                summary_lines.append(line)
                used += len(line) + 1
            if summary_lines:
                chunk = "\n".join(summary_lines)
                if char_count + len(chunk) > TOKEN_BUDGET:
                    chunk = chunk[: TOKEN_BUDGET - char_count]
                parts.append(chunk)
                parts.append("")
                char_count += len(chunk) + 1
        else:
            summary_lines = []
            in_section = False
            for line in lines:
                if line.startswith(("# Skill:", "## What to Look For", "## Detection Heuristic",
                                    "## Scope and prerequisites", "## Recorded setup and limits",
                                    "## Recorded validation outcomes", "## Reuse")):
                    in_section = True
                elif line.startswith("## ") and in_section:
                    in_section = False
                if in_section:
                    summary_lines.append(line)
            if summary_lines:
                chunk = _context_scope(content) + "\n".join(summary_lines[:30])
                if char_count + len(chunk) > TOKEN_BUDGET:
                    break
                parts.append(chunk)
                parts.append("")
                char_count += len(chunk) + 1

    return "\n".join(parts)[:TOKEN_BUDGET]


def skill_applicability_report(
    repo_path: Optional[str] = None,
    language: Optional[str] = None,
    custom_path: Optional[str] = None,
    repo_profile: Optional["RepoProfile"] = None,
) -> Dict[str, Any]:
    """Kickoff-time decision record: which enabled skills apply to this repo and why.

    Builds (or accepts) a repo profile, evaluates every enabled skill against it
    and returns a JSON-safe report (profile, applicable[], skipped[], reasons,
    scores). The pipeline logs its summary at audit kickoff; the same payload
    can back a skills-applicability view in the UI.
    """
    from backend.skill_applicability import applicability_report, profile_from_language, profile_repo

    profile = repo_profile
    if profile is None and repo_path:
        profile = profile_repo(repo_path, base_language=language)
    if profile is None:
        profile = profile_from_language(language)
    items = _collect_enabled_skills(custom_path)
    report = applicability_report(profile, items)
    report["mandatory"] = sorted(MANDATORY_SKILL_NAMES)
    return report


def format_rag_skills(rag_hits: List[Dict[str, Any]]) -> str:
    """Convert hybrid_search_skills results into markdown context (never assign raw list)."""
    if not rag_hits:
        return ""
    parts = ["## Query-Relevant Skills (RAG)\n"]
    for item in rag_hits:
        title = item.get("title") or item.get("filename") or "skill"
        content = (item.get("content") or "")[:1500]
        parts.append(f"### {title}\n{_context_scope(content)}{content}\n")
    return "\n".join(parts)


def merge_skills_context(base: str, rag_hits: Optional[List[Dict[str, Any]]] = None, budget: int = 12000) -> str:
    """Merge pack-loaded skills with RAG hits into a single string under budget."""
    rag_md = format_rag_skills(rag_hits or [])
    if not base and not rag_md:
        return ""
    if not rag_md:
        return (base or "")[:budget]
    if not base:
        return rag_md[:budget]
    # Prefer methodology base, append RAG unique content
    merged = base.rstrip() + "\n\n" + rag_md
    return merged[:budget]


def list_skills() -> List[Dict]:
    """Return metadata for all skill files across enabled packs + immortal learned."""
    _ensure_dir()
    result = []
    all_files = _gather_skill_files()

    for f in sorted(set(all_files), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            content = f.read_text(encoding="utf-8")
            title = "Unknown"
            language = "unknown"
            cvss = 0.0
            category = f.parent.name if f.parent != SKILLS_DIR else "general"
            pack = "lotus-core" if category in ("methodology", "discovery", "gating", "bug-classes") else (
                "learned" if category == "learned" else "general"
            )
            for line in content.split("\n")[:25]:
                if line.startswith("# Skill:"):
                    title = line.replace("# Skill:", "").strip()
                if "**Language**" in line or line.startswith("language:"):
                    language = line.split(":")[-1].strip().strip('"')
                if "**Severity**" in line and "CVSS" in line:
                    m = re.search(r"CVSS ([\d.]+)", line)
                    if m:
                        cvss = float(m.group(1))
                if line.startswith("cvss:"):
                    try:
                        cvss = float(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                if "**Category**" in line:
                    category = line.split(":")[-1].strip().split("/")[0].strip()
                if line.startswith("pack:"):
                    pack = line.split(":", 1)[1].strip()
            result.append({
                "filename": f.name,
                "title": title,
                "language": language,
                "category": category,
                "pack": pack,
                "cvss": cvss,
                "size": f.stat().st_size,
                "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "path": str(f.relative_to(SKILLS_DIR)) if str(f).startswith(str(SKILLS_DIR)) else f.name,
            })
        except Exception:
            continue
    return result


def get_skill_content(filename: str) -> Optional[str]:
    """Read a specific skill file. Searches doctrine root, known subdirs, and immortal learned/.

    Validates that the resolved path stays within SKILLS_DIR or the learned dir
    to prevent path traversal.
    """
    if ".." in filename or filename.startswith("/"):
        return None
    if "\x00" in filename:
        return None

    def _allowed_bases() -> List[Path]:
        bases = [SKILLS_DIR.resolve(), get_learned_dir().resolve()]
        home = get_platform_home().resolve()
        if home not in bases:
            bases.append(home)
        return bases

    def _safe_read(candidate: Path) -> Optional[str]:
        try:
            resolved = candidate.resolve()
            allowed = False
            for base in _allowed_bases():
                if str(resolved) == str(base) or str(resolved).startswith(str(base) + "/"):
                    allowed = True
                    break
            if not allowed:
                return None
            if resolved.exists() and resolved.suffix == ".md":
                return resolved.read_text(encoding="utf-8")
        except Exception:
            pass
        return None

    result = _safe_read(SKILLS_DIR / filename)
    if result is not None:
        return result
    result = _safe_read(get_learned_dir() / filename)
    if result is not None:
        return result
    for subdir in ["methodology", "discovery", "gating", "bug-classes", "learned"]:
        result = _safe_read(SKILLS_DIR / subdir / filename)
        if result is not None:
            return result
    return None


def skill_count() -> int:
    return len(list_skills())


# ---------------------------------------------------------------------------
# Per-skill enable/disable state (skills_state.json)
# ---------------------------------------------------------------------------

def _state_file() -> Path:
    # Enable/disable flags live on the platform home so they survive doctrine swaps.
    home = get_platform_home()
    home.mkdir(parents=True, exist_ok=True)
    return home / "skills_state.json"


@contextmanager
def _skills_state_lock(*, exclusive: bool):
    """Coordinate skill capability reads/writes across threads and workers."""
    with _STATE_LOCK:
        if fcntl is None:
            yield
            return
        lock_path = _state_file().with_name("skills_state.json.lock")
        handle = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()


def _read_skills_state_unlocked() -> Dict[str, bool]:
    sf = _state_file()
    if not sf.exists():
        return {}
    try:
        data = json.loads(sf.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {str(k): bool(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def _write_skills_state_unlocked(state: Dict[str, bool]) -> None:
    """Atomically publish capability state, never exposing truncated JSON."""
    sf = _state_file()
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(
        prefix=".skills_state.", suffix=".tmp", dir=str(sf.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, sf)
    finally:
        try:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        except OSError:
            pass


def load_skills_state() -> Dict[str, bool]:
    """Load per-skill enabled/disabled state. Returns {filename: enabled}."""
    with _skills_state_lock(exclusive=False):
        return _read_skills_state_unlocked()


def save_skills_state(state: Dict[str, bool]):
    """Persist per-skill enabled/disabled state atomically."""
    _ensure_dir()
    with _skills_state_lock(exclusive=True):
        _write_skills_state_unlocked({str(k): bool(v) for k, v in state.items()})


def is_skill_enabled(filename: str) -> bool:
    """Check if a specific skill file is enabled. Defaults to True."""
    state = load_skills_state()
    return state.get(filename, True)


def set_skill_enabled(filename: str, enabled: bool):
    """Enable or disable a specific skill file atomically across workers."""
    # Keep read-modify-write under one exclusive lock; separate load/save calls
    # lose a concurrent worker's update even if each individual write is atomic.
    with _skills_state_lock(exclusive=True):
        state = _read_skills_state_unlocked()
        state[str(filename)] = bool(enabled)
        _write_skills_state_unlocked(state)


def _gather_skill_files() -> List[Path]:
    """Enumerate skill files from ENABLED packs (registry), with a filesystem
    fallback. Shared by load_skills() and _active_skill_names() so the direct
    context and the RAG context always agree on which skill files exist."""
    _ensure_dir()
    learned_pack_enabled = True
    try:
        from backend.skill_packs import get_registry, ensure_default_packs_seeded
        ensure_default_packs_seeded()
        # Always bind registry to current LOTUS_SKILLS_DIR / SKILLS_DIR
        registry = get_registry(force_reload=True)
        # If skills.py SKILLS_DIR differs (tests), construct explicitly
        if Path(registry.skills_dir).resolve() != SKILLS_DIR.resolve():
            from backend.skill_packs import SkillPackRegistry
            registry = SkillPackRegistry(skills_dir=SKILLS_DIR)
        files = list(registry.list_skill_files())
        lp = registry.get("learned")
        if lp is not None:
            learned_pack_enabled = bool(lp.enabled)
    except Exception:
        files = []
        for subdir in ("methodology", "gating", "discovery", "bug-classes", "learned"):
            sub = SKILLS_DIR / subdir
            if sub.exists():
                files.extend(sorted(sub.glob("*.md")))
    # BYOS doctrine roots often keep .md files at the directory root. Registry
    # packs only glob category subdirs, so always union root-level skills.
    try:
        seen = {p.resolve() for p in files}
        for f in sorted(SKILLS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.name.lower() == "readme.md":
                continue
            if f.resolve() not in seen:
                files.append(f)
                seen.add(f.resolve())
    except Exception:
        pass
    if learned_pack_enabled:
        try:
            learned = get_learned_dir()
            if learned.exists():
                seen = {p.resolve() for p in files}
                for f in sorted(learned.glob("*.md")):
                    if f.resolve() not in seen:
                        files.append(f)
                        seen.add(f.resolve())
        except Exception:
            pass
    return files


def _active_skill_names() -> set:
    """Filenames currently active for AI context: files from ENABLED packs minus
    per-skill DISABLED entries (Capabilities tab). Single source of truth shared
    by load_skills() and the RAG search (vector/hybrid) so toggling a skill or a
    pack loads/unloads it from EVERY context path, regardless of model/provider."""
    state = load_skills_state()
    return {f.name for f in _gather_skill_files() if state.get(f.name, True)}


def reindex_skills() -> Dict[str, Any]:
    """Re-scan the skills directory and update state for any new/removed files.
    
    Returns stats about what changed.
    """
    _ensure_dir()
    with _skills_state_lock(exclusive=True):
        state = _read_skills_state_unlocked()
        current_files = {f.name for f in _gather_skill_files()}

        existing = set(state.keys())
        added = current_files - existing
        removed = existing - current_files

        # Add new files as enabled by default
        for fname in added:
            state[fname] = True

        # Remove state for deleted files
        for fname in removed:
            state.pop(fname, None)

        if added or removed:
            _write_skills_state_unlocked(state)
    
    return {
        "total": len(current_files),
        "enabled": sum(1 for v in state.values() if v),
        "disabled": sum(1 for v in state.values() if not v),
        "added": sorted(added),
        "removed": sorted(removed),
    }


def get_capabilities_summary() -> Dict[str, Any]:
    """Get a summary of all capabilities (skills) with their enabled state."""
    skills = list_skills()
    state = load_skills_state()
    
    enabled_count = 0
    disabled_count = 0
    for s in skills:
        fname = s["filename"]
        s["enabled"] = state.get(fname, True)
        if s["enabled"]:
            enabled_count += 1
        else:
            disabled_count += 1
    
    # Group by category
    categories = {}
    for s in skills:
        cat = s.get("category", "general")
        if cat not in categories:
            categories[cat] = {"total": 0, "enabled": 0, "disabled": 0}
        categories[cat]["total"] += 1
        if s.get("enabled", True):
            categories[cat]["enabled"] += 1
        else:
            categories[cat]["disabled"] += 1
    
    return {
        "skills": skills,
        "total": len(skills),
        "enabled": enabled_count,
        "disabled": disabled_count,
        "categories": categories,
        "skills_dir": str(SKILLS_DIR),
        **skills_roots(),
    }


def seed_audit_methodology_skills() -> int:
    """Seed default packs + methodology content. Returns files newly written."""
    try:
        from backend.skill_packs import ensure_default_packs_seeded, SkillPackRegistry
        # Prefer skills.py SKILLS_DIR (tests may patch it)
        from backend.skill_seeds import seed_all
        _ensure_dir()
        get_learned_dir().mkdir(parents=True, exist_ok=True)
        seeded = seed_all(SKILLS_DIR)
        # Also ensure pack manifests under this same root
        os.environ["LOTUS_SKILLS_DIR"] = str(SKILLS_DIR)
        ensure_default_packs_seeded()
        return seeded
    except Exception:
        _ensure_dir()
        from backend.skill_seeds import seed_all
        return seed_all(SKILLS_DIR)


def get_skill_revisions(filename: str) -> List[Dict]:
    """Get revision history for a skill file."""
    _ensure_dir()
    rev_dir = _revisions_dir()
    if not rev_dir.exists():
        return []
    # Extract stem to match revisions
    stem = Path(filename).stem
    revisions = []
    for f in sorted(rev_dir.glob(f"{stem}--rev-*.md"), key=lambda p: p.name, reverse=True):
        try:
            content = f.read_text(encoding="utf-8")
            # Extract timestamp from filename
            rev_ts = f.stem.rsplit("--rev-", 1)[-1] if "--rev-" in f.stem else ""
            revisions.append({
                "filename": f.name,
                "timestamp": rev_ts,
                "content": content,
                "size": f.stat().st_size,
            })
        except Exception:
            continue
    return revisions


# ---------------------------------------------------------------------------
# LangChain RAG Vector Store
# ---------------------------------------------------------------------------

def vector_search_skills(query: str, language: Optional[str] = None, top_k: int = 5) -> List[Dict[str, Any]]:
    """LangChain RAG semantic vector search over skill files."""
    seed_audit_methodology_skills()
    skills_list = list_skills()
    # Respect Capabilities-tab toggles + pack enable/disable so DESELECTED skills
    # are fully unloaded from context. load_skills() already excludes them from the
    # direct context; without this filter the RAG path (here + hybrid_search_skills,
    # used by the pipeline, analysis, and LangGraph) would silently re-inject them.
    _active = _active_skill_names()
    skills_list = [s for s in skills_list if s.get("filename", "") in _active]
    if not skills_list:
        return []

    from langchain_core.documents import Document
    docs = []
    for item in skills_list:
        filename = item.get("filename", "")
        # Prefer pack-relative path when available
        content = get_skill_content(item.get("path") or filename) or get_skill_content(filename) or ""
        title = item.get("title", filename)
        cat = item.get("category", "general")
        lang = item.get("language", "unknown")
        
        # Filter by language if specified
        if language and lang != "unknown" and language.lower() not in lang.lower():
            continue

        doc = Document(
            # Index a wide slice so the strengthened doctrine bodies (discovery
            # vectors + cross-language examples) are retrievable, not just the header.
            page_content=f"# {title}\nCategory: {cat}\nLanguage: {lang}\n\n{content[:4000]}",
            metadata={"filename": filename, "title": title, "category": cat, "language": lang}
        )
        docs.append(doc)

    if not docs:
        return []

    # Fast in-memory RAG document scoring (BM25-style with TF-IDF)
    import math
    from collections import Counter
    
    q_words = query.lower().split()
    
    # Calculate document frequencies (DF) for TF-IDF
    doc_freqs = Counter()
    doc_words_list = []
    
    for d in docs:
        d_words = d.page_content.lower().split()
        doc_words_list.append((d, d_words))
        # Unique words in this document
        unique_words = set(d_words)
        for w in unique_words:
            doc_freqs[w] += 1
            
    num_docs = len(docs)
    
    scored = []
    for d, d_words in doc_words_list:
        text_lower = d.page_content.lower()
        score = 0.0
        
        # Calculate Term Frequency (TF) for this doc
        tf_counts = Counter(d_words)
        doc_len = len(d_words)
        
        # BM25-style scoring with TF-IDF weighting
        for w in q_words:
            if w in tf_counts:
                tf = tf_counts[w] / max(1, doc_len)
                # Inverse Document Frequency (IDF)
                idf = math.log(num_docs / max(1, doc_freqs[w]))
                score += tf * idf
                
                # Exact word overlap base score (legacy compatibility)
                score += 1.0
                
        # Language-specific skill boosting (3x boost for matching target language)
        if language and d.metadata["language"] != "unknown" and language.lower() in d.metadata["language"].lower():
            score *= 3.0
        elif language and language.lower() in text_lower:
            score += 2.0
            
        scored.append((score, d.metadata["filename"], d.metadata["title"], d.page_content))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for score, filename, title, content in scored[:top_k]:
        results.append({
            "filename": filename,
            "title": title,
            "score": score,
            "content": content,
        })
    return results


_EMBEDDER = "unset"          # "unset" -> not yet probed; None -> unavailable; else a callable
_EMBED_CACHE: Dict[str, Any] = {}   # content-hash -> vector


def _get_embedder():
    """Lazily resolve a dense-embedding backend. Optional and dependency-free by default:
      1. sentence-transformers (LOTUS_EMBED_MODEL, default all-MiniLM-L6-v2) if installed.
      2. else a local Ollama/OpenAI-compatible /api/embeddings endpoint if LOTUS_EMBED_URL set.
      3. else None -> hybrid retrieval falls back to BM25 + char-ngram (still a real hybrid).
    Returns a callable(list[str]) -> list[vector] or None. Cached per process.
    """
    global _EMBEDDER
    if _EMBEDDER != "unset":
        return _EMBEDDER
    if os.environ.get("LOTUS_EMBEDDINGS", "auto").strip().lower() in ("0", "off", "false", "no"):
        _EMBEDDER = None
        return None
    # Backend 1: sentence-transformers (best quality, offline once downloaded).
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        model_name = os.environ.get("LOTUS_EMBED_MODEL", "all-MiniLM-L6-v2")
        _model = SentenceTransformer(model_name)
        _EMBEDDER = lambda texts: [list(map(float, v)) for v in _model.encode(list(texts))]
        return _EMBEDDER
    except Exception:
        pass
    # Backend 2: remote embeddings endpoint (e.g. Ollama `nomic-embed-text`).
    _url = os.environ.get("LOTUS_EMBED_URL", "").strip()
    _emodel = os.environ.get("LOTUS_EMBED_MODEL", "nomic-embed-text")
    if _url:
        import httpx as _httpx

        def _remote(texts):
            out = []
            with _httpx.Client(timeout=20) as c:
                for t in texts:
                    r = c.post(_url, json={"model": _emodel, "prompt": t})
                    r.raise_for_status()
                    d = r.json()
                    out.append([float(x) for x in (d.get("embedding") or d.get("data", [{}])[0].get("embedding", []))])
            return out
        _EMBEDDER = _remote
        return _EMBEDDER
    _EMBEDDER = None
    return None


def _embed_one(text: str) -> Optional[List[float]]:
    emb = _get_embedder()
    if emb is None:
        return None
    import hashlib
    key = hashlib.sha1((text or "")[:4000].encode("utf-8", "ignore")).hexdigest()
    if key in _EMBED_CACHE:
        return _EMBED_CACHE[key]
    try:
        vec = emb([text or ""])[0]
    except Exception:
        return None
    _EMBED_CACHE[key] = vec
    if len(_EMBED_CACHE) > 4000:
        for k in list(_EMBED_CACHE.keys())[:1000]:
            _EMBED_CACHE.pop(k, None)
    return vec


def _vec_cosine(a: Optional[List[float]], b: Optional[List[float]]) -> float:
    import math
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _char_ngrams(text: str, n: int = 3) -> "Counter":
    """Character n-gram multiset  - a lexical-fuzzy signal that survives tokenization,
    typos, and morphological variants (e.g. 'deserialize' vs 'deserialization')."""
    from collections import Counter
    t = re.sub(r"\s+", " ", (text or "").lower())
    if len(t) < n:
        return Counter([t]) if t else Counter()
    return Counter(t[i:i + n] for i in range(len(t) - n + 1))


def _cosine(a: "Counter", b: "Counter") -> float:
    """Cosine similarity between two sparse n-gram vectors."""
    import math
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[g] * b[g] for g in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def hybrid_search_skills(query: str, language: Optional[str] = None, top_k: int = 5) -> List[Dict[str, Any]]:
    """Genuine hybrid retrieval over the skills corpus.

    Fuses two INDEPENDENT similarity signals with Reciprocal Rank Fusion:
      1. Token BM25/TF-IDF lexical relevance (`vector_search_skills`).
      2. Character-3-gram cosine similarity (fuzzy/semantic-ish; catches morphological
         and typo variants that token matching misses).
    This is a real hybrid  - the two rankings disagree and complement each other  -
    rather than RRF over a single signal. (Dense embeddings remain a P2 upgrade; the
    char-ngram signal gives most of the fuzzy-match benefit with zero heavy deps.)
    """
    # Wider candidate recall from the lexical signal, then re-rank + fuse.
    candidates = vector_search_skills(query, language=language, top_k=max(top_k * 3, 15))
    if not candidates:
        return []

    # Signal 1: BM25 order (already sorted by vector_search_skills).
    bm25_rank = {item["filename"]: r for r, item in enumerate(candidates)}

    # Signal 2: char-ngram cosine of the query against each candidate's content.
    q_vec = _char_ngrams(query)
    ngram_scored = sorted(
        candidates,
        key=lambda it: _cosine(q_vec, _char_ngrams(it.get("content", ""))),
        reverse=True,
    )
    ngram_rank = {item["filename"]: r for r, item in enumerate(ngram_scored)}

    # Signal 3 (optional): dense-embedding cosine, if an embedding backend is available.
    # Genuine semantic similarity; degrades gracefully to the 2-signal hybrid when absent.
    emb_rank: Dict[str, int] = {}
    q_emb = _embed_one(query)
    if q_emb is not None:
        emb_scored = sorted(
            candidates,
            key=lambda it: _vec_cosine(q_emb, _embed_one(it.get("content", ""))),
            reverse=True,
        )
        emb_rank = {item["filename"]: r for r, item in enumerate(emb_scored)}

    # Reciprocal Rank Fusion across the independent rankings (2 or 3 signals).
    k = 60
    skill_data = {item["filename"]: item for item in candidates}
    rrf: Dict[str, float] = {}
    for fn in skill_data:
        rrf[fn] = 1.0 / (k + bm25_rank.get(fn, len(candidates)) + 1) \
            + 1.0 / (k + ngram_rank.get(fn, len(candidates)) + 1)
        if emb_rank:
            rrf[fn] += 1.0 / (k + emb_rank.get(fn, len(candidates)) + 1)

    results = []
    for fn, score in sorted(rrf.items(), key=lambda x: x[1], reverse=True)[:top_k]:
        item = skill_data[fn]
        item["score"] = score
        results.append(item)
    return results
