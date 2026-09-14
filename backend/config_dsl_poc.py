"""Native PoC engine for compiled CLI tools that consume a config/DSL and then
emit or execute a shell script (e.g. microCI: ``.microCI.yml`` -> generated bash).

Why this exists
---------------
The LangGraph proof gate only runs an *HTTP* probe matrix, and the legacy CLI
probe shapes (``_lead_driven_cli_probes``) only fit *Python* tools (``tool.py``,
argparse flags, ``!!python/object`` YAML). A compiled config-DSL tool like
microCI has neither an HTTP surface nor a Python entrypoint, so every lead -
including Joern's data-flow flows and the ``taint-proximity`` template/shell
interpolation hits - could never be lab-proven and 315 candidates collapsed to
0 confirmed.

This engine closes that structural gap. It is target-agnostic: it reuses the
target's *own* sample recipes as known-valid templates, poisons a NON-command
field (an ``options``/``args``/``source`` style value or a plain filename) with a
shell metacharacter canary, runs the built binary, and confirms the canary
reaches *command position* (i.e. survives un-quoted) in the generated shell.

The oracle is sound: a canary token immediately followed by an un-quoted ``;id``
in the generated script proves the tool failed to sanitise/quote an
attacker-influenced value before emitting it into an executable shell context.
Values that the tool correctly single-quotes are ignored (true negative).
"""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # pyyaml is a hard dep of the backend; guard anyway for import safety
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False

# Unique, metacharacter-free marker. The ``;id`` that follows it in the poisoned
# value is the injection: if it survives un-quoted into the generated script,
# the tool is injectable.
MARKER = "LOTUSxCFGINJ"
INJECT_VALUE = f"{MARKER};id"

# Keys whose values are *meant* to be shell/code - injecting here is by-design
# (like GitHub Actions ``run:``) and must never be treated as a vulnerability.
COMMAND_KEYS = {
    "bash", "sh", "shell", "script", "run", "command", "commands", "cmd",
    "exec", "eval", "entrypoint", "code", "program",
}
# Keys the tool commonly sanitises (step identifiers, metadata) - poisoning them
# yields dead probes, so we skip them entirely.
NON_INJECTABLE_KEYS = {
    "name", "description", "desc", "version", "only", "network", "user",
    "stage", "needs", "when", "id", "type",
}
# Keys whose values are semantically data (filenames, flags, options, images)
# but flow into generated shell - these are the genuine injection surface.
PREFERRED_KEYS = {
    "options", "option", "opts", "args", "arguments", "flags", "checks",
    "source", "sources", "input", "inputs", "include", "output", "outputs",
    "image", "images", "file", "files", "filename", "template", "path",
    "paths", "tag", "params", "dir", "target", "url",
}

# Source-level signals that a (compiled) tool generates or executes shell.
_SHELL_GEN_PATTERNS = [
    r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecl\w*\s*\(", r"\bexecv\w*\s*\(",
    r"->Script\s*\(\)", r"\bScript\s*\(\)\s*<<", r"std::ofstream",
    r"exec\.Command", r"os/exec", r"\"-c\"", r"Command::new",
    r"std::process", r"fmt::format", r"inja::render",
]
_CONFIG_READ_PATTERNS = [
    r"YAML::", r"yaml-cpp", r"serde_yaml", r"gopkg\.in/yaml", r"viper",
    r"\.as<std::string>\(\)", r"yaml\.safe_load", r"toml::", r"json::parse",
]
_COMPILED_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".go", ".rs"}
_RECIPE_STRUCTURAL_KEYS = {"steps", "jobs", "stages", "pipeline", "tasks", "plugin", "workflow"}


_SKIP_PARTS = {"3rd", "vendor", "node_modules", ".git", "build", "dist", "__pycache__"}


def _is_skippable(p: Path, dest: Path, skip_tests: bool = False) -> bool:
    """Skip vendored/build dirs by RELATIVE path parts (never the absolute path,
    which may itself contain words like 'test' e.g. under pytest tmp dirs)."""
    try:
        parts = set(p.relative_to(dest).parts)
    except Exception:
        return False
    if parts & _SKIP_PARTS:
        return True
    if skip_tests and (parts & {"test", "tests"}):
        return True
    return False


def _read_text(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _looks_like_recipe(text: str) -> bool:
    if not _HAVE_YAML:
        return False
    try:
        data = yaml.safe_load(text)
    except Exception:
        return False
    if not isinstance(data, (dict, list)):
        return False
    blob = text.lower()
    return any(k in blob for k in _RECIPE_STRUCTURAL_KEYS)


def _has_injectable_field(text: str) -> bool:
    if not _HAVE_YAML:
        return False
    try:
        data = yaml.safe_load(text)
    except Exception:
        return False
    return bool(_walk_inject_ops(data)) if isinstance(data, (dict, list)) else False


def _discover_recipes(dest: Path, max_recipes: int = 8) -> List[Tuple[str, str]]:
    """Return [(rel_path, text)] of the target's own YAML recipes.

    Ranked so recipes that actually expose an injectable data field come first,
    then by size (smallest first) for fast, deterministic PoCs.
    """
    cands: List[Tuple[int, int, str, str]] = []
    patterns = ("*.yml", "*.yaml", ".*.yml", ".*.yaml")
    seen: set = set()
    for pat in patterns:
        for p in dest.rglob(pat):
            rp = str(p.relative_to(dest))
            if rp in seen:
                continue
            # skip vendored / build dirs (by relative parts, not absolute path)
            if _is_skippable(p, dest):
                continue
            try:
                size = p.stat().st_size
            except Exception:
                continue
            if size == 0 or size > 64_000:
                continue
            text = _read_text(p)
            if _looks_like_recipe(text):
                seen.add(rp)
                inj_rank = 0 if _has_injectable_field(text) else 1
                cands.append((inj_rank, size, rp, text))
    cands.sort(key=lambda t: (t[0], t[1]))
    return [(rp, text) for _, _, rp, text in cands[:max_recipes]]


def _source_shell_gen_evidence(dest: Path, max_files: int = 400) -> Optional[str]:
    """Return a representative sink file iff the compiled source generates/execs shell."""
    shell_gen = re.compile("|".join(_SHELL_GEN_PATTERNS))
    config_read = re.compile("|".join(_CONFIG_READ_PATTERNS))
    has_shell = has_config = False
    best_file: Optional[str] = None
    scanned = 0
    for p in dest.rglob("*"):
        if scanned >= max_files:
            break
        if not p.is_file() or p.suffix.lower() not in _COMPILED_EXTS:
            continue
        if _is_skippable(p, dest):
            continue
        scanned += 1
        text = _read_text(p, limit=120_000)
        if shell_gen.search(text):
            has_shell = True
            if best_file is None:
                try:
                    best_file = str(p.relative_to(dest))
                except Exception:
                    best_file = p.name
        if config_read.search(text):
            has_config = True
        if has_shell and has_config and best_file:
            return best_file
    return None


def _walk_inject_ops(node: Any, path: str = "") -> List[Tuple[List[Any], str]]:
    """Collect injection ops as (accessor_path, kind).

    kind is 'seq_append' (append a poisoned item to a scalar sequence) or
    'scalar_set' (replace a scalar string leaf). Command-key values are skipped.
    """
    ops: List[Tuple[List[Any], str]] = []

    def _recurse(n: Any, acc: List[Any], key: Optional[str]):
        if isinstance(n, dict):
            for k, v in n.items():
                _recurse(v, acc + [k], str(k))
        elif isinstance(n, list):
            key_low = (key or "").lower()
            is_command = any(c in key_low for c in COMMAND_KEYS)
            is_skip = key_low in NON_INJECTABLE_KEYS
            all_scalars = all(isinstance(x, (str, int, float)) for x in n) if n else False
            if not is_command and not is_skip and all_scalars and n:
                ops.append((acc, "seq_append"))
            for i, v in enumerate(n):
                _recurse(v, acc + [i], key)
        elif isinstance(n, str):
            key_low = (key or "").lower()
            if (
                key_low
                and not any(c in key_low for c in COMMAND_KEYS)
                and key_low not in NON_INJECTABLE_KEYS
            ):
                ops.append((acc, "scalar_set"))

    _recurse(node, [], None)

    # Prioritise preferred keys, then everything else. seq_append before scalar_set.
    def _score(op: Tuple[List[Any], str]) -> Tuple[int, int]:
        acc, kind = op
        key = next((str(x) for x in reversed(acc) if isinstance(x, str)), "").lower()
        pref = 0 if any(k in key for k in PREFERRED_KEYS) else 1
        kindscore = 0 if kind == "seq_append" else 1
        return (pref, kindscore)

    ops.sort(key=_score)
    return ops


def _apply_op(data: Any, acc: List[Any], kind: str) -> Any:
    out = copy.deepcopy(data)
    node = out
    for step in acc:
        node = node[step]
    if kind == "seq_append" and isinstance(node, list):
        node.append(INJECT_VALUE)
    else:  # scalar_set: navigate to parent and set the leaf
        parent = out
        for step in acc[:-1]:
            parent = parent[step]
        parent[acc[-1]] = INJECT_VALUE
    return out


def build_injected_recipes(text: str, max_variants: int = 3) -> List[Tuple[str, str]]:
    """Return [(mutated_yaml, field_desc)] poisoning non-command fields.

    Falls back to a line-based injection when the YAML cannot be re-serialised.
    """
    variants: List[Tuple[str, str]] = []
    if _HAVE_YAML:
        try:
            data = yaml.safe_load(text)
        except Exception:
            data = None
        if isinstance(data, (dict, list)):
            for acc, kind in _walk_inject_ops(data)[:max_variants]:
                try:
                    mutated = _apply_op(data, acc, kind)
                    dumped = yaml.safe_dump(mutated, default_flow_style=False, sort_keys=False)
                    field = ".".join(str(x) for x in acc) or "(root)"
                    variants.append((dumped, f"{field} [{kind}]"))
                except Exception:
                    continue
    if variants:
        return variants
    # Line-based fallback: append a poisoned item under the first options/args list.
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s*)([A-Za-z_]+)\s*:\s*$", ln)
        if m and m.group(2).lower() in PREFERRED_KEYS:
            indent = m.group(1) + "  "
            lines.insert(i + 1, f"{indent}- \"{INJECT_VALUE}\"")
            return [("\n".join(lines), f"{m.group(2)} [line_append]")]
    return []


def _guess_binary_names(dest: Path) -> List[str]:
    names: List[str] = []
    proj = dest.name
    for n in (proj, proj.lower(), proj.replace("-", ""), proj.lower().replace("-", "")):
        if n and n not in names:
            names.append(n)
    # README usage lines like `microCI | bash`
    for readme in ("README.md", "README", "README.rst"):
        rp = dest / readme
        if rp.exists():
            txt = _read_text(rp, limit=40_000)
            for m in re.finditer(r"(?m)^\s*\$?\s*([A-Za-z][\w.-]{2,30})\s*\|\s*bash", txt):
                if m.group(1) not in names:
                    names.append(m.group(1))
    return names[:6]


def oracle_hit(output: str) -> Optional[str]:
    """Return the offending generated line iff the canary reached command position.

    The marker must be followed by an un-quoted ``;id``. Single-quoted spans are
    stripped first so correctly-escaped values do NOT produce a false positive.
    """
    if not output or MARKER not in output:
        return None
    needle = f"{MARKER};id"
    for line in output.splitlines():
        if MARKER not in line:
            continue
        # Remove single-quoted regions - anything the tool safely quoted.
        stripped = re.sub(r"'[^']*'", "", line)
        if needle in stripped:
            return line.strip()[:200]
    return None


_DEFAULT_NAME_RE = re.compile(
    r"""["']((?:\.?[\w][\w.\-]*/)*\.?[\w][\w.\-]*\.(?:ya?ml|json|toml|ini|conf|cfg))["']"""
)


def detect_default_config_name(dest: Path) -> Optional[str]:
    """Find the config filename the binary defaults to, from its own source.

    General across languages: looks for a string literal that (a) matches a
    config-file shape and (b) sits near default/config/input/file keywords -
    e.g. microCI's ``auto yamlFileName = std::string{".microCI.yml"};``. This is
    how the engine writes the recipe under the name the tool auto-reads, without
    hardcoding any project-specific filename.
    """
    best: Optional[str] = None
    best_score = -1
    for p in dest.rglob("*"):
        if best_score >= 3:
            break
        if not p.is_file() or p.suffix.lower() not in (_COMPILED_EXTS | {".py", ".rb", ".js", ".ts"}):
            continue
        if _is_skippable(p, dest, skip_tests=True):
            continue
        text = _read_text(p, limit=120_000)
        if not text:
            continue
        for m in re.finditer(_DEFAULT_NAME_RE, text):
            fname = m.group(1)
            base = fname.rsplit("/", 1)[-1]
            ctx = text[max(0, m.start() - 60): m.start()].lower()
            score = 0
            if any(k in ctx for k in ("default", "config", "input", "file", "yaml", "recipe", "pipeline")):
                score += 2
            if base.startswith("."):  # dotfile default (.microCI.yml, .gitlab-ci.yml)
                score += 2
            if any(k in base.lower() for k in ("ci", "config", "pipeline", "recipe")):
                score += 1
            if score > best_score:
                best_score, best = score, base
    return best if best_score >= 2 else None


def detect_config_dsl_target(dest: Path) -> Optional[Dict[str, Any]]:
    """Language-agnostic detection of a config-DSL -> shell generator/executor.

    Returns structured metadata (or None) used by BOTH the Phase-1 scanner (to
    emit leads) and the PoC harness (to build tests). Nothing here is tied to a
    specific project - every value is discovered from the target.
    """
    sink_file = _source_shell_gen_evidence(dest)
    if not sink_file:
        return None
    recipes = _discover_recipes(dest)
    if not recipes:
        return None
    default_name = detect_default_config_name(dest)
    fields: List[Dict[str, str]] = []
    if _HAVE_YAML:
        for rp, text in recipes:
            try:
                data = yaml.safe_load(text)
            except Exception:
                continue
            for acc, kind in _walk_inject_ops(data)[:3]:
                fields.append({
                    "recipe": rp,
                    "field": ".".join(str(x) for x in acc) or "(root)",
                    "kind": kind,
                })
    return {
        "sink_file": sink_file,
        "recipes": recipes,
        "binary_names": _guess_binary_names(dest),
        "default_config_name": default_name,
        "config_format": Path(recipes[0][0]).suffix.lstrip(".") or "yaml",
        "injectable_fields": fields,
    }


def _build_probe_script(config_names: List[str], recipe: str, binary_names: List[str],
                        marker: str = MARKER, build_setup: str = "") -> str:
    names = " ".join(re.escape(n) for n in binary_names) or "cli"
    # De-dup while preserving order; the recipe is written under every candidate
    # name so both default-cwd readers and explicit-arg tools are covered.
    seen: set = set()
    cfg_names = [c for c in config_names if c and not (c in seen or seen.add(c))] or ["config.yml"]
    write_files = "\n".join(f'cp "$RECIPE" "{c}" 2>/dev/null || true' for c in cfg_names)
    cfg_args = " ".join(f'"{c}"' for c in cfg_names) or '"config.yml"'
    # Self-heal build: derived generically from the repo (deps + non-bootstrap
    # build + amalgamation fallback) so a serve-only lab image without the binary
    # does not block the native PoC. Runs only if the binary isn't already there.
    build_block = build_setup or (
        "make -j2 >/dev/null 2>&1 || "
        "( cmake -B build >/dev/null 2>&1 && cmake --build build -j2 >/dev/null 2>&1 ) || "
        "( [ -d src ] && make -C src -j2 >/dev/null 2>&1 ) || true"
    )
    # Heredoc uses a quoted delimiter so $(...) / ; in the recipe are preserved verbatim.
    return f"""
set +e
NAMES="{names}"
find_bin() {{
  for n in $NAMES; do p=$(command -v "$n" 2>/dev/null); [ -n "$p" ] && {{ echo "$p"; return 0; }}; done
  for n in $NAMES; do
    p=$(find /app /usr/local /root /build /src -maxdepth 6 -type f -name "$n" -perm -u+x 2>/dev/null | head -1)
    [ -n "$p" ] && {{ echo "$p"; return 0; }}
  done
  return 1
}}
BIN=$(find_bin)
if [ -z "$BIN" ]; then
  ( cd /app 2>/dev/null || cd /src 2>/dev/null || true
{build_block}
  )
  BIN=$(find_bin)
fi
[ -z "$BIN" ] && {{ echo "LOTUS_NO_BINARY"; exit 4; }}
D=$(mktemp -d) && cd "$D" || exit 3
RECIPE="$D/.lotus_recipe"
cat > "$RECIPE" <<'LOTUS_RECIPE_EOF'
{recipe}
LOTUS_RECIPE_EOF
{write_files}
OUT=$("$BIN" 2>&1)
for CFG in {cfg_args}; do
  echo "$OUT" | grep -q "{marker}" && break
  OUT=$("$BIN" -i "$CFG" 2>&1)
  echo "$OUT" | grep -q "{marker}" && break
  OUT=$("$BIN" --input "$CFG" 2>&1)
  echo "$OUT" | grep -q "{marker}" && break
  OUT=$("$BIN" "$CFG" 2>&1)
  echo "$OUT" | grep -q "{marker}" && break
  OUT=$("$BIN" -f "$CFG" 2>&1)
done
printf '%s\\n' "$OUT"
"""


def _config_name_candidates(target: Dict[str, Any], leads: Optional[List[Dict[str, Any]]]) -> List[str]:
    """Filenames to write the poisoned recipe as, most-authoritative first.

    Order: the tool's detected default config name -> any lead-supplied name ->
    dotfile recipe basenames the target ships -> other recipe basenames. Nothing
    hardcoded to a specific project.
    """
    names: List[str] = []
    if target.get("default_config_name"):
        names.append(target["default_config_name"])
    for l in (leads or []):
        meta = (l or {}).get("config_dsl") or {}
        if meta.get("default_config_name"):
            names.append(meta["default_config_name"])
    recipes = target.get("recipes") or []
    for rp, _ in recipes:
        base = Path(rp).name
        if base.startswith(".") and base.lower().endswith((".yml", ".yaml")):
            names.append(base)
    for rp, _ in recipes:
        names.append(Path(rp).name)
    seen: set = set()
    return [n for n in names if n and not (n in seen or seen.add(n))]


def build_config_dsl_probes(dest: Path, leads: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Return docker-exec probes that prove config-DSL -> shell injection.

    Driven by generic detection (and any Phase-1 lead metadata under
    ``config_dsl``). Empty list when the target is not a config-driven shell
    generator, when no sample recipe exists, or when pyyaml is unavailable.
    """
    target = detect_config_dsl_target(dest)
    if not target:
        return []
    sink_file = target["sink_file"]
    recipes = target["recipes"]
    binary_names = target["binary_names"]
    config_names = _config_name_candidates(target, leads)
    # Generic self-heal: install inferred deps + build the target inside the lab
    # if the baked image didn't produce a binary. Never project-specific.
    try:
        from backend.native_build import build_setup_shell
        build_setup = build_setup_shell(dest, binary_names)
    except Exception:
        build_setup = ""

    probes: List[Dict[str, Any]] = []
    for rp, text in recipes:
        for mutated, field_desc in build_injected_recipes(text):
            script = _build_probe_script(config_names, mutated, binary_names, build_setup=build_setup)
            probes.append({
                "argv": ["bash", "-lc", script],
                "title": (
                    "Command injection via unsanitized config field into "
                    f"generated shell ({field_desc})"
                ),
                "cvss": 9.1,
                "check": lambda out: oracle_hit(out) is not None,
                "class": "command_injection",
                "file": sink_file,
                # Route through the config-injection gate carve-out (acceptance IS
                # the oracle) instead of the direct-RCE uid= requirement.
                "evidence_path": f"config-recipe-injection:{Path(rp).name}",
                "anomaly_type": "command_injection",
                "snippet_extract": oracle_hit,
                "timeout": 240.0,
            })
            if len(probes) >= 6:
                return probes
    return probes
