"""Phase-1 scanner: config-DSL -> generated-shell command injection.

Language-agnostic detector for the target class that previously slipped through
every gate: a tool that reads a config/DSL file (YAML/JSON/TOML) and emits or
executes a shell script, where an un-sanitised *data* field (a filename, option,
image, or arg - NOT a designated shell/command field) flows into command
position of the generated script.

This scanner is intentionally NOT tied to any project: everything (the sink
files, the sample recipes, the injectable fields, the tool's default config
name, the binary names) is discovered from the target. It emits leads carrying
structured ``config_dsl`` metadata that the Phase-2 native PoC harness
(``config_dsl_poc.build_config_dsl_probes``) consumes to build a proving test.
"""
from pathlib import Path
from typing import Any, Dict, List


def _run_config_shell_injection_audit(dest: Path, language: str) -> List[Dict[str, Any]]:
    """Detect config-DSL -> shell generators and emit injection leads.

    Returns [] for targets that are not config-driven shell generators, so it is
    safe to register for all languages (it self-gates on source evidence).
    """
    try:
        from backend.config_dsl_poc import detect_config_dsl_target
    except Exception:
        return []

    target = detect_config_dsl_target(dest)
    if not target:
        return []

    sink_file = target.get("sink_file") or "src"
    default_name = target.get("default_config_name")
    fmt = target.get("config_format") or "yaml"
    fields = target.get("injectable_fields") or []
    meta = {
        "default_config_name": default_name,
        "binary_names": target.get("binary_names") or [],
        "config_format": fmt,
        "recipes": [rp for rp, _ in (target.get("recipes") or [])][:8],
    }

    leads: List[Dict[str, Any]] = []
    # One lead per distinct injectable data field (capped), each PoC-ready.
    seen: set = set()
    for fld in fields:
        key = (fld.get("recipe"), fld.get("field"))
        if key in seen:
            continue
        seen.add(key)
        field = fld.get("field", "")
        recipe = fld.get("recipe", "")
        leads.append({
            "tool": "config-shell-injection",
            "title": (
                f"Config-DSL command injection: '{field}' flows into generated shell"
            ),
            "cvss": 8.8,
            "description": (
                f"The tool reads a {fmt} recipe and generates/executes a shell script. "
                f"The data field '{field}' (from recipe '{recipe}') is concatenated into "
                f"command position without shell-escaping, so a value containing shell "
                f"metacharacters (;, $(), backticks) is executed when the generated script "
                f"runs. Non-command fields like this are not meant to grant shell access, "
                f"so this is an injection - distinct from by-design script/bash fields. "
                f"Sink: {sink_file}."
            ),
            "file": sink_file,
            "line": 0,
            "confidence": "high",
            "qualification": "QUALIFIED",
            "domain": "injection",
            "class": "command_injection",
            "cwe": "CWE-78",
            # Structured metadata consumed by the Phase-2 native PoC harness.
            "config_dsl": {**meta, "injectable_field": field, "recipe": recipe},
        })
        if len(leads) >= 8:
            break

    # If detection fired but no explicit field was extracted (e.g. YAML missing),
    # still emit a single class lead so the PoC harness engages.
    if not leads:
        leads.append({
            "tool": "config-shell-injection",
            "title": "Config-DSL command injection: untrusted recipe value into generated shell",
            "cvss": 8.5,
            "description": (
                f"The tool reads a {fmt} recipe and generates/executes shell. Recipe values "
                f"appear to reach command position without escaping. Sink: {sink_file}."
            ),
            "file": sink_file,
            "line": 0,
            "confidence": "medium",
            "qualification": "QUALIFIED",
            "domain": "injection",
            "class": "command_injection",
            "cwe": "CWE-78",
            "config_dsl": meta,
        })
    return leads
