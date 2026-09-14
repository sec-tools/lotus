"""Report enrichment  - turn a persisted Finding into researcher- AND developer-grade
report sections.

Every finding section is built so that BOTH a vulnerability researcher and the code's
developer can, from the report alone:
  1. Read and understand the issue (title, complete evidence, root-cause code snippet +
     an accurate ASCII data-flow diagram).
  2. See the confirmation and its proof (the exact oracle/output that confirmed it),
     reachable by clicking the "confirmed" status in the UI.
  3. Reproduce it  - manually and inside the isolated local lab pod (runnable cells).
  4. Understand impact and the environment it was tested in.
  5. Remediate it: up to TWO ranked fixes, each shipping a concrete code diff, a
     regression test, a lab-runnable proof-that-the-fix-works, and before/after metrics.

Grounding / anti-hallucination
- Locations and code snippets are read from the finding's own cited file in the cloned
  repo (data/repos/<id>). Nothing file-specific is invented.
- Internal engine bookkeeping ("AISH CONFIRMED", "Gates: passed", harness iteration
  markers) is stripped from user-facing prose.
- Where a value cannot be derived it is labelled, not fabricated.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # reuse the fix classifier so classes stay consistent across the platform
    from backend.fix_suggestions import _blob as _fix_blob, _classify as _fix_classify
except Exception:  # pragma: no cover - defensive import
    def _fix_blob(f):  # type: ignore
        return " ".join(str(f.get(k) or "") for k in ("title", "description", "ai_response")).lower()

    def _fix_classify(_blob):  # type: ignore
        return "generic"


# Internal bookkeeping tokens that must never leak into user-facing prose.
_NOISE = re.compile(
    r"(AISH\s*CONFIRMED\s*\|?)"
    r"|(Harness iteration\s*\d+\s*\|?)"
    r"|(Gates?\s*:\s*(passed|pass|ok)\b\.?)"
    r"|(\bqualification\s*[:=]\s*\S+)"
    r"|(\bconviction[_ ]level\s*[:=]\s*\d+)",
    re.IGNORECASE,
)

_EXT_LANG = {
    ".py": "python", ".rb": "ruby", ".php": "php", ".js": "javascript", ".ts": "typescript",
    ".go": "go", ".java": "java", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".rs": "rust", ".sh": "bash", ".pl": "perl", ".ex": "elixir", ".scala": "scala",
}


# ---------------------------------------------------------------------------
# Location + source reading
# ---------------------------------------------------------------------------

def parse_location(finding: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    """Return (relative_file, line) parsed from explicit fields or the description."""
    file_ = str(finding.get("file") or "").strip()
    line = finding.get("line")
    desc = str(finding.get("description") or "")
    if not file_:
        m = re.search(r"file=([^\s|]+)", desc)
        if m:
            file_ = m.group(1)
    if file_ and ":" in file_ and (line is None):
        head, _, rest = file_.partition(":")
        if rest.split(":")[0].isdigit():
            line = int(rest.split(":")[0])
            file_ = head
    if line is None:
        m = re.search(r"\bline[=: ]+(\d+)", desc, re.IGNORECASE)
        if m:
            line = int(m.group(1))
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None
    return file_, line


def lang_for(file_: str) -> str:
    return _EXT_LANG.get(Path(file_).suffix.lower(), "")


def read_code_snippet(
    repo_id: Optional[int], file_: str, line: Optional[int], radius: int = 6, *, source_root: Optional[Path] = None
) -> Optional[Dict[str, Any]]:
    """Read a real code snippet around `line` from data/repos/<repo_id>/<file>.

    Returns {code, lang, start_line, end_line, focus_line} or None when unavailable.
    """
    if not repo_id or not file_:
        return None
    data_root = (os.environ.get("LOTUS_DATA_DIR") or "").strip()
    default = str(Path(data_root).expanduser() / "repos") if data_root else (
        "/app/data/repos" if os.path.isdir("/app") else str(
            Path(__file__).resolve().parent.parent / "data" / "repos")
    )
    base = Path(source_root) if source_root is not None else Path(os.environ.get("LOTUS_REPOS_DIR", default)) / str(repo_id)
    # Resolve the file defensively (reject traversal outside the repo root).
    candidate = (base / file_).resolve()
    try:
        base_res = base.resolve()
        if base_res not in candidate.parents and candidate != base_res:
            return None
    except Exception:
        return None
    if not candidate.is_file():
        return None
    try:
        text = candidate.read_text(errors="ignore").splitlines()
    except Exception:
        return None
    if not text:
        return None
    if not line or line < 1 or line > len(text):
        # No usable line -> show the first meaningful lines.
        start, end = 1, min(len(text), radius * 2)
        focus = None
    else:
        start = max(1, line - radius)
        end = min(len(text), line + radius)
        focus = line
    snippet = "\n".join(text[start - 1:end])
    return {
        "code": snippet,
        "lang": lang_for(file_),
        "start_line": start,
        "end_line": end,
        "focus_line": focus,
    }


# ---------------------------------------------------------------------------
# Evidence sanitising + source/sink inference
# ---------------------------------------------------------------------------

def clean_prose(text: str) -> str:
    """Strip internal engine tokens and tidy whitespace for user-facing prose."""
    if not text:
        return ""
    out = _NOISE.sub("", str(text))
    out = re.sub(r"\|\s*\|", "|", out)          # collapse emptied pipe separators
    out = re.sub(r"^\s*[|·]\s*", "", out)        # leading separators
    out = re.sub(r"\s*[|·]\s*$", "", out)        # trailing separators
    out = re.sub(r"[ \t]{2,}", " ", out)
    return out.strip(" |·\n\t")


# Per-class profile: human sink/source description + the concrete sink API names used to
# build accurate evidence and the data-flow diagram.
_CLASS_PROFILE: Dict[str, Dict[str, str]] = {
    "command_injection": {"source": "attacker-controlled request/argument", "sink": "OS command execution", "api": "system() / subprocess(shell=True) / exec"},
    "sql_injection": {"source": "attacker-controlled request parameter", "sink": "SQL query execution", "api": "cursor.execute / raw SQL string"},
    "ssti": {"source": "attacker-controlled string", "sink": "server-side template render", "api": "render_template_string / Template()"},
    "deserialization": {"source": "attacker-controlled bytes/body", "sink": "unsafe deserializer", "api": "pickle.loads / yaml.load / Marshal.load / readObject"},
    "path_traversal": {"source": "attacker-controlled path/filename", "sink": "filesystem open/read", "api": "open() / send_file"},
    "path_traversal_read": {"source": "attacker-controlled path/filename", "sink": "filesystem open/read", "api": "open() / send_file"},
    "path_traversal_write": {"source": "attacker-controlled path/filename", "sink": "filesystem write", "api": "open(w) / send_file"},
    "denial_of_service": {"source": "attacker-controlled malformed input", "sink": "unbounded work / hang", "api": "parser / recursive walk"},
    "memory_corruption": {"source": "attacker-controlled length/index", "sink": "unsafe memory operation", "api": "memcpy / strcpy / asan-class"},
    "ssrf": {"source": "attacker-controlled URL/host", "sink": "outbound HTTP fetch", "api": "requests.get / urlopen"},
    "xss": {"source": "attacker-controlled content", "sink": "HTML/JS response render", "api": "innerHTML / |safe / dangerouslySetInnerHTML"},
    "authz_bypass": {"source": "unauthenticated/unauthorized request", "sink": "privileged handler (missing guard)", "api": "route handler without authz check"},
    "weak_secret": {"source": "predictable/committed secret material", "sink": "auth/token/crypto use", "api": "random.* / hardcoded key"},
    "code_injection": {"source": "attacker-controlled expression", "sink": "dynamic code evaluation", "api": "eval / exec / Function / constantize"},
    "api_surface": {"source": "attacker-controlled API call", "sink": "dangerous exec/file API", "api": "/shell /bash /code /file surfaces"},
    "generic": {"source": "untrusted input", "sink": "the cited security-sensitive sink", "api": "see evidence"},
}


def infer_source_sink(finding: Dict[str, Any], bug_class: str) -> Tuple[str, str, str]:
    """Return (source, sink, sink_api) grounded in the class + any tokens in the finding."""
    try:
        from backend.ontology import normalize
        bug_class = normalize(bug_class)
    except Exception:
        pass
    prof = _CLASS_PROFILE.get(bug_class, _CLASS_PROFILE["generic"])
    desc = str(finding.get("description") or "")
    source = prof["source"]
    sink = prof["sink"]
    api = prof["api"]
    m = re.search(r"sink[=: ]+([^\s|]+)", desc, re.IGNORECASE)
    if m:
        api = m.group(1)
    m = re.search(r"(param|parameter|arg|input)[=: ]+([^\s|]+)", desc, re.IGNORECASE)
    if m:
        source = f"{prof['source']} (`{m.group(2)}`)"
    return source, sink, api


# ---------------------------------------------------------------------------
# ASCII data-flow diagram
# ---------------------------------------------------------------------------

def _box(lines: List[str], width: int) -> List[str]:
    top = "┌" + "─" * (width + 2) + "┐"
    bot = "└" + "─" * (width + 2) + "┘"
    body = [f"│ {ln.ljust(width)} │" for ln in lines]
    return [top] + body + [bot]


def flow_diagram(source: str, sink: str, sink_api: str, file_: str, line: Optional[int]) -> str:
    """Build a concise, accurate ASCII data-flow diagram: source -> propagation -> sink."""
    loc = file_ + (f":{line}" if line else "") if file_ else "cited sink"
    src_lines = ["UNTRUSTED SOURCE", _trim(source, 34)]
    mid = "reaches sink without sufficient"
    mid2 = "validation / sanitization / authz"
    sink_lines = ["SECURITY SINK", _trim(sink, 34), _trim(sink_api, 34), _trim(loc, 34)]
    width = max(len(x) for x in src_lines + sink_lines + [mid, mid2])
    parts: List[str] = []
    parts += _box(src_lines, width)
    pad = " " * ((width + 4) // 2)
    parts.append(f"{pad}│")
    parts.append(f"{pad}│  {mid}")
    parts.append(f"{pad}│  {mid2}")
    parts.append(f"{pad}▼")
    parts += _box(sink_lines, width)
    return "\n".join(parts)


def _trim(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Confirmation proof (what the clickable "confirmed" status reveals)
# ---------------------------------------------------------------------------

def confirmation_block(finding: Dict[str, Any], index: int, anchor: str) -> List[str]:
    """Full proof-of-issue section. Reconstructs the oracle/output that confirmed the
    finding from ai_response/description (internal tokens stripped)."""
    ai = clean_prose(str(finding.get("ai_response") or ""))
    desc = str(finding.get("description") or "")
    status = str(finding.get("status") or "")

    # Pull structured proof fragments if present.
    attack = _grab(ai + " " + desc, r"attack[_ ]?vector\s*[:=]\s*([^|]+)")
    primitive = _grab(ai + " " + desc, r"primitive[_ ]?type\s*[:=]\s*([^|]+)")
    conviction = _grab(ai + " " + desc, r"conviction[_ ]?level\s*[:=]\s*(\d+)")
    oracle = _grab(desc, r"(?:oracle|evidence|proof)\s*[:=]\s*(.+)")

    lines: List[str] = [
        f"<!--anchor:{anchor}-->",
        "### Confirmation — proof of issue",
        "",
    ]
    if finding.get("proof_receipt_valid") is True:
        lines.append(
            "This finding carries a verified signed runner receipt. Consult that receipt "
            "for the exact demonstrated behavior, target identity, and proof gates."
        )
    else:
        lines.append(f"Recorded status: **{status or 'unknown'}**. No verified receipt was supplied to this renderer.")
    lines.append("")
    if conviction:
        _ladder = {"0": "hypothesis", "1": "reachable", "2": "triggerable", "3": "impactful (demonstrated)"}
        lines.append(f"- **Conviction level**: {conviction} — {_ladder.get(conviction, 'n/a')}")
    if attack:
        lines.append(f"- **Attack vector**: {clean_prose(attack)}")
    if primitive:
        lines.append(f"- **Primitive**: {clean_prose(primitive)}")
    if ai:
        lines += ["", "**Analysis / oracle:**", "", "> " + ai.replace("\n", "\n> ")]
    if oracle:
        lines += ["", "**Captured evidence:**", "", "```text", clean_prose(oracle)[:1200], "```"]
    lines.append("")
    return lines


def _grab(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Remediation: max 2 fixes, each with diff + test + proof-of-fix + metrics
# ---------------------------------------------------------------------------

def _fix_catalog(bug_class: str, loc: str, lang: str) -> List[Dict[str, Any]]:
    """Return up to TWO concrete fixes. Each: title, effort, effectiveness, residual,
    perf, diff(before/after), test(code+lang), proof(cmd+lang+expect), metrics(rows)."""
    py = lang in ("", "python")

    C: Dict[str, List[Dict[str, Any]]] = {
        "command_injection": [
            {
                "title": "Use an argv list, never shell=True",
                "effort": "<1h", "effectiveness": 9.0, "residual": 2.0, "perf": "none",
                "before": "import os\n# tainted `user_input` flows into a shell string\nos.system(f\"convert {user_input} out.png\")",
                "after": "import subprocess, shlex\n# argv list: no shell, no metachar interpretation\nsubprocess.run([\"convert\", user_input, \"out.png\"], shell=False, check=True)",
                "test_lang": "python",
                "test": "import subprocess, pytest\n\ndef test_metacharacters_are_data_not_syntax():\n    # `; id` must be treated as a literal filename, not a command\n    r = subprocess.run([\"convert\", \"; id\", \"out.png\"], shell=False,\n                       capture_output=True, text=True)\n    assert \"uid=\" not in (r.stdout + r.stderr)",
                "proof_lang": "bash",
                "proof": "# Re-run the original PoC against the patched service. A fixed build must NOT\n# execute the injected command (no uid= / marker in the output).\ncurl -s \"$LAB_URL/run?cmd=;%20id\" | tee /tmp/out; \\\n  grep -q 'uid=' /tmp/out && echo 'STILL VULNERABLE' || echo 'FIX VERIFIED: no command execution'",
                "metrics": [("Exploitable", "Yes (RCE)", "No"), ("p95 latency", "~same", "~same (argv skips shell spawn)"), ("Added overhead", "n/a", "none — argv exec ≤ shell exec")],
            },
            {
                "title": "Structural: typed job API with an operation allowlist",
                "effort": "1-2d", "effectiveness": 9.5, "residual": 0.5, "perf": "low",
                "before": "run(request.args[\"cmd\"])  # free-form command from the client",
                "after": "OPS = {\"rebuild\": [\"make\", \"build\"], \"export\": [\"./export.sh\"]}\nargv = OPS.get(request.args[\"op\"])\nif argv is None:\n    abort(400)\nsubprocess.run(argv, shell=False, check=True)",
                "test_lang": "python",
                "test": "def test_only_allowlisted_ops_run(client):\n    assert client.get('/job?op=rebuild').status_code == 200\n    assert client.get('/job?op=;id').status_code == 400",
                "proof_lang": "bash",
                "proof": "curl -s -o /dev/null -w '%{http_code}\\n' \"$LAB_URL/job?op=;id\"  # expect 400",
                "metrics": [("Exploitable", "Yes", "No"), ("Attack surface", "arbitrary argv", "fixed allowlist"), ("Overhead", "n/a", "1 dict lookup / request")],
            },
        ],
        "sql_injection": [
            {
                "title": "Parameterized query / bound ORM",
                "effort": "<1h", "effectiveness": 9.5, "residual": 1.5, "perf": "none",
                "before": "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                "after": "cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))",
                "test_lang": "python",
                "test": "def test_quote_is_data_not_syntax(db):\n    rows = find_user(\"' OR '1'='1\")\n    assert rows == []  # injection string matches no real user",
                "proof_lang": "bash",
                "proof": "curl -s \"$LAB_URL/search?q=%27%20OR%20%271%27%3D%271\" | tee /tmp/o; \\\n  grep -qi 'sql' /tmp/o && echo 'STILL VULNERABLE (sql error leaked)' || echo 'FIX VERIFIED'",
                "metrics": [("Exploitable", "Yes (data exfil)", "No"), ("Query plan", "string-built", "prepared (cacheable)"), ("p95 latency", "baseline", "≤ baseline (plan reuse)")],
            },
            {
                "title": "Structural: identifier allowlist for dynamic ORDER BY/columns",
                "effort": "1-4h", "effectiveness": 9.0, "residual": 1.0, "perf": "none",
                "before": "cur.execute(f\"SELECT * FROM t ORDER BY {sort}\")",
                "after": "COLS = {\"name\", \"created_at\"}\nif sort not in COLS: abort(400)\ncur.execute(f\"SELECT * FROM t ORDER BY {sort}\")  # sort now provably in allowlist",
                "test_lang": "python",
                "test": "def test_unknown_sort_key_rejected(client):\n    assert client.get('/list?sort=name').status_code == 200\n    assert client.get('/list?sort=(select 1)').status_code == 400",
                "proof_lang": "bash",
                "proof": "curl -s -o /dev/null -w '%{http_code}\\n' \"$LAB_URL/list?sort=(select%201)\"  # expect 400",
                "metrics": [("Exploitable", "Yes", "No"), ("Overhead", "n/a", "O(1) set lookup")],
            },
        ],
        "path_traversal": [
            {
                "title": "Canonicalize and confine to an allowlisted root",
                "effort": "<1h", "effectiveness": 9.0, "residual": 1.5, "perf": "low",
                "before": "open(os.path.join(DATA_DIR, request.args[\"name\"]))",
                "after": "root = Path(DATA_DIR).resolve()\np = (root / request.args[\"name\"]).resolve()\nif root not in p.parents:\n    abort(403)\nopen(p)",
                "test_lang": "python",
                "test": "def test_escape_is_blocked(client):\n    assert client.get('/file?name=../../etc/passwd').status_code == 403",
                "proof_lang": "bash",
                "proof": "curl -s \"$LAB_URL/file?name=../../../../etc/passwd\" | tee /tmp/o; \\\n  grep -q 'root:.*:0:0:' /tmp/o && echo 'STILL VULNERABLE' || echo 'FIX VERIFIED'",
                "metrics": [("Exploitable", "Yes (arbitrary read)", "No"), ("Overhead", "n/a", "1 path resolve / request")],
            },
        ],
        "ssrf": [
            {
                "title": "Allowlist outbound hosts + block link-local/metadata",
                "effort": "1-4h", "effectiveness": 8.5, "residual": 2.0, "perf": "low",
                "before": "requests.get(request.args[\"url\"])",
                "after": "u = urlparse(request.args[\"url\"])\nip = socket.gethostbyname(u.hostname)\nif u.scheme != \"https\" or is_private(ip) or ip == \"169.254.169.254\":\n    abort(400)\nrequests.get(request.args[\"url\"], allow_redirects=False)",
                "test_lang": "python",
                "test": "def test_metadata_and_private_blocked(client):\n    assert client.get('/fetch?url=http://169.254.169.254/').status_code == 400\n    assert client.get('/fetch?url=http://127.0.0.1/').status_code == 400",
                "proof_lang": "bash",
                "proof": "curl -s -o /dev/null -w '%{http_code}\\n' \"$LAB_URL/fetch?url=http://169.254.169.254/latest/meta-data/\"  # expect 400",
                "metrics": [("Exploitable", "Yes (cloud metadata)", "No"), ("Added latency", "n/a", "1 DNS resolve + IP check")],
            },
        ],
        "deserialization": [
            {
                "title": "Refuse unsafe loaders on untrusted data",
                "effort": "1-4h", "effectiveness": 9.5, "residual": 1.5, "perf": "low",
                "before": "obj = pickle.loads(request.data)  # arbitrary object graph",
                "after": "obj = json.loads(request.data)  # data-only; no code execution\n# if a binary format is required, verify an HMAC before loading",
                "test_lang": "python",
                "test": "def test_reduce_payload_does_not_execute():\n    import json, pytest\n    with pytest.raises(json.JSONDecodeError):\n        json.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")  # pickle RCE gadget rejected",
                "proof_lang": "bash",
                "proof": "printf '%s' \"$(python3 -c \"import pickle,os;print(pickle.dumps(type('x',(object,),{'__reduce__':lambda s:(os.system,('id',))})()))\" 2>/dev/null)\" \\\n | curl -s --data-binary @- \"$LAB_URL/load\" | grep -q 'uid=' && echo 'STILL VULNERABLE' || echo 'FIX VERIFIED'",
                "metrics": [("Exploitable", "Yes (RCE)", "No"), ("Format", "pickle (code)", "json (data)"), ("Overhead", "n/a", "comparable parse cost")],
            },
        ],
        "ssti": [
            {
                "title": "Pass user data as a template variable, never as template source",
                "effort": "<1h", "effectiveness": 9.5, "residual": 1.0, "perf": "none",
                "before": "render_template_string(f\"<h1>{user_input}</h1>\")",
                "after": "render_template(\"page.html\", title=user_input)  # autoescaped variable",
                "test_lang": "python",
                "test": "def test_expression_does_not_evaluate(client):\n    body = client.get('/p?q={{7*7}}').text\n    assert '49' not in body  # rendered literally, not evaluated",
                "proof_lang": "bash",
                "proof": "curl -s \"$LAB_URL/p?q=%7B%7B7*7%7D%7D\" | grep -q '49' && echo 'STILL VULNERABLE' || echo 'FIX VERIFIED'",
                "metrics": [("Exploitable", "Yes (SSTI→RCE)", "No"), ("Render cost", "compile attacker str", "static template (faster)")],
            },
        ],
    }
    variants = C.get(bug_class)
    if not variants:
        variants = [{
            "title": "Validate at the trust boundary and fail closed",
            "effort": "1-4h", "effectiveness": 7.5, "residual": 3.0, "perf": "low",
            "before": f"# {loc}: untrusted value reaches the sink unchecked\nsink(user_value)",
            "after": f"# {loc}: allowlist/validate before the sink; deny by default\nif not is_allowed(user_value):\n    abort(400)\nsink(user_value)",
            "test_lang": (lang or "python"),
            "test": "def test_reported_poc_is_blocked(client):\n    # Encode the reported PoC input; a fixed build must reject or neutralize it.\n    assert client.get('/vuln-endpoint?input=<POC>').status_code in (400, 403)",
            "proof_lang": "bash",
            "proof": "# Re-run the reported PoC against the patched build; expect it to be blocked.\ncurl -s -o /dev/null -w '%{http_code}\\n' \"$LAB_URL/<vuln-endpoint>?input=<POC>\"  # expect 400/403",
            "metrics": [("Exploitable", "Yes", "No"), ("Overhead", "n/a", "validation cost (low)")],
        }]
    return variants[:2]


def extract_endpoint(finding: Dict[str, Any]) -> Dict[str, str]:
    """Best-effort parse of {method, path, param} from the finding's attack vector /
    description so reproduction commands target the real confirmed path."""
    blob = f"{finding.get('ai_response') or ''} {finding.get('description') or ''}"
    method = ""
    m = re.search(r"\b(GET|POST|PUT|DELETE|PATCH)\b", blob)
    if m:
        method = m.group(1)
    path = ""
    m = re.search(r"(/[A-Za-z0-9_\-/{}.]+)", blob)
    if m:
        path = m.group(1)
    param = ""
    # "param=NAME" / "parameter: NAME" states the parameter name explicitly.
    m = re.search(r"\bparam(?:eter)?\s*[=:]\s*([A-Za-z0-9_]+)", blob, re.IGNORECASE)
    if m:
        param = m.group(1)
    else:
        _stop = {"get", "post", "put", "delete", "patch", "http", "https",
                 "user", "input", "the", "arg", "field"}
        for mm in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)=", blob):
            cand = mm.group(1)
            if cand.lower() not in _stop:
                param = cand
                break
    return {"method": method or "GET", "path": path, "param": param}


# Per-class reproduction: concrete manual steps + a runnable PoC whose oracle prints a
# clear VULNERABLE / not-reproduced marker (so the fix-verifier can score it too).
def build_reproduction(finding: Dict[str, Any], bug_class: str, source: str, sink: str,
                       sink_api: str, file_: str, line: Optional[int]) -> Dict[str, Any]:
    ep = extract_endpoint(finding)
    path = ep["path"] or "/<vulnerable-endpoint>"
    param = ep["param"] or "input"

    web_pocs = {
        "command_injection": (f"curl -s \"$LAB_URL{path}?{param}=;id\" | tee /tmp/poc.out; "
                              "grep -q 'uid=' /tmp/poc.out && echo 'VULNERABLE: command executed (uid= in output)' || echo 'not reproduced'"),
        "sql_injection": (f"curl -s \"$LAB_URL{path}?{param}=%27%20OR%20%271%27%3D%271\" | tee /tmp/poc.out; "
                          "grep -qiE 'sql|syntax|sqlite|mysql|postgres' /tmp/poc.out && echo 'VULNERABLE: SQL error/data leaked' || echo 'not reproduced'"),
        "path_traversal": (f"curl -s \"$LAB_URL{path}?{param}=../../../../etc/passwd\" | tee /tmp/poc.out; "
                           "grep -q 'root:.*:0:0:' /tmp/poc.out && echo 'VULNERABLE: /etc/passwd disclosed' || echo 'not reproduced'"),
        "ssrf": (f"curl -s \"$LAB_URL{path}?{param}=http://169.254.169.254/latest/meta-data/\" | tee /tmp/poc.out; "
                 "test -s /tmp/poc.out && echo 'VULNERABLE: internal metadata reachable (inspect output)' || echo 'not reproduced'"),
        "ssti": (f"curl -s \"$LAB_URL{path}?{param}=%7B%7B7*7%7D%7D\" | tee /tmp/poc.out; "
                 "grep -q '49' /tmp/poc.out && echo 'VULNERABLE: template expression evaluated (7*7=49)' || echo 'not reproduced'"),
        "xss": (f"curl -s \"$LAB_URL{path}?{param}=%3Cscript%3Ealert(1)%3C/script%3E\" | tee /tmp/poc.out; "
                "grep -q '<script>alert(1)</script>' /tmp/poc.out && echo 'VULNERABLE: payload reflected unescaped' || echo 'not reproduced'"),
        "deserialization": (f"printf '{{\"x\":1}}' | curl -s --data-binary @- \"$LAB_URL{path}\" | tee /tmp/poc.out; "
                            "echo '(send a crafted gadget payload; VULNERABLE if the object graph executes)'"),
    }
    manual = {
        "command_injection": [
            f"Send a request to `{ep['method']} {path}` with `{param}` set to a shell-injection payload, e.g. `;id` or `$(id)`.",
            "Because the value flows into a shell command unsanitised, the injected command runs.",
            "Confirm execution by looking for `uid=…gid=…` (output of `id`) in the response.",
        ],
        "sql_injection": [
            f"Send `{ep['method']} {path}` with `{param}=' OR '1'='1`.",
            "The unparameterised query changes meaning; a SQL error or extra rows confirm injection.",
        ],
        "path_traversal": [
            f"Request `{ep['method']} {path}` with `{param}=../../../../etc/passwd`.",
            "The path is not confined to the data root, so a file outside it is read.",
            "Confirm by seeing `/etc/passwd` contents (`root:x:0:0:`) in the response.",
        ],
        "ssrf": [
            f"Request `{ep['method']} {path}` with `{param}` pointing at an internal address (e.g. `http://169.254.169.254/latest/meta-data/`).",
            "The server fetches the attacker-chosen URL; internal/metadata content in the response confirms SSRF.",
        ],
        "ssti": [
            f"Send `{ep['method']} {path}` with `{param}={{{{7*7}}}}`.",
            "If the response contains `49`, the template engine evaluated attacker input (SSTI).",
        ],
        "xss": [
            f"Send `{ep['method']} {path}` with `{param}=<script>alert(1)</script>`.",
            "If the payload is reflected unescaped in the HTML response, XSS is confirmed.",
        ],
        "deserialization": [
            f"POST a crafted serialized gadget to `{path}` (e.g. a pickle/YAML/Java object with a side effect).",
            "If the side effect fires (marker file / command output), unsafe deserialization is confirmed.",
        ],
    }
    default_manual = [
        f"Drive the {source} into the {sink} ({sink_api})" + (f" at `{file_}{':'+str(line) if line else ''}`" if file_ else "") + ".",
        "Observe the security-relevant effect (unexpected output, error, or state change) that confirms the issue.",
    ]
    default_poc = (
        "# No confirmed HTTP endpoint parsed from the finding. Inspect the sink, then drive\n"
        "# the documented input into it inside the pod:\n"
        + (f"f=$(find / -path '*{file_}' -not -path '*/.git/*' 2>/dev/null | head -1); echo \"$f\"; sed -n '1,80p' \"$f\""
           if file_ else "pwd; ls -la")
    )
    return {
        "manual": manual.get(bug_class, default_manual),
        "poc": web_pocs.get(bug_class, default_poc),
    }


def remediation_block(finding: Dict[str, Any], bug_class: str, loc: str, lang: str,
                      *, repo_id: Optional[int] = None, file_: str = "",
                      repro_poc: str = "") -> List[str]:
    fixes = _fix_catalog(bug_class, loc, lang)
    lines: List[str] = ["### Remediation — up to 2 ranked fixes", ""]
    lines.append(
        "_These are unverified class-level remediation examples, not target-specific patches or "
        "measured results. Match the original code and review the test oracle before applying "
        "an example. Only retained verification results establish whether a fix works._"
    )
    lines.append("")
    for i, fx in enumerate(fixes, 1):
        kind = "minimal effective" if i == 1 else "structural / durable"
        # Structured payload for the one-click "Apply & verify in lab pod" component:
        # it applies BEFORE→AFTER in the cloned file, re-runs the repro PoC (expects it
        # blocked), runs the fix's test, and measures before/after timing.
        import base64 as _b64, json as _json
        payload = {
            "file": file_,
            "before": fx["before"],
            "after": fx["after"],
            "test": fx["test"],
            "test_lang": fx["test_lang"],
            "repro_poc": repro_poc,
            "lang": lang or "",
            "fix_title": fx["title"],
        }
        tok = _b64.b64encode(_json.dumps(payload).encode()).decode()
        lines += [
            f"#### Fix {i} — {fx['title']}  ({kind})",
            "",
            f"- **Effort**: {fx['effort']} · **Estimated effectiveness**: {fx['effectiveness']}/10 · "
            f"**Estimated residual risk**: {fx['residual']}/10 · **Perf impact**: {fx['perf']}",
            "",
            f"{{{{verifyfix:{tok}}}}}",
            "",
            "**Code change (keyed to the cited sink):**",
            "",
            "_Illustrative before (not a source snapshot):_",
            "",
            f"```{lang or 'text'}",
            fx["before"],
            "```",
            "",
            "_Proposed after (not yet verified):_",
            "",
            f"```{lang or 'text'}",
            fx["after"],
            "```",
            "",
            "**Regression test for the fix:**",
            "",
            f"```{fx['test_lang']}",
            fx["test"],
            "```",
            "",
            "**Proof the fix works (run in the isolated lab pod after patching):**",
            "",
            f"```{fx['proof_lang']}",
            fx["proof"],
            "```",
            "",
            "**Metrics (before → after):** _click Apply & verify above to measure live; "
            "class-level baseline shown until then._",
            "",
            "| Metric | Before fix | After fix |",
            "|--------|------------|-----------|",
        ]
        for row in fx["metrics"]:
            lines.append(f"| {row[0]} | {row[1]} | {row[2]} |")
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Top-level per-finding renderer
# ---------------------------------------------------------------------------

def render_finding(
    finding: Dict[str, Any],
    index: int,
    repo_id: Optional[int],
    *,
    ai_section: Optional[Dict[str, Any]] = None,
    source_root: Optional[Path] = None,
) -> List[str]:
    """Return the full markdown lines for one finding section."""
    ai_section = ai_section or {}
    title = str(finding.get("title") or "Untitled finding").strip()
    cvss = float(finding.get("cvss") or 0.0)
    status = str(finding.get("status") or "unproven")
    sev = "Critical" if cvss >= 9.0 else ("High" if cvss >= 7.0 else ("Medium" if cvss >= 4.0 else "Low"))

    file_, line = parse_location(finding)
    bug_class = _fix_classify(_fix_blob(finding))
    lang = lang_for(file_)
    source, sink, sink_api = infer_source_sink(finding, bug_class)
    loc_disp = (file_ + (f":{line}" if line else "")) if file_ else "see evidence"
    anchor = f"confirmation-{index}"

    # Status line: make "confirmed" clickable -> scrolls to the Confirmation proof.
    if status in ("confirmed", "report-eligible"):
        status_disp = f"✅ {status} — {{{{link:{anchor}|view proof of confirmation ▸}}}}"
    else:
        status_disp = status

    lines: List[str] = [
        f"## {title}",
        "",
        f"**Severity**: {sev} (CVSS {cvss})  ",
        f"**Status**: {status_disp}  ",
        f"**Location**: `{loc_disp}`  ",
        f"**Bug class**: `{bug_class}`  ",
        "",
        "### Root Cause",
        "",
        (clean_prose(ai_section.get("root_cause", "")) or clean_prose(str(finding.get("ai_response") or ""))[:600]
         or "A source-backed root cause was not recorded; the finding description is a claim requiring its cited evidence."),
        "",
    ]

    snippet = read_code_snippet(repo_id, file_, line, source_root=source_root) if source_root is not None else None
    if snippet:
        head = f"Vulnerable code — `{file_}` lines {snippet['start_line']}-{snippet['end_line']}"
        if snippet.get("focus_line"):
            head += f" (sink at line {snippet['focus_line']})"
        lines += [f"**{head}:**", "", f"```{snippet['lang'] or ''}", snippet["code"], "```", ""]
    else:
        lines += [
            "_Verified audit snapshot source is unavailable; no snippet from a mutable checkout is substituted._",
            "",
        ]

    lines += [
        "**Data-flow hypothesis (inferred from the reported class; not a recorded trace):**",
        "",
        "```text",
        flow_diagram(source, sink, sink_api, file_, line),
        "```",
        "",
        "### Impact Assessment",
        "",
        (clean_prose(ai_section.get("impact", "")) or
         f"Class-level impact hypothesis for {bug_class.replace('_', ' ')}: if an attacker controls the "
         f"{source} can reach {sink} ({sink_api}). Impact scales with the privileges of the "
         f"process hosting the sink."),
        "",
        "### Evidence",
        "",
        f"- **Untrusted source**: {source}",
        f"- **Security sink**: {sink} — `{sink_api}`",
        f"- **Location**: `{loc_disp}`",
        f"- **Observed**: {clean_prose(str(finding.get('description') or '')) or 'see analysis below'}",
        "",
    ]

    # Reproduction: numbered MANUAL steps + a runnable PoC script (what the ▶ Repro
    # button executes). Both are grounded in the finding's confirmed attack path.
    repro = build_reproduction(finding, bug_class, source, sink, sink_api, file_, line)
    lines += ["### Reproduction", "", "**Manual steps:**", ""]
    for n, step in enumerate(repro["manual"], 1):
        lines.append(f"{n}. {step}")
    lines += [
        "",
        "**Unverified class-level reproduction template** (not a retained execution receipt; review against the exact target before explicit execution). Set `LAB_URL` in the Interactive "
        "Lab Shell first; then use Run:",
        "",
        "```bash",
        ": \"${LAB_URL:=http://127.0.0.1:8080}\"   # base URL of the target inside the pod",
        repro["poc"],
        "```",
        "",
    ]

    lines += confirmation_block(finding, index, anchor)
    lines += remediation_block(finding, bug_class, loc_disp, lang,
                               repo_id=repo_id, file_=file_, repro_poc=repro["poc"])
    lines += ["---", ""]
    return lines


def render_notebook_context(context: Dict[str, Any]) -> List[str]:
    """Portable evidence appendix; recorded commands are inert text in exports."""
    import json
    def block(value):
        value = str(value or "")
        longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
        fence = "`" * max(3, longest + 1)
        return [fence + "text", value, fence, ""]
    lines = ["## Audit Notebook Context", "", "The signed manifest retains the structured context. Notebook executions are separate observations and cannot change this publication's proof decisions.", ""]
    lines += block(json.dumps(context.get("binding") or {}, sort_keys=True, indent=2))
    lines += ["### Recorded Product Architecture", ""]
    architecture = context.get("architecture") or {}
    labels = {row["id"]: row["label"] for row in architecture.get("nodes") or []}
    lines += block("\n".join([f"{row['id']}: {row['label']} ({row['kind']})" for row in architecture.get("nodes") or []] +
                              [f"{labels.get(row['source'], row['source'])} -> {labels.get(row['target'], row['target'])}: {row['label']}" for row in architecture.get("edges") or []] +
                              list(architecture.get("unknowns") or [])))
    if context.get("source_architecture"):
        lines += ["### Source Declarations and Configuration", "", "These declarations are source-backed references, not observations of runtime behavior or independent proof.", ""]
        lines += block(json.dumps(context["source_architecture"], sort_keys=True, indent=2))
    lines += ["### Coverage", ""]
    coverage = context.get("coverage") or {}
    if coverage.get("status") == "recorded":
        lines += ["The full interactive surface map is retained in this report's signed evidence manifest. It is a publication snapshot; subsequent audits do not change it.", ""]
        lines += block(json.dumps(coverage, sort_keys=True, indent=2))
    else:
        lines += block(coverage.get("reason") or "No surface coverage map was captured in this publication. Tool totals alone do not establish surface coverage.")
    if context.get("assurance"):
        lines += block(context["assurance"])
    lines += ["### Actual and Intended Behavior", ""]
    for row in context.get("comparisons") or []:
        lines += block(f"{row['title']}\nProof: {row['proof_status']}\nClaim: {row['claim']}\nIntended: {row['intended_behavior']['text']}\nObserved: {row['observed_behavior']['text']}\nComparison: {row['comparison']['status']} — {row['comparison']['reason']}")
    lines += ["### Verification Appendix", "", "Successful, failed, and inconclusive outcomes below describe recorded attempts. Success alone does not establish a vulnerability, impact, or fix effectiveness.", ""]
    for row in context.get("appendix") or []:
        lines += block(f"{row['title']}\nOutcome: {row['status']}\nEvidence scope: {row['evidence_scope']}\nReason: {row['reason']}\nSources: {', '.join(row['source_refs'])}\nMissing context: {'; '.join(row['missing_context'])}")
        for command in row["commands"]:
            lines += block(f"Recorded command ({command['language']}):\n{command['code']}")
        if row["stdout"]:
            lines += block("Recorded stdout:\n" + row["stdout"])
        if row["stderr"]:
            lines += block("Recorded stderr:\n" + row["stderr"])
    lines += ["### Missing Context for Retry", ""]
    lines += block("\n".join(row["reason"] for row in context.get("missing_context") or []) or "No additional identity gaps were detected in this projection. Artifact completeness and proof still require review.")
    return lines
