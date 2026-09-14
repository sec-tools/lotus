"""Phase-1 handler→sink tracer.

Trust-boundary-map lists unauthenticated mutating verbs. Phase 2 still does not
know which of those verbs reach RCE / write / SSRF / deser vs a no-op health
handler. This tracer resolves the registration to a function body and tags
known sinks, writing ``.lotus/handler_sinks.json`` so Phase 2 labs the
highest-impact edges first.

Does not confirm vulnerabilities. Lab proof still required.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.analyzers.trust_boundary import (
    _iter_files,
    _rel,
    collect_trust_boundary,
)

_FUNC_GO = re.compile(r"^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(", re.M)
_FUNC_RS = re.compile(r"^(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*[<(]", re.M)
_FUNC_C = re.compile(
    r"^(?:static\s+)?(?:[\w*]+\s+)+(\w+)\s*\([^;{]*\)\s*\{", re.M,
)

# Ordered: first match in a function is the primary lab hint.
_SINKS: List[Tuple[str, float, re.Pattern[str]]] = [
    ("rce", 9.0, re.compile(
        r"exec\.Command|syscall\.Exec|/bin/(?:ba)?sh|Language:\s*\"command\""
        r"|RunCommand\(|RunCode\(|RunInSession\(|os\.StartProcess"
        r"|Command::new|std::process::Command",
    )),
    ("ssrf", 8.6, re.compile(
        r"ReverseProxy|NewSingleHostReverseProxy|httputil\.ReverseProxy"
        r"|proxy\.Director|http\.Get\(|http\.Post\(|reqwest::",
    )),
    ("file_write", 8.1, re.compile(
        r"os\.WriteFile|os\.OpenFile|os\.Create\(|CreateFileF|WriteFileF"
        r"|InsertMock\(|io\.Copy\(|tokio::fs::write|std::fs::write",
    )),
    ("path_join", 8.1, re.compile(r"filepath\.Join\s*\(")),
    ("deser", 7.5, re.compile(
        r"gob\.NewDecoder|proto\.Unmarshal|json\.Unmarshal\s*\(|yaml\.Unmarshal"
        r"|serde_json::from_|bincode::deserialize",
    )),
    ("file_read", 7.5, re.compile(
        r"os\.ReadFile|os\.Open\(|ExpandPath\(|DownloadFile\(",
    )),
    ("nested_io", 7.5, re.compile(
        r"nested_io_open|avio_open2?\(|ffurl_open|open_url\s*\(",
    )),
    ("queue_admin", 7.5, re.compile(
        r"NewInspector|DeleteAll|ArchiveAll|\.Enqueue\(",
    )),
    ("proxy_start", 8.6, re.compile(
        r"StartIncomingProxy|StartOutgoing",
    )),
    ("mutate_api", 8.6, re.compile(
        r"create_sandbox\(|kill_sandbox\(|delete_sandbox\(|resumer\.Resume|"
        r"\.Resume\(ctx",
    )),
]

_HIGH = {
    "rce", "ssrf", "file_write", "nested_io", "deser", "queue_admin",
    "path_join", "proxy_start", "mutate_api",
}


def _window_after(text: str, start: int, lines: int = 180) -> str:
    rest = text[start:]
    chunk: List[str] = []
    for i, ln in enumerate(rest.splitlines()):
        if i > 3 and (
            ln.startswith("func ")
            or ln.startswith("pub async fn ")
            or ln.startswith("pub fn ")
            or (ln.startswith("fn ") and not ln.startswith("fn ("))
        ):
            break
        chunk.append(ln)
        if i >= lines:
            break
    return "\n".join(chunk)


def _index_functions(dest: Path) -> Dict[str, List[Tuple[str, int, str]]]:
    index: Dict[str, List[Tuple[str, int, str]]] = {}
    for p in _iter_files(dest, limit=2800):
        ext = p.suffix.lower()
        if ext not in {".go", ".rs", ".c", ".cc", ".cpp", ".h"}:
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if len(text) > 600_000:
            text = text[:600_000]
        rel = _rel(dest, p)
        pats = []
        if ext == ".go":
            pats = [_FUNC_GO]
        elif ext == ".rs":
            pats = [_FUNC_RS]
        else:
            pats = [_FUNC_C]
        for pat in pats:
            for m in pat.finditer(text):
                name = m.group(1)
                if name in {"if", "for", "switch", "return", "var", "type"}:
                    continue
                line = text[:m.start()].count("\n") + 1
                body = _window_after(text, m.start())
                index.setdefault(name, []).append((rel, line, body))
    return index


def _score_body(rel: str, route_file: str, path: str) -> int:
    reln = rel.replace("\\", "/")
    rf = (route_file or "").replace("\\", "/")
    score = 0
    if rf and reln == rf:
        score += 120
    try:
        if rf and Path(reln).parent == Path(rf).parent:
            score += 50
        rp, fp = Path(reln).parts, Path(rf).parts
        score += sum(1 for a, b in zip(rp, fp) if a == b) * 8
    except Exception:
        pass
    low = reln.lower()
    if any(tok in low for tok in ("/sdk", "/sdks/", "client", "/cmd/", "testdata")):
        score -= 90
    if any(tok in low for tok in ("controller", "/handlers/", "/web/", "/routes/")):
        score += 30
    pl = (path or "").lower()
    if "isolated" in pl and "isolated" in low:
        score += 45
    if "/files/" in pl and "isolated" not in pl and "filesystem" in low and "isolated" not in low:
        score += 45
    if "upload" in pl and "upload" in low:
        score += 20
    return score


def _sinks_in(text: str) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    seen = set()
    for kind, cvss, pat in _SINKS:
        m = pat.search(text)
        if not m or kind in seen:
            continue
        seen.add(kind)
        snippet = text[m.start(): m.start() + 80].splitlines()[0][:80]
        found.append({
            "kind": kind,
            "cvss": cvss,
            "line_offset": text[:m.start()].count("\n") + 1,
            "snippet": snippet.strip(),
        })
    return found


def collect_handler_sinks(
    dest: Path,
    language: str = "",
    tb: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dest = Path(dest)
    if tb is None:
        from backend.tool_registry import is_tool_enabled
        if is_tool_enabled("trust-boundary-map"):
            _, tb = collect_trust_boundary(dest, language)
        else:
            tb = {"status": "skipped", "reason": "Trust-boundary inputs disabled by capabilities configuration",
                  "configure_tool": "trust-boundary-map", "coverage_complete": False}

    index = _index_functions(dest)
    traces: List[Dict[str, Any]] = []

    def add_trace(
        method: str,
        path: str,
        route_file: str,
        handler: str,
        why: str,
        extra_text: str = "",
        handler_file: str = "",
        handler_line: int = 0,
    ) -> None:
        bodies: List[Tuple[str, int, str]] = []
        # File-scoped traces (nested_io / queue / sibling) must not bind a
        # global symbol like open_url / NewInspector across the whole repo.
        if extra_text:
            bodies = []
        elif handler and handler in index:
            ranked = sorted(
                index[handler],
                key=lambda item: -_score_body(item[0], route_file, path),
            )
            bodies = ranked[:4]
        sinks: List[Dict[str, Any]] = []
        hf, hl = handler_file, handler_line
        for rel, line, body in bodies:
            file_sinks = _sinks_in(body)
            for s in file_sinks:
                rec = dict(s)
                rec["file"] = rel
                rec["line"] = line + max(int(s.get("line_offset") or 1) - 1, 0)
                sinks.append(rec)
            if not hf:
                hf, hl = rel, line
            # Controller/handler files often split work across helpers in the
            # same file (UploadFile → writeUploadFile). Scan the file once.
            low = rel.replace("\\", "/").lower()
            # Helpers live in the same controller/handler file. Do not scan
            # fat route registries (keploy record.go hosts every handler).
            if any(tok in low for tok in ("controller", "/handlers/")) and "/routes/" not in low:
                try:
                    whole = (dest / rel).read_text(errors="ignore")[:80_000]
                except Exception:
                    whole = ""
                for s in _sinks_in(whole):
                    rec = dict(s)
                    rec["file"] = rel
                    rec["line"] = int(s.get("line_offset") or 1)
                    sinks.append(rec)
        if extra_text:
            for s in _sinks_in(extra_text):
                rec = dict(s)
                rec["file"] = route_file
                rec["line"] = int(s.get("line_offset") or 1)
                sinks.append(rec)
        # Dedupe kinds, keep first (highest severity — _SINKS is ordered)
        uniq: List[Dict[str, Any]] = []
        seen_k = set()
        for s in sinks:
            if s["kind"] in seen_k:
                continue
            seen_k.add(s["kind"])
            uniq.append(s)
        traces.append({
            "method": method,
            "path": path,
            "route_file": route_file,
            "handler": handler,
            "handler_file": hf,
            "handler_line": hl,
            "why": why,
            "sinks": uniq,
            "primary_sink": uniq[0]["kind"] if uniq else "",
            "cvss": uniq[0]["cvss"] if uniq else 0,
        })

    for r in (tb.get("unauth_mutating") or [])[:40]:
        add_trace(
            r.get("method") or "POST",
            r.get("path") or "",
            r.get("file") or "",
            r.get("handler") or "",
            r.get("why") or "unauth mutating",
        )

    for nio in (tb.get("nested_io") or [])[:12]:
        rel = nio.get("file") or ""
        p = dest / rel
        extra = ""
        try:
            extra = p.read_text(errors="ignore")[:80_000]
        except Exception:
            extra = "nested_io_open"
        add_trace(
            "NESTED", rel, rel, "open_url",
            "nested protocol file/http allow", extra_text=extra,
        )

    for q in (tb.get("queue_tcbs") or [])[:8]:
        rel = q.get("file") or ""
        extra = ""
        try:
            extra = (dest / rel).read_text(errors="ignore")[:40_000]
        except Exception:
            extra = "NewInspector"
        add_trace("QUEUE", rel, rel, "NewInspector", "redis queue TCB", extra_text=extra)

    for gap in (tb.get("sibling_gaps") or [])[:8]:
        rel = gap.get("unguarded_file") or ""
        extra = ""
        try:
            extra = (dest / rel).read_text(errors="ignore")[:40_000]
        except Exception:
            extra = "filepath.Join"
        add_trace("JOIN", rel, rel, "", "sibling missing path guard", extra_text=extra)

    # Rank: high sinks first, then by cvss.
    def _rank(tr: Dict[str, Any]) -> Tuple[int, float]:
        kinds = {s["kind"] for s in tr.get("sinks") or []}
        high = 0 if kinds & _HIGH else 1
        return (high, -(float(tr.get("cvss") or 0)))

    traces.sort(key=_rank)
    priority = [t for t in traces if {s["kind"] for s in t.get("sinks") or []} & _HIGH][:18]

    findings: List[Dict[str, Any]] = []
    for tr in priority:
        kinds = ", ".join(s["kind"] for s in tr["sinks"][:4])
        loc = tr.get("handler_file") or tr.get("route_file") or ""
        line = int(tr.get("handler_line") or 1)
        findings.append({
            "tool": "handler-sink-trace",
            "title": f"{tr['method']} {tr['path']} → {kinds}",
            "cvss": float(tr.get("cvss") or 7.5),
            "description": (
                f"Handler `{tr.get('handler') or '?'}` in {loc}:{line} reached from "
                f"{tr['method']} {tr['path']} ({tr.get('why')}). Sinks: {kinds}. "
                "Phase 2: lab-prove the sink oracle (write/RCE/SSRF/deser), not 200-without-effect."
            ),
            "file": loc,
            "line": line,
            "confidence": "high",
            "qualification": "QUALIFIED",
            "phase2_hint": "handler_sink",
            "canonical_class": "rce" if tr.get("primary_sink") == "rce" else "authz_bypass",
            "primitive_type": tr.get("primary_sink") or "auth_bypass",
            "handler": tr.get("handler"),
            "path": tr.get("path"),
        })

    payload = {
        "language": language,
        "input_omissions": ([{"tool": "trust-boundary-map", **tb}] if tb.get("status") == "skipped" else []),
        "traces": traces[:50],
        "priority": priority,
        "counts": {
            "traces": len(traces),
            "priority": len(priority),
            "with_sink": sum(1 for t in traces if t.get("sinks")),
        },
    }
    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "handler_sinks.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8",
        )
    except Exception:
        pass
    return findings, payload


def _run_handler_sink_trace(dest: Path, language: str) -> List[dict]:
    findings, _hs = collect_handler_sinks(dest, language)
    return findings
