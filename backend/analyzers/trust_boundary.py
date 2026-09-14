"""Phase-1 trust-boundary mapper.

``attack-surface-map`` greps filenames and misses Rust (CubeAPI). Phase 2 then
plans from empty ``admin_namespaces`` / ``routes``. This mapper extracts
*concrete* HTTP routes, whether auth middleware wraps them, listen/bind
defaults, shipped config fail-open, sibling guard gaps, and queue/protocol
TCBs — and writes ``.lotus/trust_boundary.json`` so Phase 2 can probe
unauthenticated mutating verbs instead of guessing controllers.

Does not confirm vulnerabilities. Lab proof still required.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", ".venv", "venv",
    "target", "build", "dist", "testdata", "fixtures", "third_party", "thirdparty",
    ".tox", "doxygen",
}

_CODE_EXT = {".go", ".rs", ".py", ".js", ".ts", ".rb", ".java", ".php", ".c", ".cc", ".cpp", ".h"}
_CFG_EXT = {".yml", ".yaml", ".toml", ".json", ".conf"}

_GIN_CHI = re.compile(
    r"""(?:^|[^A-Za-z])(?:(\w+)\.)?(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*["'](/[^"']*)["']""",
    re.M,
)
_CHI_ROUTE = re.compile(r"""\.Route\(\s*["'](/[^"']*)["']""")
_GIN_GROUP = re.compile(r"""(\w+)\s*:?=\s*\w*\.Group\(\s*["'](/[^"']*)["']""")
_AXUM_ROUTE = re.compile(
    r"""\.route\(\s*["'](/[^"']+)["']\s*,\s*(get|post|put|patch|delete)\s*\(""",
    re.I,
)
_MUX_HANDLE = re.compile(r"""(?:HandleFunc|Handle)\(\s*["'](/[^"']+)["']""")
_LISTEN = re.compile(
    r"""ListenAndServe\(\s*"([^"]*)"|fmt\.Sprintf\(\s*":%d"|HttpBind\s*[:=]\s*"([^"]*)"|["']0\.0\.0\.0:""",
)
_EMPTY_TOKEN = re.compile(r"""(?:ServerAccessToken|accessToken|token)\s*[:=]\s*""\s*(?:$|[,;])""", re.M)
_AUTH_MW = re.compile(
    r"accessTokenMiddleware|unified_auth|checkAuth|GinRequestMiddleware|AuthGuard|with_auth",
)
_AUTH_SKIP = re.compile(
    r"""if\s+token\s*==\s*""|if\s+!.*AuthConf\.Enable|auth_configured|if\s+auth_configured""",
)
_REDIS_TCB = re.compile(r"RedisClientOpt|NewInspector\s*\(|proto\.Unmarshal\s*\(")
_JOIN_WRITE = re.compile(r"filepath\.Join\s*\(|CreateFileF\s*\(|WriteFileF\s*\(")
_GUARD_FUNC = re.compile(r"func\s+validateNameComponent\s*\(|ValidateSingleSegment|pathsafe")
_NESTED_IO = re.compile(r"nested_io_open|avio_open|ffurl_open")
_CFG_AUTH_OFF = re.compile(r"auth:\s*\n[ \t]+enable:\s*false", re.I)


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest))
    except Exception:
        return str(p)


def _iter_files(dest: Path, limit: int = 3500) -> Iterable[Path]:
    n = 0
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_root = Path(root).relative_to(dest)
        if any(part in SKIP_DIRS for part in rel_root.parts):
            continue
        for fname in files:
            p = Path(root) / fname
            ext = p.suffix.lower()
            if fname.endswith(("_test.go", "_test.rs", "_test.py", "_spec.rb")):
                continue
            if ext not in _CODE_EXT and ext not in _CFG_EXT:
                continue
            if "libavcodec" in str(p) and n > 400:
                continue
            n += 1
            if n > limit:
                return
            yield p


def _is_mutating(method: str) -> bool:
    return method.upper() in {"POST", "PUT", "PATCH", "DELETE"}


def _mux_likely_mutating(path: str, handler: str) -> bool:
    """std mux HandleFunc has no method; infer mutating from path/handler name."""
    blob = f"{path} {handler}".lower()
    if any(x in blob for x in ("health", "ready", "ping", "metrics", "status")):
        return False
    return any(
        x in blob
        for x in (
            "resume", "create", "delete", "kill", "update", "upload", "pause",
            "stop", "insert", "sandbox", "command", "exec", "run", "proxy",
        )
    )


def _handler_from_line(line: str) -> str:
    """Best-effort handler name from a gin/chi/axum registration line."""
    m = re.search(r"\bc\.([A-Z]\w+)\(\)", line)
    if m:
        return m.group(1)
    m = re.search(
        r"(?:get|post|put|patch|delete|any)\s*\(\s*([A-Za-z_:][\w:]*)",
        line, re.I,
    )
    if m:
        return m.group(1).split("::")[-1]
    m = re.search(r",\s*(?:[A-Za-z_]\w*\.)+([A-Z]\w+)\s*\)?\s*$", line.strip())
    if m:
        return m.group(1)
    m = re.search(r",\s*([A-Z]\w+)\s*\)?\s*$", line.strip())
    if m:
        return m.group(1)
    return ""


def _hit(title: str, cvss: float, desc: str, file: str, line: int, **extra) -> Dict[str, Any]:
    rec = {
        "tool": extra.pop("tool", "trust-boundary-map"),
        "title": title,
        "cvss": cvss,
        "description": desc,
        "file": file,
        "line": line,
        "confidence": extra.pop("confidence", "high"),
        "qualification": extra.pop("qualification", "QUALIFIED"),
        "phase2_hint": extra.pop("phase2_hint", "http_unauth_mutate"),
        "canonical_class": extra.pop("canonical_class", "authz_bypass"),
        "primitive_type": extra.pop("primitive_type", "auth_bypass"),
    }
    rec.update(extra)
    return rec


def _extract_routes_from_text(text: str, rel: str) -> List[Dict[str, Any]]:
    routes: List[Dict[str, Any]] = []
    groups = {m.group(1): m.group(2).rstrip("/") for m in _GIN_GROUP.finditer(text)}
    chi_prefixes = [m.group(1).rstrip("/") for m in _CHI_ROUTE.finditer(text)]

    def add(method: str, path: str, line: int, prefix: str = "", handler: str = "") -> None:
        # Skip commented-out registrations (keploy `// r.Post("/testbench"`).
        src_line = text.splitlines()[line - 1] if 0 < line <= len(text.splitlines()) else ""
        stripped = src_line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("--"):
            return
        full = (prefix + path) if path.startswith("/") else (prefix + "/" + path)
        if path == "" or path == "/":
            full = prefix or path or "/"
        if not full.startswith("/"):
            full = "/" + full
        routes.append({
            "method": method.upper(),
            "path": re.sub(r"/{2,}", "/", full),
            "file": rel,
            "line": line,
            "mutating": _is_mutating(method),
            "handler": handler or _handler_from_line(src_line),
        })

    for m in _GIN_CHI.finditer(text):
        recv, method, path = m.group(1), m.group(2), m.group(3)
        line = text[:m.start()].count("\n") + 1
        prefix = groups.get(recv or "", "")
        if not prefix and chi_prefixes and not path.startswith(tuple(chi_prefixes)):
            # chi inner r.Post("/storemocks") under r.Route("/agent", ...)
            prefix = chi_prefixes[0]
        add(method, path, line, prefix)

    for m in _AXUM_ROUTE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        src_line = text.splitlines()[line - 1] if 0 < line <= len(text.splitlines()) else ""
        add(m.group(2), m.group(1), line, handler=_handler_from_line(src_line))

    for m in _MUX_HANDLE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        src_line = text.splitlines()[line - 1] if 0 < line <= len(text.splitlines()) else ""
        handler = _handler_from_line(src_line)
        path = m.group(1)
        method = "POST" if _mux_likely_mutating(path, handler) else "ANY"
        add(method, path, line, handler=handler)

    return routes


def collect_trust_boundary(dest: Path, language: str = "") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dest = Path(dest)
    http_routes: List[Dict[str, Any]] = []
    listen_binds: List[Dict[str, Any]] = []
    auth_gates: List[Dict[str, Any]] = []
    config_fail_open: List[Dict[str, Any]] = []
    sibling_gaps: List[Dict[str, Any]] = []
    queue_tcbs: List[Dict[str, Any]] = []
    nested_io: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    guard_files: List[str] = []
    join_write_files: List[Tuple[str, int]] = []

    n_files = 0
    for p in _iter_files(dest):
        n_files += 1
        rel = _rel(dest, p)
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if len(text) > 800_000:
            text = text[:800_000]

        if p.suffix.lower() in _CODE_EXT:
            file_routes = _extract_routes_from_text(text, rel)
            http_routes.extend(file_routes)

            has_auth_mw = bool(_AUTH_MW.search(text))
            has_skip = bool(_AUTH_SKIP.search(text) or _EMPTY_TOKEN.search(text))
            if has_auth_mw or has_skip:
                idx = text.find("accessTokenMiddleware")
                if idx < 0:
                    idx = text.find("checkAuth")
                if idx < 0:
                    idx = text.find("unified_auth")
                auth_gates.append({
                    "file": rel,
                    "has_middleware": has_auth_mw,
                    "fail_open": has_skip,
                    "line": text[:max(idx, 0)].count("\n") + 1,
                })

            for m in _LISTEN.finditer(text):
                bind = m.group(1) or m.group(2) or "0.0.0.0"
                listen_binds.append({
                    "file": rel,
                    "bind": bind or ":%d",
                    "all_interfaces": "0.0.0.0" in (bind or "") or bind == ":%d" or ":%d" in m.group(0),
                    "line": text[:m.start()].count("\n") + 1,
                })

            if _REDIS_TCB.search(text) and ("inspector" in rel.lower() or "asynq" in rel.lower() or "base.go" in rel.lower()):
                queue_tcbs.append({"file": rel, "kind": "redis-queue"})
            if _NESTED_IO.search(text) and any(x in rel for x in ("hls.c", "dashdec.c", "concatdec.c", "src_movie.c", "teeproto.c")):
                nested_io.append({"file": rel, "kind": "nested-protocol"})

            if _GUARD_FUNC.search(text):
                guard_files.append(rel)
            if _JOIN_WRITE.search(text) and "func validateNameComponent" not in text:
                join_write_files.append((rel, text.find("filepath.Join") if "filepath.Join" in text else 1))

        if p.suffix.lower() in _CFG_EXT and _CFG_AUTH_OFF.search(text):
            if "cubemaster" in rel.lower() or "cube-master" in rel.lower() or rel.endswith("conf.yaml"):
                m = _CFG_AUTH_OFF.search(text)
                config_fail_open.append({
                    "file": rel,
                    "key": "auth.enable",
                    "value": False,
                    "line": text[:m.start()].count("\n") + 1 if m else 1,
                })

    # Dedupe routes
    seen_rt = set()
    uniq_routes: List[Dict[str, Any]] = []
    for r in http_routes:
        k = (r["method"], r["path"], r["file"])
        if k in seen_rt:
            continue
        seen_rt.add(k)
        uniq_routes.append(r)
    http_routes = uniq_routes[:400]

    auth_files = {g["file"] for g in auth_gates}
    fail_open_files = {g["file"] for g in auth_gates if g.get("fail_open")}
    unauth_mutating: List[Dict[str, Any]] = []
    for r in http_routes:
        if not r["mutating"]:
            continue
        # Unauth if the route file has fail-open, OR the file has routes but no auth middleware
        # and is a known control-plane name.
        in_fail_open = r["file"] in fail_open_files
        no_mw = r["file"] not in auth_files
        controlish = any(x in r["file"].lower() for x in (
            "router.go", "routes.go", "routes.rs", "record.go", "replay.go", "server.go",
        ))
        if in_fail_open or (no_mw and controlish):
            rec = dict(r)
            rec["why"] = "fail-open middleware" if in_fail_open else "no auth middleware in route file"
            unauth_mutating.append(rec)

    # Sibling: guard defined in one package, Join+write in a sibling without the guard.
    if guard_files:
        interesting_unguarded = ("mockdb", "/import/", "openapidb", "mapdb")
        for rel, idx in join_write_files:
            if rel in guard_files:
                continue
            if not any(tok in rel.replace("\\", "/") for tok in interesting_unguarded):
                continue
            sibling_gaps.append({
                "guard_files": guard_files[:6],
                "unguarded_file": rel,
                "primitive": "path_join",
            })

    # Findings — map summary always (intel, not a vuln).
    findings.append(_hit(
        f"Trust-boundary map: {len(http_routes)} HTTP routes "
        f"({sum(1 for r in http_routes if r['mutating'])} mutating, "
        f"{len(unauth_mutating)} unauth-mutating)",
        0.0,
        "Structured entrypoint map for Phase 2. Unauth mutating routes, bind-all, "
        "config fail-open, and sibling missing guards are listed in "
        ".lotus/trust_boundary.json. This row is inventory, not a confirmed vuln.",
        unauth_mutating[0]["file"] if unauth_mutating else (http_routes[0]["file"] if http_routes else ""),
        unauth_mutating[0]["line"] if unauth_mutating else 1,
        qualification="INVENTORY",
        confidence="high",
        phase2_hint="control_plane_map",
        record_type="inventory-summary",
        result_type="inventory",
        inventory_only=True,
        inventory_artifact=".lotus/trust_boundary.json",
        canonical_class="",
        primitive_type="",
    ))
    # Cap per-route leads so Phase 2 gets verbs, not 200 duplicates of control-plane-surface.
    for r in unauth_mutating[:18]:
        findings.append(_hit(
            f"Unauthenticated mutating {r['method']} {r['path']}",
            8.6 if r["mutating"] else 7.5,
            f"Trust-boundary map: {r['method']} {r['path']} in {r['file']}:{r['line']} "
            f"({r.get('why')}). Lab: hit this verb without credentials; require a mutating "
            f"oracle (create/kill/write/RCE), not 200-without-effect.",
            r["file"], r["line"],
            phase2_hint="http_unauth_mutate",
            canonical_class="authz_bypass",
        ))
    for cfg in config_fail_open[:6]:
        findings.append(_hit(
            f"Shipped config disables control-plane auth ({cfg['file']})",
            9.1,
            f"{cfg['key']}=false in {cfg['file']}. Pair with checkAuth skip and 0.0.0.0 bind. "
            "Qualify default-insecure; lab-prove a mutating route is not AuthFailed.",
            cfg["file"], cfg["line"],
            phase2_hint="default_allow_http",
        ))
    for gap in sibling_gaps[:8]:
        findings.append(_hit(
            f"Sibling missing path guard: {gap['unguarded_file']}",
            8.1,
            f"{gap['unguarded_file']} Joins/writes without validateNameComponent; "
            f"guard lives in {gap['guard_files'][:3]}. Lab: hostile .. name after Join+Clean.",
            gap["unguarded_file"], 1,
            phase2_hint="go_join_absolute",
            canonical_class="path_traversal",
            primitive_type="path_traversal",
        ))
    bind_all = [b for b in listen_binds if b.get("all_interfaces")]
    if bind_all and (fail_open_files or config_fail_open):
        b = bind_all[0]
        findings.append(_hit(
            "Listen-all-interfaces combined with fail-open / auth-off",
            9.1,
            f"{b['file']} binds {b['bind']} (all interfaces) while auth is skippable. "
            "Lab: unauthenticated client to the listen port, mutating oracle.",
            b["file"], b["line"],
            phase2_hint="empty_token_rce",
            canonical_class="rce",
        ))

    tb = {
        "n_files": n_files,
        "language": language,
        "http_routes": http_routes,
        "unauth_mutating": unauth_mutating[:40],
        "listen_binds": listen_binds[:40],
        "auth_gates": auth_gates[:40],
        "config_fail_open": config_fail_open,
        "sibling_gaps": sibling_gaps[:20],
        "queue_tcbs": queue_tcbs[:20],
        "nested_io": nested_io[:20],
        "counts": {
            "routes": len(http_routes),
            "mutating": sum(1 for r in http_routes if r["mutating"]),
            "unauth_mutating": len(unauth_mutating),
            "binds": len(listen_binds),
            "auth_gates": len(auth_gates),
            "config_fail_open": len(config_fail_open),
            "sibling_gaps": len(sibling_gaps),
        },
    }
    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "trust_boundary.json").write_text(
            json.dumps(tb, indent=2, default=str), encoding="utf-8",
        )
    except Exception:
        pass
    return findings, tb


def _run_trust_boundary_map(dest: Path, language: str) -> List[dict]:
    findings, _tb = collect_trust_boundary(dest, language)
    return findings
