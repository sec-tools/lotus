"""Phase-1 control-plane mapper for HTTP APIs, sandbox agents, queues, and media tools.

Generic grep and C++-shaped high-severity-surface miss:
  - empty-token / skip-middleware fail-open on mutating HTTP
  - Go filepath.Join + ``..``-only validators
  - ``sh -c`` of operator/config commands
  - world-writable secrets (0777)
  - gob/proto unmarshal of network/Redis bytes
  - FFmpeg concat/movie/tee nested protocols

Language-agnostic: mixed monorepos (CubeSandbox Makefile+Rust+Go) must still
light up. Lab proof lives in ``backend/control_plane_poc.py``.
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
    ".tox", "sorbet", "rbi", "licenses", "doxygen",
}

_EXT = {
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".yml", ".yaml",
    ".toml", ".json",
}

_PRIORITY = (
    "**/middleware/auth.rs",
    "**/routes.rs",
    "**/router.go",
    "**/flag/parser.go",
    "**/flag/flags.go",
    "**/pkg/platform/yaml/utils.go",
    "**/utils/command_others.go",
    "**/pkg/service/tools/tools.go",
    "**/pkg/service/tools/sanitize.go",
    "**/pkg/service/import/import.go",
    "**/pkg/platform/yaml/mockdb/db.go",
    "**/pkg/agent/routes/*.go",
    "**/cli/agent.go",
    "**/inspector.go",
    "**/internal/base/base.go",
    "**/libavformat/concatdec.c",
    "**/libavformat/hls.c",
    "**/libavformat/teeproto.c",
    "**/libavformat/subfile.c",
    "**/libavfilter/src_movie.c",
    "**/docs/guide/authentication.md",
    "**/pkg/web/proxy.go",
    "**/pkg/web/router.go",
    "**/pkg/runtime/command.go",
    "**/pkg/service/httpservice/middleware/middleware.go",
    "**/CubeMaster/conf.yaml",
    "**/configs/single-node/cubemaster.yaml",
)


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest))
    except Exception:
        return str(p)


def _hit(title: str, cvss: float, desc: str, file: str, line: int, **extra) -> Dict[str, Any]:
    rec = {
        "tool": extra.pop("tool", "control-plane-surface"),
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


def _iter_priority_then_walk(dest: Path, limit: int = 4000) -> Iterable[Path]:
    dest = Path(dest)
    seen = set()
    n = 0
    for pat in _PRIORITY:
        for p in dest.glob(pat):
            if not p.is_file():
                continue
            key = str(p)
            if key in seen:
                continue
            seen.add(key)
            n += 1
            yield p
            if n >= limit:
                return
    for root, dirs, files in os.walk(dest):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_root = Path(root).relative_to(dest)
        if any(part in SKIP_DIRS for part in rel_root.parts):
            continue
        for fname in files:
            p = Path(root) / fname
            key = str(p)
            if key in seen:
                continue
            if p.suffix.lower() not in _EXT:
                continue
            # Skip huge generated / codec trees except FFmpeg protocol sinks.
            if n > 800 and "libavcodec" in key:
                continue
            seen.add(key)
            n += 1
            if n > limit:
                return
            yield p


def _line_of(text: str, idx: int) -> int:
    if idx < 0:
        return 1
    return text[:idx].count("\n") + 1


_EMPTY_TOKEN = re.compile(
    r"if\s+(?:token|accessToken|ServerAccessToken)\s*==\s*\"\"\s*\{[^}]{0,180}(?:Next\(\)|return Ok)",
    re.S,
)
_GIN_EMPTY_SKIP = re.compile(
    r"if\s+token\s*==\s*\"\"\s*\{\s*ctx\.Next\(\)",
    re.S,
)
_AUTH_SKIP_LAYER = re.compile(
    r"if\s+auth_configured\s*\{[^}]{0,400}from_fn_with_state[^}]+unified_auth",
    re.S,
)
_AUTH_ELSE_BARE = re.compile(
    r"if\s+auth_configured\s*\{[^}]+\} else \{\s*routes\s*\}",
    re.S,
)
_WEAK_DOTDOT = re.compile(
    r"func\s+ValidatePath\s*\([^)]*\)[^{]*\{[^}]{0,400}Contains\([^,]+,\s*\"\.\.\"\)",
    re.S,
)
_SH_C = re.compile(
    r'Command(?:Context)?\s*\([^)]*,\s*"sh"\s*,\s*"-c"\s*,\s*(\w+)',
)
_SH_C_VAR = re.compile(
    r'Command(?:Context)?\s*\([^)]*,\s*(?:shell|bashShell|sh)\s*,\s*"-c"\s*,',
)
_CHMOD_777 = re.compile(r"os\.Chmod\([^,]+,\s*0?777\s*\)|WriteFile\([^,]+,\s*[^,]+,\s*0777\s*\)")
_PROTO_UNMARSHAL = re.compile(r"proto\.Unmarshal\s*\(")
_GOB_DECODE = re.compile(r"gob\.NewDecoder\s*\(")
_CORS_PERM = re.compile(r"CorsLayer::permissive\s*\(")
_DEFAULT_ALLOW_DOC = re.compile(
    r"(allows all requests without any authentication|When omitted, all requests are allowed|both unset\)?: all requests are allowed)",
    re.I,
)
_AGENT_ROUTE = re.compile(r'r\.Route\(\s*"/agent"')
_LISTEN_ALL = re.compile(r'fmt\.Sprintf\(\s*":%d"\s*,\s*flag\.ServerPort')
_TOKEN_DEFAULT_EMPTY = re.compile(r"ServerAccessToken\s*=\s*\"\"")
_CONCAT_SAFE = re.compile(r'\{\s*"safe".*OFFSET\(safe\).*AV_OPT_TYPE_BOOL,\s*\{\.i64\s*=\s*1\}', re.S)
_MOVIE_FILTER = re.compile(r"movie\s*=|ff_movie|src_movie")
_TEE_PROTO = re.compile(r"tee:|teeproto")
_INSPECTOR = re.compile(r"func\s+\(i\s+\*Inspector\)\s+(DeleteQueue|DeleteAllPendingTasks|PauseQueue)\s*\(")
_NO_DB_OPEN = re.compile(r"When no database is configured, the app runs open")
_LOOPBACK_PROXY = re.compile(
    r'Host:\s*"127\.0\.0\.1:"\s*\+\s*port|httputil\.NewSingleHostReverseProxy',
)
_AUTH_ENABLE_SKIP = re.compile(
    r'if\s+!config\.GetConfig\(\)\.AuthConf\.Enable\s*\{\s*return nil',
    re.S,
)
_AUTH_YAML_OFF = re.compile(r"auth:\s*\n[ \t]*enable:\s*false", re.I)
_POSTMAN_FOLDER = re.compile(r"testSet\s*:=\s*item\.Name")
_INSERT_MOCK = re.compile(r"func \(ys \*MockYaml\) InsertMock\(")


def _scan_file(dest: Path, p: Path, text: str) -> List[Dict[str, Any]]:
    rel = _rel(dest, p)
    out: List[Dict[str, Any]] = []
    name = p.name.lower()

    m = _GIN_EMPTY_SKIP.search(text) or _EMPTY_TOKEN.search(text)
    if m and ("router.go" in rel or "auth.rs" in rel or "middleware" in rel):
        out.append(_hit(
            "Empty access token fail-open on HTTP control plane",
            9.1,
            "Auth middleware treats an empty configured token as unauthenticated-allow "
            "(ctx.Next / passthrough). Combined with a command/file API this is unauthenticated "
            "RCE or arbitrary file read. Qualify default-insecure if the product ships token=\"\". "
            "Lab: POST /command or GET /files/download without the token header; oracle uid= or "
            "root: in /etc/passwd. Compare: non-empty token + missing header → 401.",
            rel, _line_of(text, m.start()),
            phase2_hint="empty_token_rce",
            canonical_class="rce",
            primitive_type="rce",
        ))

    if "fn with_auth" in text and "auth_configured" in text and "unified_auth" in text:
        idx = text.find("fn with_auth")
        out.append(_hit(
            "Auth middleware not layered when callback/API key unset",
            9.8,
            "Router skips unified_auth entirely when auth_configured is false (empty "
            "AUTH_CALLBACK_URL and empty CUBE_API_KEY). Mutating sandbox create/kill routes "
            "are then pre-auth. Documented default-insecure; still lab-prove POST /sandboxes "
            "is not 401 and that CubeMaster create is invoked. Empty CUBE_API_KEY string is "
            "the same passthrough as unset.",
            rel, _line_of(text, idx),
            phase2_hint="default_allow_http",
            canonical_class="authz_bypass",
        ))

    if _WEAK_DOTDOT.search(text) and "ValidatePath" in text:
        idx = text.find("func ValidatePath")
        out.append(_hit(
            "Path validator only rejects substring '..' (Clean-then-check bypass)",
            8.1,
            "ValidatePath rejects strings that still contain '..' but callers Join+Clean first. "
            "filepath.Join(base, '../../../../tmp/pwn') resolves to /tmp/pwn.yaml with no "
            "'..' left, so ValidatePath returns it. Go Join does NOT drop an absolute second "
            "argument (unlike Python os.path.join). Lab: CreateFileF(base, '../../../../tmp/lotus_keploy_escape') "
            "must create /tmp/lotus_keploy_escape.yaml. Contrast pathsafe.ValidateSingleSegment.",
            rel, _line_of(text, idx),
            phase2_hint="go_join_absolute",
            canonical_class="path_traversal",
            primitive_type="path_traversal",
        ))

    for m in _SH_C.finditer(text):
        out.append(_hit(
            "User/config command string executed via sh -c (no operator deny-list when sh exists)",
            8.6,
            "CommandContext runs `sh -c <cmdStr>` whenever /bin/sh is on PATH. Shell operators "
            "are only refused in the distroless fallback. If cmdStr is config- or network-sourced, "
            "this is command injection. Lab: CommandContext(`echo LOTUS_RCE_OK; id`) must contain "
            "uid=. Combine with world-writable keploy.yml (chmod 0777) for local PE.",
            rel, _line_of(text, m.start()),
            phase2_hint="sh_c_user_cmd",
            canonical_class="rce",
            primitive_type="rce",
        ))

    if _SH_C_VAR.search(text) and ("request.Code" in text or "getShell" in text):
        idx = text.find('"-c"')
        out.append(_hit(
            "Sandbox/agent executes request.Code via shell -c",
            9.1,
            "exec.CommandContext(ctx, shell, \"-c\", request.Code) runs attacker HTTP body as "
            "the execd uid when the access-token middleware fail-opens. Lab: runtime.Controller "
            "Language=command Code=`echo LOTUS_RCE_OK; id` → uid=.",
            rel, _line_of(text, idx),
            phase2_hint="empty_token_rce",
            canonical_class="rce",
            primitive_type="rce",
        ))

    for m in _CHMOD_777.finditer(text):
        if "0777" not in m.group(0) and "777" not in m.group(0):
            continue
        out.append(_hit(
            "Secrets/config written world-writable (mode 0777)",
            7.8,
            "keploy.yml / secret.yaml are written then chmod 0777. Any local user can rewrite "
            "`command:` which ExecuteCommand later runs via sh -c as the operator. Lab: generate "
            "config, stat mode 0777, rewrite command, prove CommandContext executes it.",
            rel, _line_of(text, m.start()),
            phase2_hint="world_writable_config",
            canonical_class="authz_bypass",
            primitive_type="privilege_escalation",
        ))

    if _GOB_DECODE.search(text) and ("/agent" in text or "StoreMocks" in text or "gob.NewDecoder(r.Body)" in text):
        idx = text.find("gob.NewDecoder")
        out.append(_hit(
            "Unauthenticated agent HTTP decodes gob from the request body",
            8.1,
            "POST /agent/storemocks (and siblings) have no auth middleware. gob.NewDecoder(r.Body) "
            "ingests client-chosen types into Mock structs and persists them. Combined with "
            "hostNetwork DaemonSet comments admitting the plane is unauthenticated, sidecar bind "
            ":port is a mutating control plane. Lab: httptest the chi router without headers; "
            "POST /agent/health is 200; POST /agent/stop or storemocks is not 401. Prefer file-write "
            "or process-stop impact over DoS-only scoring.",
            rel, _line_of(text, idx),
            phase2_hint="unauth_agent_http",
            canonical_class="authz_bypass",
        ))

    if _AGENT_ROUTE.search(text) and "chi" in text.lower() and "middleware" not in text.lower()[:400]:
        # record.go registers /agent with no Use(auth)
        if "r.Post(\"/stop\"" in text or 'r.Post("/storemocks"' in text:
            idx = text.find('r.Route("/agent"')
            out.append(_hit(
                "Keploy agent control-plane HTTP has no authentication middleware",
                8.6,
                "chi routes for /agent/stop, /agent/storemocks, /agent/incoming are registered "
                "with no bearer/mTLS gate. cli/agent.go skips the bind only for DaemonSet "
                "hostNetwork; sidecar/docker still Listen :port unauthenticated. Lab: mount "
                "DefaultRoutes.New on a fake Service, POST /agent/stop without headers → 200 "
                "and process teardown, or storemocks accepted.",
                rel, _line_of(text, idx),
                phase2_hint="unauth_agent_http",
            ))

    if _PROTO_UNMARSHAL.search(text) and ("TaskMessage" in text or "asynq" in rel):
        idx = text.find("proto.Unmarshal")
        out.append(_hit(
            "Queue task bytes proto.Unmarshal'd from Redis with no asynq-level ACL",
            7.5,
            "DecodeMessage proto.Unmarshals attacker-reachable Redis values into TaskMessage "
            "(type + payload). Inspector/Client can enqueue/delete/pause with only Redis "
            "connectivity. Default Redis has no requirepass. Qualify: Redis is TCB — still "
            "lab-prove unauthenticated Redis → worker handler execution or queue wipe. "
            "Do not report 'use Redis TLS' without that oracle.",
            rel, _line_of(text, idx),
            phase2_hint="redis_queue_admin",
            canonical_class="rce",
            primitive_type="deserialization",
        ))

    if _INSPECTOR.search(text):
        idx = text.find("func (i *Inspector)")
        out.append(_hit(
            "Asynq Inspector mutates queues with Redis credentials only (often none)",
            7.5,
            "DeleteQueue / DeleteAllPendingTasks / PauseQueue have no application ACL. "
            "Lab: Redis without AUTH, Inspector.DeleteAllPendingTasks after enqueue; "
            "oracle = pending count 0 plus worker-executed marker if a handler is registered.",
            rel, max(_line_of(text, idx), 1),
            phase2_hint="redis_queue_admin",
            canonical_class="authz_bypass",
        ))

    if _CORS_PERM.search(text) and ("with_auth" in text or "auth_configured" in text):
        idx = text.find("CorsLayer::permissive")
        out.append(_hit(
            "Permissive CORS on API that defaults to no authentication",
            7.1,
            "CorsLayer::permissive() plus skipped auth middleware means a browser on any origin "
            "can call mutating sandbox APIs when CUBE_API_KEY is unset. Lab: OPTIONS/POST "
            "without Origin rejection.",
            rel, _line_of(text, idx),
            phase2_hint="default_allow_http",
        ))

    if _DEFAULT_ALLOW_DOC.search(text):
        m = _DEFAULT_ALLOW_DOC.search(text)
        out.append(_hit(
            "Docs confirm default-allow HTTP API (no credential check)",
            9.1,
            "Project documentation states the default is unauthenticated allow. Same class as "
            "README docker run with empty root: qualify default-insecure, prove mutating verb "
            "impact (create/kill sandbox, not GET /health).",
            rel, _line_of(text, m.start() if m else 0),
            phase2_hint="default_allow_http",
        ))

    if _NO_DB_OPEN.search(text):
        m = _NO_DB_OPEN.search(text)
        out.append(_hit(
            "WebUI AuthGuard fail-open when no database is configured",
            7.5,
            "AuthGuard allows the app when auth is not required. Confirm CubeOps JWT "
            "middleware is actually skipped; Session handler currently hard-codes AuthRequired=true. "
            "Lab: start CubeOps without DATABASE_URL and attempt mutating /api/v1/sdk routes.",
            rel, _line_of(text, m.start() if m else 0),
            phase2_hint="default_allow_http",
            qualification="LATENT",
            confidence="medium",
        ))

    if _LISTEN_ALL.search(text) or _TOKEN_DEFAULT_EMPTY.search(text):
        if "ServerAccessToken" in text and ("44772" in text or "ServerPort" in text or ":%d" in text):
            idx = text.find("ServerAccessToken")
            if idx < 0:
                idx = text.find(":%d")
            out.append(_hit(
                "execd defaults to empty access token and binds all IPv4 interfaces",
                9.8,
                "flag.ServerAccessToken defaults to \"\"; main listens on :PORT (0.0.0.0). "
                "Empty-token middleware skip then exposes /command, /code, /files, /pty. "
                "Lab: NewRouter(\"\") POST /command echo/id; NewRouter(\"secret\") without header → 401. "
                "Impact: command stdout contains uid= or LOTUS_RCE_OK; file download of /etc/passwd.",
                rel, _line_of(text, idx),
                phase2_hint="empty_token_rce",
                canonical_class="rce",
                primitive_type="rce",
            ))

    if _LOOPBACK_PROXY.search(text) and "/proxy/" in text and "127.0.0.1" in text:
        idx = text.find("127.0.0.1")
        out.append(_hit(
            "Unauthenticated reverse proxy to 127.0.0.1:port (loopback SSRF)",
            8.6,
            "HTTP /proxy/{port}/... is rewritten to http://127.0.0.1:{port}. Combined with "
            "empty-token fail-open this is unauthenticated loopback SSRF (credential vault, "
            "sidecars, cloud metadata stubs). Lab: NewRouter(\"\") GET /proxy/{port}/secret "
            "against a local httptest marker LOTUS_SSRF_OK; NewRouter(secret) without header → 401.",
            rel, _line_of(text, idx),
            phase2_hint="empty_token_rce",
            canonical_class="ssrf",
            primitive_type="ssrf",
        ))

    if _AUTH_ENABLE_SKIP.search(text):
        m = _AUTH_ENABLE_SKIP.search(text)
        out.append(_hit(
            "Control-plane HTTP auth skipped when AuthConf.Enable is false",
            9.8,
            "checkAuth returns nil when AuthConf.Enable is false. Shipped CubeMaster conf.yaml "
            "and k8s chart set auth.enable: false; HttpBind defaults to 0.0.0.0:8089. "
            "Lab: unsigned POST /cube/sandbox with Enable=false must reach the handler "
            "(not AuthFailed); Enable=true must reject.",
            rel, _line_of(text, m.start()),
            phase2_hint="default_allow_http",
            canonical_class="authz_bypass",
        ))

    if _AUTH_YAML_OFF.search(text) and ("cubemaster" in rel.lower() or "cube-master" in rel.lower()):
        m = _AUTH_YAML_OFF.search(text)
        out.append(_hit(
            "Shipped CubeMaster config disables HTTP signature auth",
            9.1,
            "auth.enable: false in the product config (single-node, chart, CubeMaster/conf.yaml). "
            "Qualify default-insecure. Pair with checkAuth skip and 0.0.0.0 bind.",
            rel, _line_of(text, m.start()),
            phase2_hint="default_allow_http",
            canonical_class="authz_bypass",
        ))

    if _POSTMAN_FOLDER.search(text) and "keploy" in text.lower():
        idx = text.find("testSet := item.Name")
        out.append(_hit(
            "Postman collection folder name used as filepath.Join component",
            7.8,
            "importTestSets sets testSet := item.Name then Join(cwd, \"keploy\", testSet, \"tests\"). "
            "testdb validateNameComponent is NOT called. A hostile collection folder "
            "`../../../../tmp/pwn` writes outside the workspace. Lab: importTestSets with that "
            "name must create /tmp/lotus_keploy_postman/tests/test-1.yaml.",
            rel, _line_of(text, idx),
            phase2_hint="go_join_absolute",
            canonical_class="path_traversal",
            primitive_type="path_traversal",
        ))

    if _INSERT_MOCK.search(text) and "validateNameComponent" not in text:
        idx = text.find("func (ys *MockYaml) InsertMock")
        out.append(_hit(
            "mockdb.InsertMock joins testSetID without validateNameComponent",
            8.1,
            "testdb.upsert rejects .. in testSetID; mockdb.InsertMock does filepath.Join(MockPath, "
            "testSetID) then CreateFileF. Hostile testSetID ../../../../tmp/x writes mocks.yaml "
            "outside the keploy tree. Lab: InsertMock(..., \"../../../../../../tmp/lotus_keploy_mockset\").",
            rel, _line_of(text, idx),
            phase2_hint="go_join_absolute",
            canonical_class="path_traversal",
            primitive_type="path_traversal",
        ))

    if name == "concatdec.c" and "safe_filename" in text:
        idx = text.find("safe_filename")
        out.append(_hit(
            "FFmpeg concat demuxer can open extra URLs when safe=0 or protocol prefix is used",
            7.5,
            "concatdec safe defaults to 1 (relative alphanumeric names). With -safe 0 or a "
            "protocol-prefixed filename (file:, http:, concat:) add_file opens attacker URLs. "
            "CLI -i of a user file is by-design; hunt nested opens from HLS/movie/tee of "
            "untrusted input. Lab: default ffmpeg -f concat -i playlist with file:/etc/passwd "
            "must FAIL (DISPROVE); nested HLS file: or movie= filter from a crafted media file "
            "is the ≥7 path if it succeeds without operator -safe 0.",
            rel, _line_of(text, idx),
            phase2_hint="ffmpeg_nested_protocol",
            canonical_class="path_traversal",
            primitive_type="ssrf",
        ))

    if name in {"hls.c", "src_movie.c", "teeproto.c", "subfile.c"}:
        idx = 1
        title = f"FFmpeg {name} nested URL/file sink (protocol whitelist)"
        out.append(_hit(
            title,
            7.5,
            f"{rel} opens nested URLs (file/http/tee/subfile/movie). Prove a path from "
            "untrusted media (not operator argv -i /etc/passwd). Lab: serve an HLS playlist "
            "whose segment URI is file:///etc/passwd; if ffmpeg copies passwd bytes into the "
            "output, that is local file read. DISPROVE if protocol_whitelist blocks file:.",
            rel, idx,
            phase2_hint="ffmpeg_nested_protocol",
            canonical_class="path_traversal",
            primitive_type="ssrf",
            confidence="medium",
        ))

    return out


def collect_control_plane(dest: Path, language: str = "") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dest = Path(dest)
    findings: List[Dict[str, Any]] = []
    n_files = 0
    for p in _iter_priority_then_walk(dest):
        n_files += 1
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        if len(text) > 1_500_000:
            text = text[:1_500_000]
        findings.extend(_scan_file(dest, p, text))

    seen = set()
    uniq: List[Dict[str, Any]] = []
    for f in findings:
        k = (f.get("title"), f.get("file"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)

    trace = {
        "n_files": n_files,
        "n_findings": len(uniq),
        "language": language,
        "tools": sorted({f["tool"] for f in uniq}),
        "hints": sorted({f.get("phase2_hint") or "" for f in uniq} - {""}),
    }
    try:
        out_dir = dest / ".lotus"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "control_plane_trace.json").write_text(
            json.dumps({
                "trace": trace,
                "leads": [
                    {"title": f["title"], "file": f["file"], "line": f["line"],
                     "cvss": f["cvss"], "hint": f.get("phase2_hint")}
                    for f in uniq[:60]
                ],
            }, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    return uniq, trace


def _run_control_plane_surface(dest: Path, language: str) -> List[dict]:
    findings, _trace = collect_control_plane(dest, language)
    return findings
