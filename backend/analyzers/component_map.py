"""Phase-1 component × lab mapper.

Monorepos (CubeSandbox, OpenSandbox) have independently deployed binaries in
different languages. ``detect_language`` returns one primary (rust/go), so
Phase 2 labs CubeAPI with cargo and never schedules CubeMaster /
cube-lifecycle-manager / execd as their own TCBs with a concrete lab recipe.

This mapper inventories go.mod / Cargo.toml / Dockerfiles / media demuxers,
attaches trust-boundary routes and handler sinks to the owning component, and
writes ``.lotus/component_map.json`` so Phase 2 gets per-binary lab tasks
(docker golang:1.25 go test, static-ffmpeg, Redis sidecar) instead of one
python http.server fallback.

Does not confirm vulnerabilities. Lab proof still required.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.analyzers.trust_boundary import collect_trust_boundary
from backend.analyzers.handler_sink import collect_handler_sinks

_SKIP_PARTS = {
    "examples", "testdata", "vendor", "node_modules", ".git", "fuzz",
    "third_party", "thirdparty", "sdks", "sdk", "tests", "target", "build",
}

_HYPERVISOR_ROOT = "hypervisor"

_GO_MOD_MODULE = re.compile(r"^module\s+(\S+)", re.M)

_LAB_GO = {
    "kind": "docker-go-test",
    "image": "golang:1.25",
    "constraints": [
        "docker -v must be absolute Path.resolve() (relative paths become volume names)",
        "golang image: sh -c, not bash -lc (login shell drops go from PATH)",
        "go test -v or t.Log oracles never appear",
        "httputil.ReverseProxy: httptest.NewServer, not ResponseRecorder",
        "host.docker.internal on Mac, not --network host",
    ],
}
_LAB_RUST = {
    "kind": "docker-cargo-test",
    "image": "rust:1.85",
    "constraints": [
        "Use production build_router / unit tests that call real routes, not mocks that skip auth",
        "Auth-off is default-insecure; prove mutating verb is not 401",
    ],
}
_LAB_FFMPEG = {
    "kind": "docker-static-ffmpeg",
    "image": "mwader/static-ffmpeg:7.1",
    "constraints": [
        "Image has no sh: one ffmpeg invocation per step, not a shell script",
        "Nested playlist/MPD open is the TCB, not CLI -i /etc/passwd",
        "Output muxer extension can fail after a successful nested open — retry -f mp4",
    ],
}
_LAB_REDIS = {
    "kind": "docker-redis-sidecar",
    "image": "redis:7-alpine",
    "constraints": [
        "User-defined bridge + host.docker.internal; do not --network host on Mac",
        "Oracle is worker handler side-effect, not queue-wipe DoS",
        "go.mod replace from .lotus/pocs must reach module root",
    ],
}


def _rel(dest: Path, p: Path) -> str:
    try:
        return str(p.relative_to(dest)).replace("\\", "/")
    except Exception:
        return str(p)


def _skip(rel: str) -> bool:
    parts = set(rel.replace("\\", "/").split("/"))
    if parts & _SKIP_PARTS:
        return True
    # Collapse hypervisor crates into one component at hypervisor/.
    if rel.startswith("hypervisor/") and rel != "hypervisor/Cargo.toml":
        if rel.count("/") > 1 and rel.endswith("Cargo.toml"):
            return True
    return False


def _lang_for_manifest(p: Path) -> str:
    if p.name == "go.mod":
        return "go"
    if p.name == "Cargo.toml":
        return "rust"
    return ""


def _component_name(dest: Path, manifest: Path) -> str:
    parent = manifest.parent
    if parent == dest:
        return dest.name
    return parent.name


def _lab_for(language: str, kind: str, name: str) -> Dict[str, Any]:
    n = name.lower()
    if "ffmpeg" in n or kind == "media-demuxer":
        return dict(_LAB_FFMPEG)
    if "asynq" in n or kind == "queue-library":
        rec = dict(_LAB_REDIS)
        rec["worker_image"] = "golang:1.24"
        return rec
    if language == "rust":
        return dict(_LAB_RUST)
    if language == "go":
        return dict(_LAB_GO)
    if language == "c/cpp":
        return dict(_LAB_FFMPEG)
    return {"kind": "unknown", "image": "", "constraints": []}


def _kind_for(name: str, language: str, has_http: bool, has_docker: bool) -> str:
    n = name.lower()
    if any(x in n for x in ("hls", "dash", "concat", "teeproto")):
        return "media-demuxer"
    if "asynq" in n or n == "inspector":
        return "queue-library"
    if has_http:
        return "http-control-plane"
    if has_docker:
        return "deployed-binary"
    if language == "c/cpp":
        return "native-library"
    return "library"


def collect_component_map(
    dest: Path,
    language: str = "",
    tb: Optional[Dict[str, Any]] = None,
    hs: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    dest = Path(dest)
    if tb is None:
        from backend.tool_registry import is_tool_enabled
        if is_tool_enabled("trust-boundary-map"):
            _, tb = collect_trust_boundary(dest, language)
        else:
            tb = {"status": "skipped", "reason": "Trust-boundary inputs disabled by capabilities configuration",
                  "configure_tool": "trust-boundary-map", "coverage_complete": False}
    if hs is None:
        from backend.tool_registry import is_tool_enabled
        if is_tool_enabled("handler-sink-trace"):
            _, hs = collect_handler_sinks(dest, language, tb=tb)
        else:
            hs = {"status": "skipped", "reason": "Handler-sink inputs disabled by capabilities configuration",
                  "configure_tool": "handler-sink-trace", "coverage_complete": False}

    manifests: List[Path] = []
    for pat in ("go.mod", "Cargo.toml"):
        for p in dest.rglob(pat):
            rel = _rel(dest, p)
            if _skip(rel):
                continue
            # Depth cap: repo root, one level, or components/<name>/
            depth = rel.count("/")
            if depth > 2:
                continue
            manifests.append(p)

    # FFmpeg: no go.mod. Treat nested_io files as components.
    if (dest / "libavformat").is_dir():
        for nio in tb.get("nested_io") or []:
            fp = dest / (nio.get("file") or "")
            if fp.is_file():
                manifests.append(fp)

    components: List[Dict[str, Any]] = []
    seen = set()
    for man in manifests:
        rel_man = _rel(dest, man)
        root = man.parent if man.name in {"go.mod", "Cargo.toml"} else man.parent
        key = _rel(dest, root)
        if key in seen:
            continue
        seen.add(key)
        name = dest.name if root == dest else root.name
        lang = _lang_for_manifest(man) or (
            "c/cpp" if man.suffix == ".c" else language or ""
        )
        docker = ""
        for df in ("Dockerfile", "docker/Dockerfile"):
            cand = root / df
            if cand.is_file():
                docker = _rel(dest, cand)
                break
        prefix = key if key != "." else ""

        def _under(path: str) -> bool:
            path = (path or "").replace("\\", "/")
            if not prefix or prefix in {".", dest.name}:
                # Root module: only files not owned by a nested component later.
                return True
            return path == prefix or path.startswith(prefix + "/")

        routes = [r for r in (tb.get("unauth_mutating") or []) if _under(r.get("file") or "")]
        binds = [b for b in (tb.get("listen_binds") or []) if _under(b.get("file") or "")]
        gates = [g for g in (tb.get("auth_gates") or []) if _under(g.get("file") or "")]
        cfgs = [c for c in (tb.get("config_fail_open") or []) if _under(c.get("file") or "")]
        sinks = [s for s in (hs.get("priority") or []) if _under(s.get("route_file") or s.get("handler_file") or "")]
        fail_open = any(g.get("fail_open") for g in gates) or bool(cfgs)
        bind_all = any(b.get("all_interfaces") for b in binds)
        kind = _kind_for(name, lang, bool(routes or binds), bool(docker))
        if man.suffix == ".c":
            name = Path(rel_man).parent.name or Path(rel_man).stem
            kind = "media-demuxer"
            lang = "c/cpp"
        lab = _lab_for(lang, kind, name)
        components.append({
            "name": name,
            "path": key,
            "language": lang,
            "kind": kind,
            "manifest": rel_man,
            "dockerfile": docker,
            "fail_open": fail_open,
            "bind_all": bind_all,
            "binds": binds[:8],
            "unauth_mutating": routes[:12],
            "priority_sinks": [
                {
                    "method": s.get("method"),
                    "path": s.get("path"),
                    "primary_sink": s.get("primary_sink"),
                    "handler": s.get("handler"),
                }
                for s in sinks[:8]
            ],
            "config_fail_open": cfgs[:4],
            "lab": lab,
            "phase2_priority": bool(routes or fail_open or bind_all or sinks or kind == "media-demuxer"),
        })

    # Root-module files should not steal nested component routes.
    nested_prefixes = [c["path"] for c in components if c["path"] not in {".", dest.name, ""}]
    if nested_prefixes:
        for c in components:
            if c["path"] in {".", dest.name, ""}:
                def _not_nested(path: str) -> bool:
                    path = (path or "").replace("\\", "/")
                    return not any(path == p or path.startswith(p + "/") for p in nested_prefixes)
                c["unauth_mutating"] = [r for r in c["unauth_mutating"] if _not_nested(r.get("file") or "")]
                c["priority_sinks"] = [s for s in c["priority_sinks"] if _not_nested(s.get("path") or "")]
                c["phase2_priority"] = bool(
                    c["unauth_mutating"] or c["fail_open"] or c["bind_all"]
                    or c["priority_sinks"] or c["kind"] in ("media-demuxer", "queue-library")
                )

    # asynq: force a queue component even with no nested manifests.
    if (dest / "inspector.go").is_file() and not any(c["kind"] == "queue-library" for c in components):
        components.append({
            "name": dest.name,
            "path": ".",
            "language": "go",
            "kind": "queue-library",
            "manifest": "go.mod" if (dest / "go.mod").is_file() else "inspector.go",
            "dockerfile": "",
            "fail_open": True,
            "bind_all": False,
            "binds": [],
            "unauth_mutating": [],
            "priority_sinks": [{"method": "QUEUE", "path": "inspector.go", "primary_sink": "queue_admin", "handler": "NewInspector"}],
            "config_fail_open": [],
            "lab": _lab_for("go", "queue-library", dest.name),
            "phase2_priority": True,
        })

    components.sort(key=lambda c: (0 if c.get("phase2_priority") else 1, c.get("name") or ""))
    components = components[:24]

    findings: List[Dict[str, Any]] = []
    findings.append({
        "tool": "component-lab-map",
        "title": f"Component map: {len(components)} deployable TCBs",
        "cvss": 0.0,
        "description": (
            "Per-binary inventory for Phase 2. Nested Go/Rust control planes keep their "
            "own language, bind, auth-default, and lab recipe. See .lotus/component_map.json."
        ),
        "file": components[0]["path"] if components else "",
        "line": 1,
        "confidence": "high",
        "qualification": "INVENTORY",
        "phase2_hint": "component_lab",
        "record_type": "inventory-summary",
        "result_type": "inventory",
        "inventory_only": True,
        "inventory_artifact": ".lotus/component_map.json",
    })
    for c in components:
        if not c.get("phase2_priority"):
            continue
        n_mut = len(c.get("unauth_mutating") or [])
        n_sink = len(c.get("priority_sinks") or [])
        if n_mut == 0 and n_sink == 0 and c["kind"] not in ("media-demuxer", "queue-library") and not c.get("fail_open"):
            continue
        cvss = 9.1 if (c.get("fail_open") and c.get("bind_all")) else (
            8.6 if n_mut else (7.5 if n_sink or c["kind"] in ("media-demuxer", "queue-library") else 5.0)
        )
        findings.append({
            "tool": "component-lab-map",
            "title": (
                f"Component {c['name']} ({c['language']}/{c['kind']}) "
                f"{n_mut} unauth-mutating, lab={c['lab'].get('kind')}"
            ),
            "cvss": cvss,
            "description": (
                f"Path {c['path']}. fail_open={c.get('fail_open')} bind_all={c.get('bind_all')} "
                f"dockerfile={c.get('dockerfile') or 'none'}. Lab: {c['lab'].get('image')} "
                f"({c['lab'].get('kind')}). Phase 2 must PoC this binary, not the repo-level language."
            ),
            "file": c.get("manifest") or c["path"],
            "line": 1,
            "confidence": "high",
            "qualification": "QUALIFIED",
            "phase2_hint": "component_lab",
            "canonical_class": "authz_bypass",
            "component": c["name"],
            "lab_kind": c["lab"].get("kind"),
        })

    payload = {
        "language": language,
        "input_omissions": ([{"tool": "trust-boundary-map", **tb}] if tb.get("status") == "skipped" else [])
                           + ([{"tool": "handler-sink-trace", **hs}] if hs.get("status") == "skipped" else []),
        "components": components,
        "counts": {
            "components": len(components),
            "phase2_priority": sum(1 for c in components if c.get("phase2_priority")),
            "languages": sorted({c["language"] for c in components if c.get("language")}),
        },
    }
    try:
        out = dest / ".lotus"
        out.mkdir(exist_ok=True)
        (out / "component_map.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8",
        )
    except Exception:
        pass
    return findings, payload


def _run_component_lab_map(dest: Path, language: str) -> List[dict]:
    findings, _cm = collect_component_map(dest, language)
    return findings
