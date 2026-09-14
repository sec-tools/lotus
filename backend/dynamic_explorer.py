"""Dynamic path-exploration subsystem for Phase 1.

Goal: *exercise* code paths that parse untrusted data - not just pattern-match
them statically - and hand Phase 2 concrete artifacts (crashing/interesting
inputs, coverage, exercised-path intel) so PoC construction is far more
effective.

Design: a pluggable set of per-language **path-exploration engines** behind one
orchestrator (:func:`explore_paths`). Each engine:

  1. **discovers** functions that parse/deserialize untrusted data
     (entry points),
  2. **synthesizes** a coverage-guided harness that drives each entry point
     with fuzzed input (i.e. it *writes tests that exercise the parse paths*),
  3. **runs** the harness inside an isolated lab pod, and
  4. returns findings (crashes -> QUALIFIED, proven-in-lab) plus a
     *code-path-intel* artifact (coverage, corpus, reproducers) for Phase 2.

Engines and applicability:
  * **Go** (implemented here, fully): native ``go test -fuzz`` (coverage-guided,
    built into the toolchain we already containerize via ``golang`` image).
    Applies to Go targets (tailscale/authelia/casbin).
  * **Python** (implemented here, fully): **Atheris** (libFuzzer) in a ``python``
    pod - drives module-level parse/loads/decode/render/eval functions.
  * **Node.js** (implemented here, fully): **Jazzer.js** (libFuzzer + built-in
    command-injection / prototype-pollution / path-traversal bug detectors) in a
    ``node`` pod - drives exported single-arg parse/deserialize/render functions.
  * **C/C++**: KLEE symbolic-execution pod (see :func:`run_klee`) - LLVM-only,
    emits one concrete input per explored path + branch-reachability intel.
  * **Java**: a Jazzer (JVM) harness synthesizer is provided
    (:func:`synthesize_jazzer_harness`); its execution engine is staged. Node/
    Java/Ruby also get a grep **danger-sink map** for Phase-2 targeting.

Everything degrades gracefully: no Docker / wrong language -> empty result, the
audit is never blocked.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.async_process import terminate_and_reap

# Must match backend.ext_analyzers.GOLANG_IMAGE: fuzz harnesses for modern
# modules (Kubernetes-scale repos with a `toolchain` directive) fail to build on
# an old base, and with GOTOOLCHAIN=auto the correct toolchain is fetched into
# the shared cache. 1.22 silently produced 0/N compiling harnesses.
GOLANG_IMAGE = os.environ.get("LOTUS_GOLANG_IMAGE", "golang:1.25")
KLEE_IMAGE = os.environ.get("LOTUS_KLEE_IMAGE", "klee/klee:latest")
_GO_CACHE_VOLUME = os.environ.get("LOTUS_GO_CACHE_VOLUME", "lotus-go-cache")

# Per-harness fuzzing budget and how many entry points we drive per audit.
DEFAULT_FUZZTIME_S = int(os.environ.get("LOTUS_GO_FUZZTIME", "30"))
MAX_HARNESSES = int(os.environ.get("LOTUS_MAX_HARNESSES", "8"))


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _container_runtime_args(repo_id: int = 0, *, mutable_root: bool = False,
                              klee: bool = False) -> List[str]:
    """Return the centrally-defined containment flags for analyzer pods.

    Dynamic exploration used to assemble ``docker run`` commands independently
    from the main lab launcher.  That made fuzzers and symbolic execution an
    escape hatch: a future engine could accidentally run as root without
    resource limits or ``no-new-privileges``.  Keep the policy in
    :mod:`backend.lab` and apply it to every engine.  Cache-build containers
    need a writable image root, so they retain the limits/cap-drop policy but
    explicitly omit only ``--read-only``.

    ``klee=True`` is a special case: the official ``klee/klee`` image installs
    the whole LLVM/Clang toolchain under ``/tmp``.  Mounting a tmpfs over
    ``/tmp`` would hide the compiler, and ``--read-only`` prevents KLEE from
    writing ``klee-out-*`` to the source mount.  We therefore drop ``--read-only``
    and the ``/tmp``/``/run`` tmpfs mounts, while keeping the rest of the
    containment policy.  KLEE still runs as a non-root user and can only write
    to the bound ``/src`` and the image's own ``/tmp``.
    """
    try:
        from backend.lab import hardened_runtime_args
        args = list(hardened_runtime_args(repo_id if repo_id else None))
    except Exception:
        # Never turn an import failure into an unconfined analyzer.  Keep a
        # conservative static policy for standalone/packaging contexts.
        args = ["--memory", "4g", "--cpus", "2", "--pids-limit", "512",
                "--read-only", "--cap-drop=ALL", "--security-opt",
                "no-new-privileges:true", "--user", "65532:65532",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
                "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=32m"]
    if mutable_root or klee:
        try:
            args.remove("--read-only")
        except ValueError:
            pass
    if klee:
        # Remove tmpfs mounts that would shadow the image's /tmp toolchain.
        # Filter both the "--tmpfs" flag and the value that follows it.
        filtered, i = [], 0
        while i < len(args):
            if args[i] == "--tmpfs" and i + 1 < len(args):
                if args[i + 1].startswith("/tmp:") or args[i + 1].startswith("/run:"):
                    i += 2
                    continue
            filtered.append(args[i])
            i += 1
        args = filtered
    return args


# ---------------------------------------------------------------------------
# Persistent fuzz corpus (coverage carries over between audits)
# ---------------------------------------------------------------------------
# libFuzzer names corpus entries by content hash, so a persistent seed corpus lets
# a later run resume from the coverage a previous run discovered instead of cold-
# starting - materially deeper paths on repeat audits of the same repo. Reproducers
# (crash-*) are never treated as corpus.
PERSIST_CORPUS = str(os.environ.get("LOTUS_FUZZ_PERSIST_CORPUS", "1")).lower() in ("1", "true", "yes")
_CORPUS_CAP = int(os.environ.get("LOTUS_FUZZ_CORPUS_CAP", "5000"))


def _sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s))[:120] or "_"


def _corpus_store() -> Path:
    return Path(os.environ.get("LOTUS_DATA_DIR", "./data")) / "fuzz_corpus"


def persistent_corpus_dir(repo_id: int, engine: str, target_key: str) -> Path:
    """Host-side directory that persists a target's corpus across audits."""
    d = _corpus_store() / _sanitize(repo_id) / _sanitize(engine) / _sanitize(target_key)
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d


def seed_corpus(persist_dir: Optional[Path], run_dir: Path, cap: int = _CORPUS_CAP) -> int:
    """Copy persisted seeds into the pod-visible run corpus dir. Returns count."""
    n = 0
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return 0
    if not persist_dir:
        return 0
    try:
        for f in sorted(persist_dir.glob("*")):
            if n >= cap:
                break
            if f.is_file():
                try:
                    (run_dir / f.name).write_bytes(f.read_bytes())
                    n += 1
                except Exception:
                    pass
    except Exception:
        pass
    return n


def harvest_corpus(run_dir: Path, persist_dir: Optional[Path], cap: int = _CORPUS_CAP) -> int:
    """Copy newly-discovered corpus entries back to the persistent store (deduped by
    content-hash filename; crash reproducers are excluded). Returns new-entry count."""
    if not persist_dir:
        return 0
    n = 0
    try:
        persist_dir.mkdir(parents=True, exist_ok=True)
        existing = {p.name for p in persist_dir.glob("*") if p.is_file()}
        for f in sorted(run_dir.glob("*"), key=lambda p: -p.stat().st_mtime):
            if not f.is_file() or f.name.startswith("crash-"):
                continue
            if f.name in existing:
                continue
            if len(existing) + n >= cap:
                break
            try:
                (persist_dir / f.name).write_bytes(f.read_bytes())
                n += 1
            except Exception:
                pass
    except Exception:
        pass
    return n


# ---------------------------------------------------------------------------
# Per-repo image cache (skip the heavy per-harness install - clang+atheris+deps
# for Python, maven/gradle deps + Jazzer for the JVM - by baking it into a
# per-repo image once, reused across harnesses and later audits). Bounded by an
# LRU-by-creation eviction policy so cache images do not grow without limit.
# ---------------------------------------------------------------------------
ATHERIS_CACHE = str(os.environ.get("LOTUS_ATHERIS_CACHE", "1")).lower() in ("1", "true", "yes")
# Bounded number of per-repo cache images kept per cache repository (oldest evicted).
CACHE_MAX_IMAGES = max(1, int(os.environ.get("LOTUS_ATHERIS_CACHE_MAX", "8") or 8))
_ATHERIS_CACHE_REPO = "lotus-atheris-cache"
_JVM_CACHE_REPO = "lotus-jvm-cache"


def _repo_cache_key(repo_id: int, dest: Path) -> str:
    """Stable short key for a repo's cache artifacts (docker-tag safe)."""
    import hashlib
    raw = f"{repo_id}:{Path(dest).name}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _atheris_cache_tag(repo_id: int, dest: Path) -> str:
    """Per-repo Atheris image tag (lowercase, docker-tag safe)."""
    return f"{_ATHERIS_CACHE_REPO}:{_repo_cache_key(repo_id, dest)}"


def _jvm_cache_tag(repo_id: int, dest: Path) -> str:
    """Per-repo JVM (Jazzer) image tag (lowercase, docker-tag safe)."""
    return f"{_JVM_CACHE_REPO}:{_repo_cache_key(repo_id, dest)}"


def _images_to_evict(images: List[Tuple[str, float]], max_keep: int,
                     keep_tag: Optional[str] = None) -> List[str]:
    """Pure LRU-by-creation decision: given ``(tag, created_epoch)`` pairs, return the
    tags to remove so at most ``max_keep`` remain (oldest first). ``keep_tag`` is never
    evicted (the image we just built/used). Unit-tested; no Docker involved."""
    if max_keep < 1:
        max_keep = 1
    # Newest first; a freshly-(re)built keep_tag is always retained.
    ordered = sorted(images, key=lambda t: t[1], reverse=True)
    keep: List[str] = []
    evict: List[str] = []
    for tag, _ts in ordered:
        if keep_tag and tag == keep_tag:
            if tag not in keep:
                keep.insert(0, tag)
            continue
        if len(keep) < max_keep:
            keep.append(tag)
        else:
            evict.append(tag)
    # If keep_tag pushed us over, drop the oldest kept (never keep_tag).
    while len(keep) > max_keep:
        victim = keep.pop()  # oldest non-keep tag is at the end
        if victim == keep_tag:  # pragma: no cover - defensive
            keep.append(victim)
            break
        evict.append(victim)
    return evict


async def _image_exists(tag: str) -> bool:
    o, _ = await _run(["docker", "images", "-q", tag], 20)
    return bool(o.strip())


async def _prune_cache_images(repo: str, max_keep: int, keep_tag: Optional[str] = None) -> int:
    """Evict oldest ``repo:*`` cache images beyond ``max_keep``. Best-effort; returns
    the number removed. Never raises."""
    try:
        out, _ = await _run(
            ["docker", "images", repo, "--format", "{{.Tag}}\t{{.CreatedAt}}"], 30)
        images: List[Tuple[str, float]] = []
        for line in (out or "").splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or parts[0] in ("<none>", ""):
                continue
            tag = f"{repo}:{parts[0].strip()}"
            # Docker CreatedAt like "2026-08-26 12:00:00 -0700 PDT"; parse best-effort.
            ts = 0.0
            try:
                import datetime as _dt
                head = " ".join(parts[1].split()[:3])  # date time tz
                ts = _dt.datetime.strptime(head, "%Y-%m-%d %H:%M:%S %z").timestamp()
            except Exception:
                pass
            images.append((tag, ts))
        victims = _images_to_evict(images, max_keep, keep_tag=keep_tag)
        removed = 0
        for tag in victims:
            _o, _e = await _run(["docker", "rmi", "-f", tag], 60)
            removed += 1
        return removed
    except Exception:
        return 0


async def _build_cache_image(dest: Path, tag: str, install_cmd: str, base_image: str,
                             commit_env: List[str], platform: Optional[str] = None,
                             repo_id: int = 0) -> bool:
    """Run the heavy install once in a throwaway container and commit it to ``tag``.
    ``commit_env`` is a list of ``KEY=VALUE`` strings baked into the image. ``platform``
    (e.g. ``linux/amd64``) pins the build arch when the payload ships a native binary for
    one arch only (Jazzer). Returns True on success. Never raises - caller falls back to
    per-run install."""
    name = "lotus-cache-build-" + tag.replace(":", "-").replace("/", "-")
    plat = ["--platform", platform] if platform else []
    try:
        await _run(["docker", "rm", "-f", name], 30)  # fresh build container (no --rm: must commit)
        build = ["docker", "run", "--name", name] + _container_runtime_args(
            repo_id, mutable_root=True) + plat + ["-v", f"{dest}:/src", "-w", "/src",
                 "--network", "bridge", base_image, "bash", "-c",
                 install_cmd + " echo __CACHE_BUILD_DONE__"]
        out, _ = await _run(build, timeout=1800)
        if "__CACHE_BUILD_DONE__" not in (out or ""):
            await _run(["docker", "rm", "-f", name], 30)
            return False
        commit = ["docker", "commit"]
        for kv in commit_env:
            commit += ["-c", f"ENV {kv}"]
        commit += [name, tag]
        co, _ = await _run(commit, timeout=300)
        await _run(["docker", "rm", "-f", name], 30)
        return bool(co is not None) and await _image_exists(tag)
    except Exception:
        try:
            await _run(["docker", "rm", "-f", name], 30)
        except Exception:
            pass
        return False


async def _build_atheris_cache(dest: Path, tag: str, install_cmd: str,
                               repo_id: int = 0) -> bool:
    """Bake the atheris + clang + target-deps install into ``tag`` (see _build_cache_image)."""
    return await _build_cache_image(
        dest, tag, install_cmd, ATHERIS_IMAGE,
        commit_env=["CLANG_BIN=/usr/bin/clang", "PYTHONPATH=/src:/src/src"],
        repo_id=repo_id)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ParseEntryPoint:
    """A function that ingests untrusted data and is a candidate for fuzzing."""
    language: str
    file: str            # repo-relative
    line: int
    package: str         # Go package name (or module/class for other langs)
    symbol: str          # function name
    input_kind: str      # 'bytes' | 'string' | 'reader'
    signature: str       # raw declaration text
    role: str            # 'unmarshal'|'parse'|'decode'|'load'|'compile'|'read'|'new'|'generic'
    confidence: str = "medium"

    def key(self) -> str:
        return f"{self.file}:{self.symbol}"


@dataclass
class Harness:
    """A synthesized coverage-guided harness targeting one entry point."""
    language: str
    entry: ParseEntryPoint
    pkg_dir: str         # repo-relative dir the harness file is written into
    filename: str
    source: str
    fuzz_func: str       # e.g. FuzzLotus_Parse


@dataclass
class ExplorationResult:
    language: str
    engine: str
    entrypoints: List[ParseEntryPoint] = field(default_factory=list)
    harnesses: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    coverage: List[Dict[str, Any]] = field(default_factory=list)   # per-package coverage
    artifacts: List[Dict[str, Any]] = field(default_factory=list)  # reproducers / corpus
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "language": self.language,
            "entrypoints": [asdict(e) for e in self.entrypoints],
            "harnesses": self.harnesses,
            "coverage": self.coverage,
            "artifacts": self.artifacts,
            "stats": self.stats,
        }


# ===========================================================================
# GO ENGINE
# ===========================================================================
_GO_ROLE_PATTERNS = [
    ("unmarshal", re.compile(r"unmarshal", re.I)),
    ("decode", re.compile(r"decode", re.I)),
    ("parse", re.compile(r"parse", re.I)),
    ("compile", re.compile(r"compile", re.I)),
    ("load", re.compile(r"\bload|fromstring|fromtext|fromfile", re.I)),
    ("read", re.compile(r"^read|readall|readfrom", re.I)),
    ("new", re.compile(r"^new\w", re.I)),
]

# Single-parameter signatures we can synthesize a harness for. Group 1 = func
# name, group 2 = (optional) param name, group 3 = type.
_GO_FUNC_RE = re.compile(
    r"^func\s+(?P<name>[A-Z]\w*)\s*\(\s*"
    r"(?:(?P<pname>\w+)\s+)?(?P<ptype>\[\]byte|string|io\.Reader)\s*\)"
    r"(?P<rest>[^{]*)\{",
    re.M,
)

_INPUT_KIND = {"[]byte": "bytes", "string": "string", "io.Reader": "reader"}


def _go_package_name(text: str) -> str:
    m = re.search(r"^package\s+(\w+)", text, re.M)
    return m.group(1) if m else ""


def _classify_role(name: str) -> str:
    for role, pat in _GO_ROLE_PATTERNS:
        if pat.search(name):
            return role
    return "generic"


def discover_go_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find exported, single-argument Go functions that ingest untrusted data.

    We restrict to a single ``[]byte`` / ``string`` / ``io.Reader`` parameter
    because those can be driven by the fuzzer without fabricating other typed
    arguments - and they are exactly the shape of real parse/unmarshal/decode
    entry points (e.g. casbin ``NewModelFromString(text string)``).
    """
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    for go in dest.rglob("*.go"):
        parts = {p.lower() for p in go.parts}
        if parts & {"vendor", "testdata", ".git", "node_modules"}:
            continue
        if go.name.endswith("_test.go"):
            continue
        try:
            text = go.read_text(errors="ignore")
        except Exception:
            continue
        pkg = _go_package_name(text)
        if not pkg:
            continue
        rel = str(go.relative_to(dest))
        # Precompute line offsets for line numbers.
        for m in _GO_FUNC_RE.finditer(text):
            name = m.group("name")
            ptype = m.group("ptype")
            role = _classify_role(name)
            # Skip obviously-not-parsing exported helpers (String, Error, ...).
            if name in ("String", "Error", "GoString", "MarshalJSON"):
                continue
            line = text.count("\n", 0, m.start()) + 1
            sig = m.group(0)[:-1].strip()
            # Confidence: parse-like name + bytes/reader input is the strongest.
            conf = "medium"
            if role in ("unmarshal", "decode", "parse", "compile", "load") and ptype in ("[]byte", "io.Reader"):
                conf = "high"
            elif role in ("unmarshal", "decode", "parse", "compile", "load"):
                conf = "high"
            elif role == "generic":
                conf = "low"
            ep = ParseEntryPoint(
                language="go", file=rel, line=line, package=pkg, symbol=name,
                input_kind=_INPUT_KIND[ptype], signature=sig, role=role, confidence=conf,
            )
            if ep.key() in seen:
                continue
            seen.add(ep.key())
            out.append(ep)
    # Rank: high confidence + parse-like roles first; then bytes/reader over string.
    role_rank = {"unmarshal": 0, "decode": 1, "parse": 2, "compile": 3, "load": 4,
                 "read": 5, "new": 6, "generic": 7}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    kind_rank = {"bytes": 0, "reader": 1, "string": 2}
    out.sort(key=lambda e: (conf_rank[e.confidence], role_rank.get(e.role, 9), kind_rank[e.input_kind]))
    return out


def synthesize_go_fuzz_harness(ep: ParseEntryPoint) -> Harness:
    """Generate a native Go fuzz harness (``FuzzXxx``) for one entry point.

    The harness is written into the target's own package directory as an
    internal ``_test.go`` file, so it can call the target directly (exported or
    not) with no import cycle. Return values are intentionally ignored (a bare
    call statement is legal Go); a panic inside the parser is what the fuzzer
    surfaces as a crash.
    """
    fuzz_func = f"FuzzLotus_{ep.symbol}"
    imports = ["testing"]
    if ep.input_kind == "reader":
        imports.insert(0, "bytes")

    if ep.input_kind == "bytes":
        seed = 'f.Add([]byte("{}"))\n\tf.Add([]byte(""))'
        body = f"{ep.symbol}(data)"
        fuzz_arg = "data []byte"
    elif ep.input_kind == "string":
        seed = 'f.Add("")\n\tf.Add("0")'
        body = f"{ep.symbol}(s)"
        fuzz_arg = "s string"
    else:  # reader
        seed = 'f.Add([]byte(""))'
        body = f"{ep.symbol}(bytes.NewReader(data))"
        fuzz_arg = "data []byte"

    import_block = "\n".join(f'\t"{i}"' for i in imports)
    source = (
        f"package {ep.package}\n\n"
        f"// Code generated by Lotus dynamic_explorer. DO NOT EDIT.\n"
        f"// Coverage-guided harness exercising untrusted-data parse path {ep.symbol}.\n\n"
        f"import (\n{import_block}\n)\n\n"
        f"func {fuzz_func}(f *testing.F) {{\n"
        f"\t{seed}\n"
        f"\tf.Fuzz(func(t *testing.T, {fuzz_arg}) {{\n"
        f"\t\t{body}\n"
        f"\t}})\n"
        f"}}\n"
    )
    pkg_dir = str(Path(ep.file).parent)
    filename = f"lotus_fuzz_{ep.symbol.lower()}_test.go"
    return Harness(language="go", entry=ep, pkg_dir=pkg_dir, filename=filename,
                   source=source, fuzz_func=fuzz_func)


# --- output parsers (pure, unit-tested offline) ---------------------------
def parse_go_fuzz_output(out: str) -> Dict[str, Any]:
    """Extract crash signal + reproducer path + panic summary from go-test output."""
    out = out or ""
    crashed = bool(re.search(r"^--- FAIL", out, re.M)) or "panic:" in out or \
        "Failing input written to" in out
    repro = None
    m = re.search(r"Failing input written to (\S+)", out)
    if m:
        repro = m.group(1).rstrip(".")
    # Panic / failure headline.
    headline = ""
    pm = re.search(r"panic:\s*(.+)", out)
    if pm:
        headline = pm.group(1).strip()[:200]
    else:
        fm = re.search(r"^\s*(fuzzing process hung|test timed out|.*runtime error:.*)$", out, re.M)
        if fm:
            headline = fm.group(1).strip()[:200]
    # Execs (rough).
    execs = 0
    em = re.findall(r"execs:\s*(\d+)", out)
    if em:
        try:
            execs = int(em[-1])
        except ValueError:
            execs = 0
    return {"crashed": crashed, "repro_path": repro, "headline": headline, "execs": execs}


def parse_cover_func(out: str) -> Dict[str, Any]:
    """Parse `go tool cover -func` output into total% + per-func lines."""
    out = out or ""
    total = 0.0
    funcs: List[Dict[str, Any]] = []
    for line in out.splitlines():
        mt = re.match(r"total:\s+\(statements\)\s+([\d.]+)%", line.strip())
        if mt:
            total = float(mt.group(1))
            continue
        mf = re.match(r"(\S+):(\d+):\s+(\S+)\s+([\d.]+)%", line.strip())
        if mf:
            funcs.append({
                "file": mf.group(1), "line": int(mf.group(2)),
                "func": mf.group(3), "coverage_pct": float(mf.group(4)),
            })
    return {"total_pct": total, "funcs": funcs}


def _classify_go_crash(headline: str) -> Tuple[float, str, str]:
    """Map a Go panic headline to (cvss, class, note). Deprioritise pure DoS."""
    h = (headline or "").lower()
    if "index out of range" in h or "slice bounds out of range" in h:
        return 6.5, "oob_index", "Out-of-bounds slice/index on untrusted input (memory-safety-adjacent; check for info leak)."
    if "nil pointer" in h or "invalid memory address" in h:
        return 5.5, "nil_deref", "Nil dereference reachable from untrusted input (robustness; DoS unless upgraded)."
    if "integer divide by zero" in h:
        return 5.0, "div_zero", "Divide-by-zero reachable from untrusted input."
    if "stack overflow" in h or "goroutine stack exceeds" in h:
        return 5.5, "stack_overflow", "Unbounded recursion on untrusted input (DoS)."
    if "makeslice: len out of range" in h or "out of memory" in h:
        return 5.5, "alloc_dos", "Attacker-controlled allocation size (DoS; check for downstream overflow)."
    if "timed out" in h or "hung" in h:
        return 4.0, "hang", "Parser hang / non-termination on crafted input (DoS)."
    return 6.0, "panic", "Unhandled panic reachable from untrusted input."


def _extract_go_build_error(out: str) -> str:
    """Return a concise Go build/compile error from fuzz output, if present.

    ``go test -fuzz`` exits 1 both for a real crash *and* for a build failure, so
    the generic "no crash oracle" reason hid the actual cause (out-of-space,
    toolchain-download failure, an undefined symbol in a generated harness, etc.).
    Surfacing the first meaningful compiler/build line makes the failure
    actionable instead of looking like a clean "no crash" result.
    """
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    # Disk exhaustion is the highest-priority signal: report it verbatim.
    for ln in lines:
        if "no space left on device" in ln.lower():
            return ln[:200]
    for ln in lines:
        low = ln.lower()
        if re.search(r"\.go:\d+:\d+:", ln) or any(s in low for s in (
            "cannot find package", "no required module provides package",
            "undefined:", "build constraints exclude all go files",
            "syntax error", "cannot load", "go: downloading", "go: error",
            "go: cannot", "toolchain", "permission denied", "out of memory",
        )):
            return ln[:200]
    # A Go compiler error block starts with "# <package>" then the detail line.
    for i, ln in enumerate(lines):
        if ln.startswith("# ") and i + 1 < len(lines):
            return f"{ln} | {lines[i + 1]}"[:200]
    return ""


async def _run(cmd: List[str], timeout: int) -> Tuple[str, int]:
    try:
        try:
            from backend.lab import _controlled_child_env
            child_env = _controlled_child_env()
        except Exception:
            child_env = None
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=child_env,
        )
        out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out_b.decode(errors="ignore"), proc.returncode or 0
    except asyncio.CancelledError:
        await terminate_and_reap(locals().get("proc"))
        raise
    except asyncio.TimeoutError:
        await terminate_and_reap(locals().get("proc"))
        return f"__timeout__ after {timeout}s", -1
    except Exception as e:  # pragma: no cover
        await terminate_and_reap(locals().get("proc"))
        return f"__error__ {e}", -1


def _go_docker_cmd(dest: Path, script: str, repo_id: int = 0) -> List[str]:
    return [
        "docker", "run", "--rm", *_container_runtime_args(repo_id),
        "-v", f"{dest}:/src", "-w", "/src",
        "-v", f"{_GO_CACHE_VOLUME}:/go", "--network", "bridge",
        "-e", "GOFLAGS=-buildvcs=false",
        "-e", "GOMODCACHE=/go/pkg/mod", "-e", "GOCACHE=/go/cache",
        # Auto-fetch the module's required toolchain (cached in /go) so modern
        # repos build; without this a stale base image failed every harness.
        "-e", "GOTOOLCHAIN=auto",
        # Non-login shell: a login shell (-l) sources /etc/profile which resets
        # PATH and drops /usr/local/go/bin, breaking `go`. Prepend it defensively.
        # GOTMPDIR/TMPDIR are pinned to the disk-backed /go volume because the
        # hardened runtime mounts /tmp as a small RAM tmpfs, which otherwise made
        # `go test -fuzz` builds fail with "no space left on device".
        GOLANG_IMAGE, "bash", "-c",
        ('export PATH="$PATH:/usr/local/go/bin"; export GOPATH=/go HOME=/tmp; '
         'mkdir -p /go/gotmp; export GOTMPDIR=/go/gotmp TMPDIR=/go/gotmp; ') + script,
    ]


async def run_go_fuzz(
    dest: Path,
    harnesses: List[Harness],
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    send=None,
    repo_id: int = 0,
) -> ExplorationResult:
    """Write harnesses, run coverage-guided ``go test -fuzz`` per entry point in
    the golang pod, and collect crashes + coverage + reproducers.
    """
    result = ExplorationResult(language="go", engine="go-native-fuzz")
    dest = Path(dest)
    if not (dest / "go.mod").exists():
        result.stats = {"status": "skipped", "reason": "no go.mod"}
        return result
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no go entrypoints"}
        return result
    # Kubernetes-first: when Kubernetes is the selected runtime, run `go test
    # -fuzz` in a Job with a shared go-module-cache PVC (see backend.k8s_dynamic).
    # Docker is used only when explicitly selected.
    if harnesses:
        from backend.k8s_runtime import use_k8s_runtime
        _use_k8s = await use_k8s_runtime(repo_id)
        if _use_k8s:
            from backend import k8s_dynamic
            return await k8s_dynamic.run_go_k8s(dest, harnesses, fuzztime_s,
                                                send=send, repo_id=repo_id)
    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", GOLANG_IMAGE], 20)
        return bool(o.strip())
    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/image unavailable"}
        return result

    written: List[Path] = []
    for h in harnesses:
        pkg_dir = dest / h.pkg_dir
        try:
            pkg_dir.mkdir(parents=True, exist_ok=True)
            hp = pkg_dir / h.filename
            hp.write_text(h.source)
            written.append(hp)
            result.harnesses.append({
                "target": h.entry.key(), "fuzz_func": h.fuzz_func,
                "pkg_dir": h.pkg_dir, "file": h.filename, "input_kind": h.entry.input_kind,
            })
        except Exception as e:  # pragma: no cover
            result.stats.setdefault("write_errors", []).append(f"{h.filename}: {e}")

    crashes = 0
    harness_failures: List[Dict[str, Any]] = []
    inconclusive: List[Dict[str, Any]] = []
    for h in harnesses:
        relpkg = "./" + h.pkg_dir if h.pkg_dir != "." else "."
        cov_file = f"/src/.lotus_cover_{h.fuzz_func}.out"
        if send:
            await send(repo_id, f"▶ Fuzzing parse path {h.entry.symbol} ({h.entry.input_kind}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-gofuzz")
        # Fuzz, then a coverage pass over the (seed+generated) corpus.
        # Preserve both inner return codes.  The old ``; rm`` tail forced the
        # outer Docker command to return zero, turning compilation errors and
        # immediately-exiting harnesses into a green "no crash" result.
        script = (
            f"cd /src; set +e; "
            f"go test -run='^$' -fuzz='^{h.fuzz_func}$' -fuzztime={fuzztime_s}s {relpkg} 2>&1; "
            f"fuzz_rc=$?; printf '\\n__FUZZ_RC__=%s\\n' \"$fuzz_rc\"; "
            f"go test -run='^{h.fuzz_func}$' -coverprofile={cov_file} {relpkg} 2>&1; "
            f"cover_rc=$?; printf '\\n__COVER_RC__=%s\\n' \"$cover_rc\"; "
            f"if [ \"$cover_rc\" -eq 0 ] && [ -f {cov_file} ]; then go tool cover -func={cov_file} 2>&1 | tail -40; fi; "
            f"rm -f {cov_file}; exit 0"
        )
        out, outer_rc = await _run(_go_docker_cmd(dest, script, repo_id), timeout=fuzztime_s + 180)
        if await _emit_go_result(result, h, out=out, outer_rc=outer_rc, fuzztime_s=fuzztime_s,
                                 harness_failures=harness_failures, inconclusive=inconclusive,
                                 repro_provider=lambda h=h: _read_go_repro(dest, h),
                                 send=send, repo_id=repo_id):
            crashes += 1

    # Clean up generated harnesses so we don't mutate the repo state for later phases.
    for hp in written:
        try:
            hp.unlink()
        except Exception:
            pass

    result.stats = {
        "status": "failed" if harness_failures else ("inconclusive" if inconclusive else "completed"),
        "harnesses_run": len(harnesses),
        "crashes": crashes, "fuzztime_s": fuzztime_s,
        "harness_failures": harness_failures,
        "inconclusive": inconclusive,
    }
    return result


def _read_go_repro(dest: Path, h: Harness) -> Optional[str]:
    """Read the newest reproducer file Go wrote under testdata/fuzz/<Fuzz>/."""
    d = dest / h.pkg_dir / "testdata" / "fuzz" / h.fuzz_func
    try:
        files = sorted([p for p in d.iterdir() if p.is_file()], key=lambda p: -p.stat().st_mtime)
        if files:
            return base64.b64encode(files[0].read_bytes()).decode()
    except Exception:
        pass
    return None


def _split_go_output(out: str) -> Tuple[str, str, Optional[int], Optional[int]]:
    """Split combined ``go test -fuzz`` + coverage output on the RC markers the
    run script emits into ``(fuzz_part, cover_part, fuzz_rc, cover_rc)``. Shared
    by the Docker and Kubernetes runtimes (both frame the two inner return codes
    so a trailing cleanup command can never mask a failed harness)."""
    out = out or ""
    fm = re.search(r"__FUZZ_RC__=(-?\d+)", out)
    cm = re.search(r"__COVER_RC__=(-?\d+)", out)
    fuzz_rc = int(fm.group(1)) if fm else None
    cover_rc = int(cm.group(1)) if cm else None
    fuzz_part = out.split("__FUZZ_RC__=", 1)[0]
    cover_part = out.split("__COVER_RC__=", 1)[-1] if "__COVER_RC__=" in out else ""
    return fuzz_part, cover_part, fuzz_rc, cover_rc


async def _emit_go_result(result: "ExplorationResult", h: "Harness", *, out: str,
                          outer_rc: int, fuzztime_s: int,
                          harness_failures: List[Dict[str, Any]],
                          inconclusive: List[Dict[str, Any]],
                          repro_provider: Callable[[], Optional[str]],
                          send=None, repo_id: int = 0) -> bool:
    """Per-harness Go crash/coverage/failure doctrine shared by the Docker and
    Kubernetes runtimes.

    Appends coverage + any crash finding to ``result`` and records
    build/setup failures and inconclusive (unproven-coverage) harnesses in the
    supplied lists, then emits the operator-facing status line. Returns True iff
    a validated crash was recorded. ``repro_provider`` reads the reproducer only
    when a crash occurred (from disk under Docker, from the harvested tar under
    k8s)."""
    relpkg = "./" + h.pkg_dir if h.pkg_dir != "." else "."
    fuzz_part, cover_part, fuzz_rc, cover_rc = _split_go_output(out)
    parsed = parse_go_fuzz_output(fuzz_part)
    cover = parse_cover_func(cover_part)
    if cover.get("total_pct") or cover.get("funcs"):
        result.coverage.append({
            "package": h.pkg_dir, "fuzz_func": h.fuzz_func,
            "total_pct": cover["total_pct"],
            "top_funcs": sorted(cover["funcs"], key=lambda f: -f["coverage_pct"])[:10],
        })

    harness_key = {"target": h.entry.key(), "fuzz_func": h.fuzz_func, "package": h.pkg_dir}
    if outer_rc != 0 or fuzz_rc is None:
        harness_failures.append({
            **harness_key,
            "reason": "fuzz container did not emit a valid return-code marker",
            "outer_return_code": outer_rc,
            "output": out[-1200:],
        })
    elif fuzz_rc != 0 and not parsed["crashed"]:
        build_err = _extract_go_build_error(fuzz_part)
        reason = (
            f"fuzz build/setup failed: {build_err}" if build_err
            else f"fuzz command exited {fuzz_rc} without a validated crash oracle"
        )
        harness_failures.append({
            **harness_key,
            "reason": reason,
            "fuzz_return_code": fuzz_rc,
            "build_error": build_err,
            "output": fuzz_part[-1200:],
        })
    # A validated crash is itself proof of execution: the coverage pass fails
    # only because re-running the corpus re-triggers the captured reproducer, so
    # a crashed harness must not also be labelled inconclusive (unproven).
    if not parsed["crashed"]:
        if cover_rc is None or cover_rc != 0:
            inconclusive.append({
                **harness_key,
                "reason": "coverage test failed or did not report a return code",
                "coverage_return_code": cover_rc,
                "output": cover_part[-1200:],
            })
        elif not (cover.get("total_pct") or cover.get("funcs")):
            inconclusive.append({
                **harness_key,
                "reason": "coverage profile was empty; harness execution is unproven",
                "coverage_return_code": cover_rc,
                "output": cover_part[-1200:],
            })

    if parsed["crashed"]:
        cvss, cls, note = _classify_go_crash(parsed["headline"])
        repro_b64 = repro_provider()
        result.findings.append({
            "tool": "go-fuzz",
            "title": f"Coverage-guided crash in {h.entry.symbol}: {cls}",
            "cvss": cvss,
            "description": (
                f"Native Go fuzzing drove untrusted input into {h.entry.package}.{h.entry.symbol} "
                f"({h.entry.signature}) and reached a crash: {parsed['headline'] or cls}. {note} "
                f"A reproducing input was captured; replay with the generated harness "
                f"{h.pkg_dir}/{h.filename} via `go test -run={h.fuzz_func}/<id>`."
            ),
            "file": h.entry.file,
            "line": h.entry.line,
            "confidence": "high",
            "discovery_technique": "coverage-guided-fuzz",
            "qualification": "QUALIFIED",
            "conviction_level": 2,
            "proven_in_lab": True,
            "lab_evidence": [{
                "path": "go-fuzz",
                "params": {"fuzz_func": h.fuzz_func, "target": h.entry.key()},
                "snippet": (parsed["headline"] or "")[:200],
                "anomaly_type": cls,
                "method": "fuzz",
            }],
            "poc": {"command": f"go test -run='{h.fuzz_func}' {relpkg}", "harness": h.filename},
            "poc_result": "triggered",
        })
        if repro_b64:
            result.artifacts.append({
                "type": "reproducer", "target": h.entry.key(),
                "fuzz_func": h.fuzz_func, "encoding": "base64", "data": repro_b64,
            })
        if send:
            await send(repo_id, f"✗ CRASH in {h.entry.symbol}: {cls} ({parsed['headline'][:80]})",
                       level="warning", detail_id=f"{repo_id}-task-gofuzz")
        return True

    if harness_failures and harness_failures[-1].get("fuzz_func") == h.fuzz_func:
        if send:
            await send(repo_id, f"✗ {h.entry.symbol}: fuzz harness failed — {harness_failures[-1]['reason']}",
                       level="warning", detail_id=f"{repo_id}-task-gofuzz")
    elif inconclusive and inconclusive[-1].get("fuzz_func") == h.fuzz_func:
        if send:
            await send(repo_id, f"⊘ {h.entry.symbol}: fuzz result inconclusive — {inconclusive[-1]['reason']}",
                       level="warning", detail_id=f"{repo_id}-task-gofuzz")
    elif send:
        cov_pct = result.coverage[-1]["total_pct"] if result.coverage and result.coverage[-1]["fuzz_func"] == h.fuzz_func else 0.0
        await send(repo_id, f"✓ {h.entry.symbol}: no crash; exercised {cov_pct:.0f}% of package stmts",
                   detail_id=f"{repo_id}-task-gofuzz")
    return False


# ===========================================================================
# C/C++ KLEE ENGINE (LLVM-only) - implemented; proven separately on C targets
# ===========================================================================
async def run_klee(
    dest: Path,
    target_c_rel: str,
    entry_func: str = "main",
    max_time_s: int = 120,
    send=None,
    repo_id: int = 0,
    driver_source: Optional[str] = None,
) -> ExplorationResult:
    """Symbolically execute a C/C++ translation unit with KLEE in a pod.

    Compiles ``target_c_rel`` to LLVM bitcode (clang -emit-llvm) and runs KLEE,
    which explores feasible paths and emits one concrete input (``.ktest``) per
    path plus branch statistics. Returns coverage/path intel + any error-class
    paths (memory errors, asserts) as findings. LLVM/C-only.

    When ``driver_source`` is given (a synthesized KLEE driver that marks input
    symbolic and calls a library function), it is written to ``/tmp`` and
    compiled instead - ``-I /src`` lets its ``#include "<repo-rel target>"``
    resolve against the mounted source. ``target_c_rel`` stays the reported file.
    """
    result = ExplorationResult(language="c/cpp", engine="klee")
    dest = Path(dest)

    # Kubernetes-first: when Kubernetes is the selected runtime, run the
    # compile+KLEE pass in a Job (see backend.k8s_dynamic.run_klee_k8s). Docker
    # stays the break-glass on hosts without a cluster.
    from backend.k8s_runtime import use_k8s_runtime
    _use_k8s = await use_k8s_runtime(repo_id)
    if _use_k8s:
        from backend import k8s_dynamic
        return await k8s_dynamic.run_klee_k8s(dest, target_c_rel, entry_func,
                                              max_time_s, send=send, repo_id=repo_id,
                                              driver_source=driver_source)

    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", KLEE_IMAGE], 20)
        return bool(o.strip())
    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/klee image unavailable"}
        return result
    # The KLEE image installs LLVM/Clang under /tmp and KLEE under
    # /home/klee/klee_build/bin. Those paths are in the root user's dotfiles,
    # but the hardened non-root container user does not inherit them, so set
    # PATH explicitly.
    _klee_path = (
        "/home/klee/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
        "/sbin:/bin:/tmp/llvm-160-install_O_D_A/bin:/home/klee/klee_build/bin"
    )
    bc = "/tmp/lotus_klee.bc"
    if driver_source is not None:
        _drv = "/tmp/lotus_klee_driver.c"
        _b64 = base64.b64encode(driver_source.encode()).decode()
        _compile = (
            f"echo '{_b64}' | base64 -d > {_drv}; "
            f"clang -I /usr/local/include -I /src -emit-llvm -c -g -O0 "
            f"-Xclang -disable-O0-optnone '{_drv}' -o {bc}"
        )
    else:
        _compile = (
            f"clang -I /usr/local/include -emit-llvm -c -g -O0 "
            f"-Xclang -disable-O0-optnone '{target_c_rel}' -o {bc}"
        )
    script = (
        f"set -e; export PATH='{_klee_path}'; cd /src; "
        f"{_compile} 2>&1 || {{ echo __COMPILE_FAIL__; exit 0; }}; "
        f"klee --only-output-states-covering-new --max-time={max_time_s}s "
        f"--libc=uclibc --posix-runtime {bc} 2>&1 | tail -60; "
        f"echo __KLEE_DONE__"
    )
    # The official klee/klee image is amd64-only (KLEE has no Linux arm64
    # support). On an arm64 host Docker runs it under emulation only when the
    # platform is requested explicitly, so pin it. ``LOTUS_KLEE_PLATFORM``
    # overrides (e.g. a custom multi-arch KLEE image); set it empty to disable.
    _klee_platform = (os.environ.get("LOTUS_KLEE_PLATFORM") or "linux/amd64").strip()
    _platform_args = ["--platform", _klee_platform] if _klee_platform else []
    # KLEE needs a writable source mount for klee-out-* and the image's /tmp
    # must not be shadowed by a tmpfs (that's where the image's clang lives).
    cmd = [
        "docker", "run", "--rm", *_platform_args, *_container_runtime_args(repo_id, klee=True),
        "-v", f"{dest}:/src", "-w", "/src",
        "--ulimit", "stack=-1", KLEE_IMAGE, "bash", "-lc", script,
    ]
    if send:
        await send(repo_id, f"▶ KLEE symbolic execution on {target_c_rel} ({max_time_s}s)...",
                   detail_id=f"{repo_id}-task-klee")
    out, _ = await _run(cmd, timeout=max_time_s + 180)
    result.stats = parse_klee_output(out)
    result.stats["compile_failed"] = "__COMPILE_FAIL__" in out
    result.stats["status"] = ("failed" if result.stats["compile_failed"]
                              else "completed" if "__KLEE_DONE__" in out else "failed")
    if result.stats["compile_failed"]:
        result.stats["reason"] = "target did not compile to LLVM bitcode"
    _emit_klee_findings(result, target_c_rel)
    return result


def _emit_klee_findings(result: "ExplorationResult", target_c_rel: str) -> None:
    """Shared KLEE error-path -> finding doctrine for the Docker and Kubernetes
    runtimes. Reads ``result.stats['errors']`` (populated by
    :func:`parse_klee_output`) and appends one QUALIFIED finding per error-class
    path (memory errors, overflows, frees, asserts)."""
    for err in result.stats.get("errors", []):
        result.findings.append({
            "tool": "klee",
            "title": f"KLEE path error: {err.get('kind', 'error')} in {target_c_rel}",
            "cvss": 6.5 if err.get("kind") in ("ptr", "overflow", "free") else 5.0,
            "description": (
                f"Symbolic execution reached a {err.get('kind')} error on a feasible path in "
                f"{target_c_rel}. Concrete input emitted as {err.get('ktest', 'test.ktest')}."
            ),
            "file": target_c_rel, "line": err.get("line", 0),
            "confidence": "high", "discovery_technique": "symbolic-execution",
            "qualification": "QUALIFIED", "proven_in_lab": True,
        })


def parse_klee_output(out: str) -> Dict[str, Any]:
    """Parse KLEE stderr summary: completed paths, generated tests, errors."""
    out = out or ""
    stats: Dict[str, Any] = {"errors": []}
    for key, pat in (
        ("completed_paths", r"completed paths\s*=\s*(\d+)"),
        ("generated_tests", r"generated tests\s*=\s*(\d+)"),
        ("instructions", r"instructions\s*=\s*(\d+)"),
    ):
        m = re.search(pat, out)
        if m:
            stats[key] = int(m.group(1))
    # KLEE prints "KLEE: ERROR: <file>:<line>: <msg>" and writes testNNNNNN.<kind>.err
    for m in re.finditer(r"KLEE: ERROR:\s*(?:([^\s:]+):(\d+):\s*)?(.+)", out):
        msg = m.group(3).strip().lower()
        kind = ("ptr" if "memory" in msg or "pointer" in msg else
                "overflow" if "overflow" in msg else
                "free" if "free" in msg else
                "assert" if "assert" in msg else
                "div" if "divide" in msg else "error")
        stats["errors"].append({
            "kind": kind, "line": int(m.group(2)) if m.group(2) else 0,
            "message": m.group(3).strip()[:160],
        })
    return stats


# ===========================================================================
# C/C++ KLEE TARGET DISCOVERY + DRIVER SYNTHESIS
# ===========================================================================
# KLEE symbolically executes a single LLVM bitcode module from ``main``. Real
# C/C++ parse entry points are library functions without a ``main``, so we
# synthesize a small driver that marks an input buffer symbolic with
# ``klee_make_symbolic`` and calls the target - the same role the coverage-guided
# harnesses play for the fuzz engines.

# A function *definition* (not a prototype or call): ``ret name(params) {``.
_C_FUNC_RE = re.compile(
    r"^[A-Za-z_][\w\s\*]*?\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^{};]*?)\)\s*\{",
    re.M,
)
_C_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "typedef",
               "do", "else", "case", "goto"}
# Param types that can carry the symbolic untrusted input.
_C_INPUT_RE = re.compile(
    r"(?:const\s+)?(?:unsigned\s+)?char\s*\*|(?:const\s+)?uint8_t\s*\*|"
    r"(?:const\s+)?void\s*\*|(?:const\s+)?char\s*\w*\s*\[")
# Scalar types that may be a buffer *length* accompanying the input param.
_C_LEN_TYPES = {"size_t", "int", "unsigned", "unsigned int", "ssize_t", "long",
                "uint32_t", "uint16_t", "int32_t", "len", "n", "length", "size"}


def _c_params(params: str) -> List[str]:
    """Split a C parameter list on top-level commas (ignoring parens/brackets)."""
    out, depth, cur = [], 0, ""
    for ch in params:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [p for p in out if p and p != "void"]


def _c_param_type(param: str) -> str:
    """Return the declared type of a C parameter (drops the param name)."""
    p = param.strip()
    # Function-pointer / array params are not drivable - bail to a opaque type.
    m = re.match(r"^(?P<t>.+?)(?P<n>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?$", p)
    if not m:
        return p
    t = m.group("t").strip()
    # ``char *uri`` -> group t already ends with '*'; ``char* uri`` likewise.
    return t


def _c_is_input_param(param: str) -> bool:
    return bool(_C_INPUT_RE.search(param))


def _c_arg_expr(param: str, *, is_input: bool, is_len: bool) -> Optional[str]:
    """Return a C expression to pass for ``param`` in the synthesized driver.

    The symbolic buffer feeds the input param; a trailing scalar length param
    gets the buffer size; other pointers get a zeroed compound literal; scalars
    get ``0``. Returns ``None`` when the param cannot be safely fabricated.
    """
    if is_input:
        return "lotus_input"
    if is_len:
        return "lotus_input_len"
    t = _c_param_type(param)
    if not t or "(" in t:  # function pointer - cannot fabricate
        return None
    if t.endswith("*"):
        return f"&({t[:-1].strip()}){{0}}"
    if re.search(r"\b(char|int|short|long|unsigned|signed|size_t|ssize_t|"
                 r"uint\d+_t|int\d+_t|float|double|bool|_Bool|enum\s+\w+)\b", t):
        return "0"
    # struct / union / opaque value type - zeroed compound literal.
    return f"({t}){{0}}"


# C parse-entry role hints - superset of the shared patterns plus the split/
# lex/tokenize vocabulary common in C parsers (uri_split, json_lex, ...).
_C_ROLE_PATTERNS = _GO_ROLE_PATTERNS + [
    ("parse", re.compile(r"split|tokeniz|lex|scan|fromstr|from_str", re.I)),
]
# Path components that mark vendored / third-party code - real parsers live
# there too, but the project's own sources are the primary audit surface.
_C_VENDOR_DIRS = {"deps", "vendor", "third_party", "third-party", "external",
                  "extern", "contrib", "subprojects"}


def _c_classify_role(name: str) -> str:
    for role, pat in _C_ROLE_PATTERNS:
        if pat.search(name):
            return role
    return "generic"


def discover_c_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find C functions that ingest an untrusted string/byte buffer.

    A drivable KLEE target has exactly one buffer-ish parameter (``char*``,
    ``const char*``, ``uint8_t*``, ``void*``) - the symbolic input - and only
    other params we can fabricate (pointers -> zeroed compound literal, scalars
    -> 0, a trailing length -> the buffer size). Candidates are ranked so the
    project's own (non-vendored), self-contained, parse-named functions win -
    those are the most likely to compile to bitcode without a generated
    config.h or external deps.
    """
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    for c in dest.rglob("*.c"):
        parts = {p.lower() for p in c.parts}
        if parts & {".git", "test", "tests", "testdata", "examples", "example"}:
            continue
        try:
            text = c.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(c.relative_to(dest))
        vendored = bool(parts & _C_VENDOR_DIRS)
        proj_includes = len(re.findall(r'^\s*#\s*include\s*"', text, re.M))
        for m in _C_FUNC_RE.finditer(text):
            name = m.group("name")
            if name in _C_KEYWORDS or name.startswith("_"):
                continue
            params = _c_params(m.group("params"))
            if not params:
                continue
            input_idx = [i for i, p in enumerate(params) if _c_is_input_param(p)]
            if len(input_idx) != 1:
                continue
            # Fabricate every other param; bail if any cannot be synthesized.
            arg_exprs: List[str] = []
            ok = True
            for i, p in enumerate(params):
                is_input = (i == input_idx[0])
                is_len = (i > input_idx[0] and _c_param_type(p).strip() in _C_LEN_TYPES)
                expr = _c_arg_expr(p, is_input=is_input, is_len=is_len)
                if expr is None:
                    ok = False
                    break
                arg_exprs.append(expr)
            if not ok:
                continue
            role = _c_classify_role(name)
            line = text.count("\n", 0, m.start()) + 1
            conf = "high" if role in ("parse", "decode", "unmarshal", "load") else "medium"
            ep = ParseEntryPoint(
                language="c/cpp", file=rel, line=line, package="", symbol=name,
                input_kind="string", signature=m.group(0)[:-1].strip(),
                role=role, confidence=conf,
            )
            # Stash the synthesized call expression for the driver generator.
            ep._klee_call = f"{name}({', '.join(arg_exprs)});"  # type: ignore[attr-defined]
            ep._klee_vendored = vendored  # type: ignore[attr-defined]
            ep._klee_includes = proj_includes  # type: ignore[attr-defined]
            if ep.key() in seen:
                continue
            seen.add(ep.key())
            out.append(ep)
    role_rank = {"parse": 0, "decode": 1, "unmarshal": 2, "load": 3,
                 "read": 4, "generic": 5}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    # Own code before vendored deps; parse-named before generic; then the most
    # self-contained (fewest project includes) first - best compile odds.
    out.sort(key=lambda e: (getattr(e, "_klee_vendored", False),
                            conf_rank[e.confidence],
                            role_rank.get(e.role, 9),
                            getattr(e, "_klee_includes", 99)))
    return out


def synthesize_klee_driver(ep: ParseEntryPoint, input_size: int = 256) -> str:
    """Generate a self-contained KLEE driver for one C parse entry point.

    The driver textually ``#include``s the target ``.c`` so every type and
    static helper is in scope, marks a fixed-size buffer symbolic, NUL-
    terminates it, and calls the target. ``ep._klee_call`` carries the call
    expression built during discovery.
    """
    call = getattr(ep, "_klee_call", None) or f"{ep.symbol}(lotus_input);"
    return (
        "/* Auto-generated KLEE driver: symbolic-exec one parse entry point. */\n"
        "#include <klee/klee.h>\n"
        "#include <string.h>\n"
        f'#include "{ep.file}"\n'
        "\n"
        "int main(void) {\n"
        f"    char lotus_input[{input_size}];\n"
        f"    const unsigned lotus_input_len = {input_size};\n"
        "    klee_make_symbolic(lotus_input, sizeof(lotus_input), \"lotus_input\");\n"
        "    lotus_input[sizeof(lotus_input) - 1] = '\\0';\n"
        f"    (void){call}\n"
        "    return 0;\n"
        "}\n"
    )


# ===========================================================================
# PYTHON / JAVA HARNESS SYNTHESIS (execution engines staged)
# ===========================================================================
def synthesize_atheris_harness(module: str, symbol: str, input_kind: str = "bytes") -> str:
    """Generate an Atheris (libFuzzer-for-Python) harness driving ``module.symbol``.

    Two subtleties matter for real apps (e.g. Superset):
    - The target module is often already imported transitively during package init,
      which makes ``instrument_imports`` a no-op (no coverage -> libFuzzer bails).
      We drop it from ``sys.modules`` so the instrumented re-import actually
      compiles it with coverage.
    - For string inputs we decode the raw bytes directly (instead of the unicode
      mangling of ``FuzzedDataProvider``) so that a human-readable seed corpus of
      valid grammar expressions can guide the fuzzer through the parser.
    """
    if input_kind == "string":
        conv = ('    try:\n'
                '        data = raw.decode("utf-8", "surrogatepass")\n'
                '    except Exception:\n'
                '        return\n')
    else:
        conv = "    data = bytes(raw)\n"
    return (
        "import atheris, sys\n"
        f"# Force a coverage-instrumented (re)import of the target module even if a\n"
        f"# package import already pulled it into sys.modules uninstrumented.\n"
        f"sys.modules.pop({module!r}, None)\n"
        f"with atheris.instrument_imports():\n    import {module}\n\n"
        "def TestOneInput(raw):\n"
        f"{conv}"
        "    try:\n"
        f"        {module}.{symbol}(data)\n"
        "    except (ValueError, TypeError, KeyError):\n"
        "        pass  # expected input-validation errors are not bugs\n\n"
        "atheris.Setup(sys.argv, TestOneInput)\n"
        "atheris.Fuzz()\n"
    )


def synthesize_jazzer_harness(fqcn: str, method: str, input_kind: str = "bytes") -> str:
    """Generate a Jazzer (libFuzzer-for-JVM) fuzz target driving ``fqcn.method``."""
    call = {
        "bytes": "target.%s(data.consumeRemainingAsBytes());" % method,
        "string": "target.%s(data.consumeRemainingAsString());" % method,
    }.get(input_kind, "target.%s(data.consumeRemainingAsBytes());" % method)
    simple = fqcn.rsplit(".", 1)[-1]
    return (
        "import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n"
        f"import {fqcn};\n\n"
        "public class LotusFuzzTarget {\n"
        "  public static void fuzzerTestOneInput(FuzzedDataProvider data) {\n"
        f"    {simple} target = new {simple}();\n"
        "    try {\n"
        f"      {call}\n"
        "    } catch (IllegalArgumentException | NullPointerException e) {\n"
        "      // expected validation errors\n"
        "    }\n"
        "  }\n"
        "}\n"
    )


# ===========================================================================
# PYTHON ENGINE (Atheris - coverage-guided, libFuzzer-based)
# ===========================================================================
ATHERIS_IMAGE = os.environ.get("LOTUS_ATHERIS_IMAGE", "python:3.11-bookworm")

_PY_ROLE_PATTERNS = [
    ("deserialize", re.compile(r"deserial|unpickle|un_?marshal|from_?pickle|from_?yaml", re.I)),
    ("unmarshal", re.compile(r"unmarshal|marshal_?load", re.I)),
    ("render", re.compile(r"render|template|jinja|from_?string", re.I)),
    ("execute", re.compile(r"eval|exec|compile|run_?sql|execute", re.I)),
    ("decode", re.compile(r"decode|b64|unquote|urldecode", re.I)),
    ("load", re.compile(r"^loads?$|_?loads?$|from_?(text|str|string|json|bytes)", re.I)),
    ("parse", re.compile(r"parse|scan|tokeniz|lex|read_", re.I)),
]

# name-hint -> input_kind for the primary parameter
_PY_BYTES_HINTS = {"data", "payload", "raw", "buf", "buffer", "body", "content",
                   "blob", "bytes", "b", "octets", "stream"}
_PY_STR_HINTS = {"text", "s", "string", "expr", "expression", "template", "tmpl",
                 "sql", "query", "src", "source", "code", "value", "val", "input", "name"}

_PY_DEF_RE = re.compile(r"^def\s+(?P<name>[a-zA-Z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:->\s*[^:]+)?:", re.M)


def _py_module_path(dest: Path, file_rel: str) -> Optional[str]:
    """Convert a repo-relative .py path to an importable dotted module path.

    Handles src-layout (strips a leading ``src.``) and drops ``__init__``. Returns
    None for files that are not part of an importable package chain when we cannot
    confidently form a module path (still best-effort - the pod adds repo root and
    src to sys.path)."""
    p = Path(file_rel)
    if p.name == "__init__.py":
        parts = list(p.parts[:-1])
    else:
        parts = list(p.parts[:-1]) + [p.stem]
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    return ".".join(parts)


def _py_primary_arg(params: str) -> Optional[Tuple[str, bool]]:
    """Return (first_param_name, callable_with_one_arg) or None.

    Callable-with-one-arg means every param after the first is optional
    (has a default, or is ``*args``/``**kwargs``), so the fuzzer can drive it
    with a single positional value."""
    raw = [x.strip() for x in params.split(",") if x.strip()]
    if not raw:
        return None
    first = raw[0].split(":")[0].split("=")[0].strip()
    if first in ("self", "cls") or first.startswith("*"):
        return None
    ok = True
    for extra in raw[1:]:
        e = extra.strip()
        if e.startswith("*"):
            continue
        if "=" not in e:
            ok = False
            break
    return (first, ok)


def _py_input_kind(params: str, first_arg: str, role: str) -> str:
    # explicit type hint wins
    m = re.search(rf"\b{re.escape(first_arg)}\s*:\s*([\w\.\[\]]+)", params)
    if m:
        t = m.group(1).lower()
        if "bytes" in t or "bytearray" in t:
            return "bytes"
        if "str" in t:
            return "string"
    low = first_arg.lower()
    if low in _PY_BYTES_HINTS:
        return "bytes"
    if low in _PY_STR_HINTS:
        return "string"
    if role in ("deserialize", "unmarshal", "decode", "load"):
        return "bytes"
    return "string"


def _classify_py_role(name: str) -> Optional[str]:
    for role, pat in _PY_ROLE_PATTERNS:
        if pat.search(name):
            return role
    return None


def discover_python_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find module-level Python functions that ingest untrusted data and can be
    driven with a single positional argument (parse/loads/decode/deserialize/
    render/eval). Prioritises deserialization/render/execute (RCE-adjacent)."""
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    skip = {"tests", "test", "testing", "migrations", "node_modules", "vendor",
            ".git", ".venv", "venv", "__pycache__", "docs", "examples", "example"}
    for py in dest.rglob("*.py"):
        try:
            rel = py.relative_to(dest)
        except ValueError:
            continue
        # Filter on the repo-RELATIVE path only; the absolute prefix (e.g. a
        # username like /Users/test/...) must never trigger skip tokens.
        if {p.lower() for p in rel.parts} & skip:
            continue
        if py.name.startswith("test_") or py.name.endswith("_test.py") or py.name == "conftest.py":
            continue
        try:
            text = py.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(rel)
        mod = _py_module_path(dest, rel)
        if not mod:
            continue
        for m in _PY_DEF_RE.finditer(text):
            # module-level only: the `def` must start at column 0
            if m.group(0)[0] != "d":  # regex is MULTILINE anchored, but guard indentation
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            if text[line_start:m.start()].strip():  # indented (method) -> skip
                continue
            name = m.group("name")
            if name.startswith("_"):
                continue
            role = _classify_py_role(name)
            if role is None:
                continue
            prim = _py_primary_arg(m.group("params"))
            if not prim or not prim[1]:
                continue
            first_arg, _ = prim
            input_kind = _py_input_kind(m.group("params"), first_arg, role)
            line = text.count("\n", 0, m.start()) + 1
            conf = "high" if role in ("deserialize", "unmarshal", "render", "execute", "load") else "medium"
            ep = ParseEntryPoint(
                language="python", file=rel, line=line, package=mod, symbol=name,
                input_kind=input_kind, signature=m.group(0).rstrip(":"),
                role=role, confidence=conf,
            )
            if ep.key() in seen:
                continue
            seen.add(ep.key())
            out.append(ep)
    role_rank = {"deserialize": 0, "unmarshal": 1, "execute": 2, "render": 3,
                 "load": 4, "decode": 5, "parse": 6}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda e: (conf_rank[e.confidence], role_rank.get(e.role, 9)))
    return out


def synthesize_python_harness(ep: ParseEntryPoint) -> Harness:
    """Wrap :func:`synthesize_atheris_harness` into a Harness for the orchestrator."""
    src = synthesize_atheris_harness(ep.package, ep.symbol, ep.input_kind)
    return Harness(language="python", entry=ep, pkg_dir=".",
                   filename=f"lotus_atheris_{ep.symbol.lower()}.py",
                   source=src, fuzz_func=ep.symbol)


# RCE/deser-adjacent Python exceptions we treat as high-signal (vs. benign parse errors)
_PY_HIGH_SIGNAL = re.compile(
    r"(pickle|yaml|marshal|subprocess|os\.system|eval|exec|jinja2|"
    r"TemplateError|CodeExecution|__reduce__|find_class|RestrictedError)", re.I)


def parse_atheris_output(out: str) -> Dict[str, Any]:
    """Detect a libFuzzer/Atheris crash and extract the Python exception class.

    Distinguishes a real fuzz crash from a **startup import failure**: the harness
    imports the target module at load time (Atheris needs the instrumented import
    for coverage), so on real apps a module that needs app/DB context raises
    ``ModuleNotFoundError``/``ImportError`` *before* fuzzing starts. That must be
    reported as a *skip-with-reason*, NOT a crash finding - otherwise the fallback
    error-line regex would mis-score the import traceback as a vulnerability."""
    out = out or ""
    # A genuine coverage-guided crash is signalled by libFuzzer/Atheris markers.
    lf_crash = ("Uncaught Python exception" in out or
                "ERROR: libFuzzer: deadly signal" in out or
                re.search(r"^==\d+== ERROR", out, re.M) is not None)
    import_fail = bool(re.search(
        r"ModuleNotFoundError|No module named|ImportError|cannot import name", out))
    import_error = ""
    mi = re.search(r"((?:ModuleNotFoundError|ImportError)[^\n]*)", out)
    if mi:
        import_error = mi.group(1).strip()[:200]
    # Extract a display exception name (independent of how we decide `crashed`).
    exc = ""
    m = re.search(r"Uncaught Python exception:.*\n\s*([A-Za-z_][\w\.]*)", out)
    if m:
        exc = m.group(1)
    m2 = re.search(r"\n([A-Za-z_][\w\.]*(?:Error|Exception)):", out)
    if not exc and m2:
        exc = m2.group(1)
    # A bare "SomeError:" line counts as a crash ONLY when it is not the harness's
    # own import failure (a skip, handled by the caller) and there is no libFuzzer
    # marker (in which case it is already a crash).
    crashed = bool(lf_crash) or (m2 is not None and not import_fail)
    crash_file = None
    mf = re.search(r"(?:Test unit written to|artifact_prefix.*?)\s*(\S*crash-\w+)", out)
    if mf:
        crash_file = mf.group(1)
    high_signal = crashed and bool(_PY_HIGH_SIGNAL.search(out))
    return {"crashed": crashed, "exception": exc, "crash_file": crash_file,
            "high_signal": high_signal,
            "import_failed": import_fail and not lf_crash,
            "import_error": import_error}


async def _emit_atheris_result(result: "ExplorationResult", h: "Harness", out: str,
                               repro_b64: Optional[str], fuzztime_s: int,
                               send, repo_id: int) -> bool:
    """Turn one harness's Atheris output into a finding/skip + progress message.

    Shared by the Docker (:func:`run_atheris`) and Kubernetes
    (:func:`backend.k8s_dynamic.run_atheris_k8s`) execution paths so the crash
    doctrine, CVSS capping and messaging never drift between runtimes.
    ``repro_b64`` is the base64 reproducer the caller harvested (from the bind
    mount or the framed artifact tar), or ``None``. Returns True on a crash.
    """
    parsed = parse_atheris_output(out)
    if parsed.get("import_failed"):
        # Target module could not be imported in the pod (needs app/DB context).
        # This is a skip-with-reason, not a crash - surface it honestly so the
        # audit shows *why* an entry point was not fuzzed rather than silently
        # counting it as "no crash".
        reason = parsed.get("import_error") or "target module failed to import"
        result.stats.setdefault("skipped_targets", []).append(
            {"target": h.entry.key(), "reason": reason})
        if send:
            await send(repo_id,
                       f"⊘ {h.entry.symbol}: not fuzzed - module import failed "
                       f"({reason[:120]})",
                       detail_id=f"{repo_id}-task-atheris")
        return False
    if parsed["crashed"]:
        exc = parsed["exception"] or "exception"
        hi = parsed["high_signal"]
        # DOCTRINE: a reproduced crash proves a *defect*, not exploitation.
        # A crash that merely REACHES a deser/exec sink is a strong RCE *lead*,
        # not a confirmed >=7 RCE - that requires a gadget/SSTI PoC with a real
        # oracle (uid=). So we cap CVSS below the 7.0 report threshold and keep
        # it QUALIFIED; Phase 2 raises severity only if an exploit oracle fires.
        # (Mirrors _classify_go_crash, which is already honest.)
        cvss = 6.5 if hi else 5.3
        cls = "deser/rce-adjacent" if hi else "unhandled-exception"
        result.findings.append({
            "tool": "atheris",
            "title": (f"Coverage-guided crash in {h.entry.symbol}: {exc} "
                      + ("(candidate RCE/deser - PoC required)" if hi
                         else "(robustness/DoS)")),
            "cvss": cvss,
            "description": (
                f"Atheris drove untrusted input into {h.entry.package}.{h.entry.symbol} "
                f"({h.entry.signature}) and reached an uncaught {exc}. "
                + ("The traceback references a code-execution/deserialization sink "
                   "(pickle/yaml/eval/jinja2). This is a HIGH-PRIORITY LEAD, not a "
                   "confirmed RCE: the crash proves reachability of the sink, but "
                   "confirming code execution requires a gadget/SSTI PoC with a "
                   "concrete oracle (e.g. uid=) in Phase 2. CVSS stays below the "
                   "report threshold until that PoC succeeds." if hi else
                   "Reproduced defect (unhandled exception -> likely 500/worker crash "
                   "= availability/robustness). Confirm any higher impact in Phase 2.")
            ),
            "file": h.entry.file, "line": h.entry.line,
            "confidence": "high" if hi else "medium",
            "discovery_technique": "coverage-guided-fuzz",
            "qualification": "QUALIFIED",
            "conviction_level": 2 if hi else 1,
            "rce_lead": bool(hi),
            "needs_exploit_poc": bool(hi),
            "proven_in_lab": True,
            "lab_evidence": [{"path": "atheris", "params": {"symbol": h.entry.key()},
                              "snippet": exc, "anomaly_type": cls, "method": "fuzz"}],
            "poc": {"command": f"python .lotus_harness/{h.filename}", "harness": h.filename},
            "poc_result": "triggered",
        })
        if repro_b64:
            result.artifacts.append({"type": "reproducer", "target": h.entry.key(),
                                     "encoding": "base64", "data": repro_b64})
        if send:
            await send(repo_id, f"✗ CRASH in {h.entry.symbol}: {exc} ({cls}, cvss~{cvss})",
                       level="warning", detail_id=f"{repo_id}-task-atheris")
        return True
    if send:
        await send(repo_id, f"✓ {h.entry.symbol}: no crash in {fuzztime_s}s",
                   detail_id=f"{repo_id}-task-atheris")
    return False


async def run_atheris(
    dest: Path,
    harnesses: List[Harness],
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    send=None,
    repo_id: int = 0,
) -> ExplorationResult:
    """Run Atheris (coverage-guided) harnesses in a python pod.

    The pod installs atheris + the target package (best-effort ``pip install -e .``)
    and runs each harness for a bounded time. Crashes with RCE/deser-adjacent
    exceptions (pickle/yaml/eval/jinja2) are surfaced as high-signal findings; a
    reproducer input is captured when libFuzzer writes one. Degrades gracefully if
    Docker or the image is unavailable, or install fails."""
    result = ExplorationResult(language="python", engine="atheris")
    dest = Path(dest)
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no python entrypoints"}
        return result
    # Kubernetes-first: when Kubernetes is the selected runtime, build the deps
    # image with kaniko and fuzz in a Job (see backend.k8s_dynamic). Docker is used
    # only when explicitly selected.
    if harnesses:
        from backend.k8s_runtime import use_k8s_runtime
        _use_k8s = await use_k8s_runtime(repo_id)
        if _use_k8s:
            from backend import k8s_dynamic
            return await k8s_dynamic.run_atheris_k8s(dest, harnesses, fuzztime_s,
                                                     send=send, repo_id=repo_id)
    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", ATHERIS_IMAGE], 20)
        return bool(o.strip())
    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/atheris image unavailable"}
        return result

    written: List[Path] = []
    hdir = dest / ".lotus_harness"
    try:
        hdir.mkdir(exist_ok=True)
    except Exception as e:
        result.stats = {"status": "skipped", "reason": f"cannot write harness dir: {e}"}
        return result
    for h in harnesses:
        try:
            hp = hdir / h.filename
            hp.write_text(h.source)
            written.append(hp)
            result.harnesses.append({"target": h.entry.key(), "module": h.entry.package,
                                     "symbol": h.entry.symbol, "file": h.filename,
                                     "input_kind": h.entry.input_kind})
        except Exception:
            pass

    crashes = 0
    # One pod that installs deps once, then runs every harness (install is the costly part).
    # Atheris ships no wheel for some arches (e.g. arm64) and must compile its native
    # module against a libFuzzer-capable clang; installing the distro clang and pointing
    # CLANG_BIN at it avoids Atheris trying to build all of LLVM from source.
    install = (
        "set +e; export DEBIAN_FRONTEND=noninteractive; "
        "(command -v clang >/dev/null 2>&1 || "
        " (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq clang >/dev/null 2>&1)); "
        "export CLANG_BIN=$(command -v clang || echo /usr/bin/clang); "
        "pip install --quiet --disable-pip-version-check atheris 2>&1 | tail -3; "
        "pip install --quiet -e . 2>&1 | tail -3 || pip install --quiet . 2>&1 | tail -3 || "
        "echo '__INSTALL_BESTEFFORT__'; "
        "export PYTHONPATH=/src:/src/src:$PYTHONPATH; "
    )
    # Bake the heavy install into a per-repo image once so every harness run (and
    # every later audit of this repo) skips it. Falls back to per-run install if
    # caching is disabled or the build/commit fails.
    run_image = ATHERIS_IMAGE
    per_harness_install = install
    cache_status = "disabled"
    if ATHERIS_CACHE:
        tag = _atheris_cache_tag(repo_id, dest)
        cached = await _image_exists(tag)
        if not cached:
            if send:
                await send(repo_id, "▶ Building Atheris cache image (one-time per repo)...",
                           detail_id=f"{repo_id}-task-atheris")
            cached = await _build_atheris_cache(dest, tag, install, repo_id)
            if cached:
                # Bound disk use: evict oldest cache images beyond the cap (keep this one).
                await _prune_cache_images(_ATHERIS_CACHE_REPO, CACHE_MAX_IMAGES, keep_tag=tag)
        if cached:
            run_image = tag
            # Env baked into the image; just refresh PYTHONPATH defensively.
            per_harness_install = "set +e; export PYTHONPATH=/src:/src/src:$PYTHONPATH; "
            cache_status = "hit"
        else:
            cache_status = "miss-fallback"
    corpus_seeded = corpus_new = 0
    for h in harnesses:
        if send:
            await send(repo_id, f"▶ Atheris fuzzing {h.entry.package}.{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-atheris")
        # Seed a persistent corpus so repeat audits resume from prior coverage.
        cname = _sanitize(h.entry.key())
        corpus_run = hdir / f"corpus_{cname}"
        persist = persistent_corpus_dir(repo_id, "atheris", h.entry.key()) if PERSIST_CORPUS else None
        corpus_seeded += seed_corpus(persist, corpus_run)
        run_one = (
            f"mkdir -p .lotus_harness/corpus_{cname}; "
            f"timeout {fuzztime_s + 20} python .lotus_harness/{h.filename} "
            f".lotus_harness/corpus_{cname} "
            f"-max_total_time={fuzztime_s} -artifact_prefix=.lotus_harness/ "
            f"2>&1 | tail -60; echo __ATHERIS_DONE__"
        )
        cmd = [
            "docker", "run", "--rm", *_container_runtime_args(repo_id),
            "-v", f"{dest}:/src", "-w", "/src",
            "--network", "bridge", run_image, "bash", "-c", per_harness_install + run_one,
        ]
        out, _ = await _run(cmd, timeout=fuzztime_s + 420)  # allow long first-time install
        corpus_new += harvest_corpus(corpus_run, persist)
        if await _emit_atheris_result(result, h, out, _read_atheris_repro(hdir),
                                      fuzztime_s, send, repo_id):
            crashes += 1

    # Clean up harnesses + crash artifacts so the repo checkout stays pristine.
    try:
        shutil.rmtree(hdir, ignore_errors=True)
    except Exception:
        pass
    _skipped = result.stats.get("skipped_targets", []) if isinstance(result.stats, dict) else []
    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "skipped_import_failed": len(_skipped),
                    "skipped_targets": _skipped,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "image_cache": cache_status}
    return result


def _read_atheris_repro(hdir: Path) -> Optional[str]:
    try:
        crashers = sorted([p for p in hdir.glob("crash-*") if p.is_file()],
                          key=lambda p: -p.stat().st_mtime)
        if crashers:
            return base64.b64encode(crashers[0].read_bytes()).decode()
    except Exception:
        pass
    return None


# ===========================================================================
# NODE.JS ENGINE (Jazzer.js - coverage-guided, libFuzzer-based, with the
# built-in bug detectors: command injection / prototype pollution / path
# traversal). Mirrors the Atheris engine and obeys the same crash=lead doctrine.
# ===========================================================================
# Debian *trixie* (glibc 2.41), not bookworm (glibc 2.36): current
# @jazzer.js/fuzzer prebuilds (fuzzer-linux-*.node) are linked against
# GLIBC_2.38, so on a bookworm base the native addon fails to dlopen
# ("version `GLIBC_2.38' not found") and every Node harness silently no-ops.
NODE_IMAGE = os.environ.get("LOTUS_NODE_IMAGE", "node:20-trixie")

# Exported-function shapes we can drive with a single untrusted argument.
_JS_PATTERNS = [
    re.compile(r"(?:module\.)?exports\.(?P<name>[A-Za-z_]\w*)\s*=\s*(?:async\s+)?function\s*\*?\s*\((?P<params>[^)]*)\)"),
    re.compile(r"(?:module\.)?exports\.(?P<name>[A-Za-z_]\w*)\s*=\s*(?:async\s+)?\((?P<params>[^)]*)\)\s*=>"),
    re.compile(r"export\s+(?:async\s+)?function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"),
    re.compile(r"export\s+const\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?:async\s+)?\((?P<params>[^)]*)\)\s*=>"),
    re.compile(r"export\s+const\s+(?P<name>[A-Za-z_]\w*)\s*=\s*(?:async\s+)?function\s*\*?\s*\((?P<params>[^)]*)\)"),
]
_JS_ROLE_PATTERNS = [
    ("deserialize", re.compile(r"deserial|unserial|unmarshal|revive|from_?json", re.I)),
    ("render", re.compile(r"render|template|compile|interpolat", re.I)),
    ("execute", re.compile(r"eval|exec|\brun\b|command|shell", re.I)),
    ("decode", re.compile(r"decode|unescape|unquote|b64|base64", re.I)),
    ("parse", re.compile(r"parse|load|read|import|ingest|process|handle|convert|transform|sanitiz", re.I)),
]
_JS_BYTES_HINTS = {"buf", "buffer", "bytes", "binary", "raw", "chunk"}
# Node crashes/findings we treat as high-signal (RCE/proto-pollution-adjacent).
_JS_HIGH_SIGNAL = re.compile(
    r"(Command Injection|Prototype Pollution|Path Traversal|Remote Code|"
    r"child_process|vm\.run|deseriali[sz]|\beval\b|Function\(|ReDoS)", re.I)


def _classify_js_role(name: str) -> Optional[str]:
    for role, rx in _JS_ROLE_PATTERNS:
        if rx.search(name):
            return role
    return None


def _js_primary_arg(params: str) -> Optional[Tuple[str, bool]]:
    """Return (first_arg_name, drivable) for a JS param list. Not drivable if the
    first arg is destructured, or if there are additional *required* params."""
    parts = [p.strip() for p in (params or "").split(",") if p.strip()]
    if not parts:
        return None
    first = parts[0]
    if first.startswith("{") or first.startswith("[") or first.startswith("..."):
        return None  # destructured / rest - cannot drive with one scalar
    name = re.split(r"[=:]", first, 1)[0].strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", name):
        return None
    for extra in parts[1:]:
        if "=" not in extra and not extra.startswith("..."):
            return None  # a second required arg - skip
    return name, True


def discover_node_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find exported Node functions that ingest untrusted data and can be driven
    with a single positional argument. Prioritises deserialize/render/execute."""
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    skip = {"tests", "test", "spec", "__tests__", "node_modules", "vendor",
            ".git", "dist", "build", "coverage", "docs", "examples", "example"}
    # Only .js/.cjs/.mjs are directly fuzzable (no TS transpile in the pod).
    for pat_glob in ("*.js", "*.cjs", "*.mjs"):
        for js in dest.rglob(pat_glob):
            try:
                rel = js.relative_to(dest)
            except ValueError:
                continue
            if {p.lower() for p in rel.parts} & skip:
                continue
            if js.name.endswith((".test.js", ".spec.js", ".min.js")):
                continue
            try:
                text = js.read_text(errors="ignore")
            except Exception:
                continue
            rel_posix = rel.as_posix()
            require_path = "../" + re.sub(r"\.(c|m)?js$", "", rel_posix)
            for pat in _JS_PATTERNS:
                for m in pat.finditer(text):
                    name = m.group("name")
                    if name.startswith("_"):
                        continue
                    role = _classify_js_role(name)
                    if role is None:
                        continue
                    prim = _js_primary_arg(m.group("params"))
                    if not prim:
                        continue
                    first_arg = prim[0]
                    input_kind = ("bytes" if (role == "decode"
                                  or first_arg.lower() in _JS_BYTES_HINTS) else "string")
                    line = text.count("\n", 0, m.start()) + 1
                    conf = "high" if role in ("deserialize", "render", "execute") else "medium"
                    ep = ParseEntryPoint(
                        language="node", file=rel_posix, line=line, package=require_path,
                        symbol=name, input_kind=input_kind,
                        signature=m.group(0).strip(), role=role, confidence=conf,
                    )
                    if ep.key() in seen:
                        continue
                    seen.add(ep.key())
                    out.append(ep)
    role_rank = {"deserialize": 0, "execute": 1, "render": 2, "decode": 3, "parse": 4}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda e: (conf_rank[e.confidence], role_rank.get(e.role, 9)))
    return out


def synthesize_jazzer_js_harness(require_path: str, symbol: str, input_kind: str = "string") -> str:
    """Generate a Jazzer.js fuzz target driving ``require(require_path).symbol``.

    Jazzer.js invokes the module's exported ``fuzz`` function with a Buffer each
    iteration and ships bug detectors (command injection / prototype pollution /
    path traversal) that flag a reached sink even without an uncaught crash. We
    swallow benign validation errors so only real defects surface, and require the
    target lazily so a module that needs app context degrades to a no-op instead
    of aborting the run."""
    if input_kind == "string":
        conv = '  let input; try { input = data.toString("utf-8"); } catch (e) { return; }\n'
    else:
        conv = "  const input = data;\n"
    return (
        '"use strict";\n'
        "module.exports.fuzz = function (data) {\n"
        f"{conv}"
        "  let target;\n"
        f"  try {{ target = require({require_path!r}); }} catch (e) {{ return; }}\n"
        f"  const fn = (target && target.{symbol}) || target;\n"
        '  if (typeof fn !== "function") { return; }\n'
        "  try {\n"
        "    fn(input);\n"
        "  } catch (e) {\n"
        '    const n = (e && e.name) || "";\n'
        "    // Benign input-validation errors are not bugs; rethrow everything else.\n"
        '    if (n === "TypeError" || n === "RangeError" || n === "SyntaxError") { return; }\n'
        "    throw e;\n"
        "  }\n"
        "};\n"
    )


def synthesize_node_harness(ep: ParseEntryPoint) -> Harness:
    src = synthesize_jazzer_js_harness(ep.package, ep.symbol, ep.input_kind)
    return Harness(language="node", entry=ep, pkg_dir=".",
                   filename=f"lotus_jazzerjs_{ep.symbol.lower()}.js",
                   source=src, fuzz_func=ep.symbol)


def parse_jazzer_js_output(out: str) -> Dict[str, Any]:
    """Detect a Jazzer.js crash / bug-detector finding and extract its class."""
    out = out or ""
    crashed = (
        "== Uncaught Exception" in out
        or "JavaScript Exception" in out
        or "libFuzzer: deadly signal" in out
        or "Security Issue" in out
        or re.search(r"^==\d+== ERROR", out, re.M) is not None
        or bool(re.search(r"(Command Injection|Prototype Pollution|Path Traversal)", out, re.I))
    )
    exc = ""
    m = (re.search(r"(?:Security Issue|Finding|Uncaught Exception):\s*([A-Za-z][\w .\-]*)", out)
         or re.search(r"\n([A-Za-z_][\w.]*(?:Error|Exception)):", out)
         or re.search(r"(Command Injection|Prototype Pollution|Path Traversal)", out, re.I))
    if m:
        exc = m.group(1).strip()
    crash_file = None
    mf = re.search(r"(?:Test unit written to|artifact_prefix.*?)\s*(\S*crash-\w+)", out)
    if mf:
        crash_file = mf.group(1)
    return {"crashed": crashed, "exception": exc or "exception",
            "crash_file": crash_file, "high_signal": bool(_JS_HIGH_SIGNAL.search(out))}


async def _emit_jazzerjs_result(result: "ExplorationResult", h: "Harness", out: str,
                                repro_b64: Optional[str], fuzztime_s: int,
                                send, repo_id: int) -> bool:
    """Turn one Jazzer.js harness's output into a finding + progress message.

    Shared by the Docker (:func:`run_node_fuzz`) and Kubernetes
    (:func:`backend.k8s_dynamic.run_node_k8s`) execution paths so the crash
    doctrine and messaging never drift between runtimes. Returns True on a crash.
    """
    parsed = parse_jazzer_js_output(out)
    if not parsed["crashed"]:
        if send:
            await send(repo_id, f"✓ {h.entry.symbol}: no crash in {fuzztime_s}s",
                       detail_id=f"{repo_id}-task-jazzerjs")
        return False
    exc = parsed["exception"]
    hi = parsed["high_signal"]
    # DOCTRINE (same as Atheris/Go): a reproduced crash proves a *defect*,
    # not exploitation. A crash/bug-detector hit that reaches an RCE / proto-
    # pollution sink is a strong LEAD - capped below the 7.0 report threshold
    # and kept QUALIFIED until Phase 2 lands a real exploit oracle.
    cvss = 6.5 if hi else 5.3
    cls = "rce/proto-pollution-adjacent" if hi else "unhandled-exception"
    stem = re.sub(r"\.js$", "", h.filename)
    result.findings.append({
        "tool": "jazzer.js",
        "title": (f"Coverage-guided crash in {h.entry.symbol}: {exc} "
                  + ("(candidate RCE/proto-pollution - PoC required)" if hi
                     else "(robustness/DoS)")),
        "cvss": cvss,
        "description": (
            f"Jazzer.js drove untrusted input into {h.entry.symbol} "
            f"({h.entry.signature}) and reached {exc}. "
            + ("A bug detector or traceback references an RCE / prototype-"
               "pollution / path-traversal sink. HIGH-PRIORITY LEAD, not a "
               "confirmed RCE: confirming impact requires an exploit PoC with a "
               "concrete oracle in Phase 2; CVSS stays below the report threshold "
               "until then." if hi else
               "Reproduced defect (unhandled exception -> likely 500/worker crash "
               "= availability/robustness). Confirm any higher impact in Phase 2.")
        ),
        "file": h.entry.file, "line": h.entry.line,
        "confidence": "high" if hi else "medium",
        "discovery_technique": "coverage-guided-fuzz",
        "qualification": "QUALIFIED",
        "conviction_level": 2 if hi else 1,
        "rce_lead": bool(hi),
        "needs_exploit_poc": bool(hi),
        "proven_in_lab": True,
        "lab_evidence": [{"path": "jazzer.js", "params": {"symbol": h.entry.key()},
                          "snippet": exc, "anomaly_type": cls, "method": "fuzz"}],
        "poc": {"command": f"npx jazzer .lotus_harness/{stem}", "harness": h.filename},
        "poc_result": "triggered",
    })
    if repro_b64:
        result.artifacts.append({"type": "reproducer", "target": h.entry.key(),
                                 "encoding": "base64", "data": repro_b64})
    if send:
        await send(repo_id, f"✗ CRASH in {h.entry.symbol}: {exc} ({cls}, cvss~{cvss})",
                   level="warning", detail_id=f"{repo_id}-task-jazzerjs")
    return True


async def run_node_fuzz(
    dest: Path,
    harnesses: List[Harness],
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    send=None,
    repo_id: int = 0,
) -> ExplorationResult:
    """Run Jazzer.js (coverage-guided) harnesses in a node pod. Installs
    @jazzer.js/core once, then drives each entry point for a bounded time.
    Degrades gracefully if Docker/image/install is unavailable."""
    result = ExplorationResult(language="node", engine="jazzer.js")
    dest = Path(dest)
    # Kubernetes-first: fuzz in a Job with a writable /work workspace (npm install
    # happens in-pod, mirroring the Docker path). Docker is the break-glass.
    if harnesses:
        from backend.k8s_runtime import use_k8s_runtime
        _use_k8s = await use_k8s_runtime(repo_id)
        if _use_k8s:
            from backend import k8s_dynamic
            return await k8s_dynamic.run_node_k8s(dest, harnesses, fuzztime_s,
                                                  send=send, repo_id=repo_id)

    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", NODE_IMAGE], 20)
        return bool(o.strip())

    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no node entrypoints"}
        return result
    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/node image unavailable"}
        return result

    hdir = dest / ".lotus_harness"
    try:
        hdir.mkdir(exist_ok=True)
    except Exception as e:
        result.stats = {"status": "skipped", "reason": f"cannot write harness dir: {e}"}
        return result
    for h in harnesses:
        try:
            (hdir / h.filename).write_text(h.source)
            result.harnesses.append({"target": h.entry.key(), "module": h.entry.package,
                                     "symbol": h.entry.symbol, "file": h.filename,
                                     "input_kind": h.entry.input_kind})
        except Exception:
            pass

    crashes = 0
    # Install jazzer.js once in a throwaway package; the target's own deps are
    # best-effort (npm install if a package.json exists).
    install = (
        "set +e; cd /src; "
        "[ -f package.json ] && (npm install --no-audit --no-fund --silent 2>&1 | tail -3); "
        "npm install --no-audit --no-fund --silent --prefix /tmp/jz @jazzer.js/core 2>&1 | tail -3 "
        "|| echo __INSTALL_BESTEFFORT__; "
        "export NODE_PATH=/tmp/jz/node_modules:/src/node_modules; "
    )
    corpus_seeded = corpus_new = 0
    for h in harnesses:
        stem = re.sub(r"\.js$", "", h.filename)
        if send:
            await send(repo_id, f"▶ Jazzer.js fuzzing {h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-jazzerjs")
        # Seed a persistent corpus so repeat audits resume from prior coverage.
        cname = _sanitize(h.entry.key())
        corpus_run = hdir / f"corpus_{cname}"
        persist = persistent_corpus_dir(repo_id, "jazzer.js", h.entry.key()) if PERSIST_CORPUS else None
        corpus_seeded += seed_corpus(persist, corpus_run)
        run_one = (
            f"mkdir -p .lotus_harness/corpus_{cname}; "
            f"timeout {fuzztime_s + 30} /tmp/jz/node_modules/.bin/jazzer "
            f".lotus_harness/{stem} .lotus_harness/corpus_{cname} -- -max_total_time={fuzztime_s} "
            f"-artifact_prefix=.lotus_harness/ 2>&1 | tail -60; echo __JAZZERJS_DONE__"
        )
        cmd = [
            "docker", "run", "--rm", *_container_runtime_args(repo_id),
            "-v", f"{dest}:/src", "-w", "/src",
            "--network", "bridge", NODE_IMAGE, "bash", "-c", install + run_one,
        ]
        out, _ = await _run(cmd, timeout=fuzztime_s + 420)
        corpus_new += harvest_corpus(corpus_run, persist)
        if await _emit_jazzerjs_result(result, h, out, _read_atheris_repro(hdir),
                                       fuzztime_s, send, repo_id):
            crashes += 1

    try:
        shutil.rmtree(hdir, ignore_errors=True)
    except Exception:
        pass
    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new}
    return result


# ===========================================================================
# JVM ENGINE (Jazzer - coverage-guided, libFuzzer-based, with the JVM bug
# detectors: OS command injection / deserialization / SSRF / EL / naming-context
# / SQL / XPath / LDAP). Mirrors the Node engine and obeys the crash=lead doctrine.
# ===========================================================================
JVM_IMAGE = os.environ.get("LOTUS_JVM_IMAGE", "maven:3.9-eclipse-temurin-17")
JAZZER_VERSION = os.environ.get("LOTUS_JAZZER_VERSION", "0.22.1")
# Bake the maven/gradle dependency cache + Jazzer release into a per-repo image once
# so each harness skips re-downloading them (mirrors the Atheris cache).
JVM_CACHE = str(os.environ.get("LOTUS_JVM_CACHE", "1")).lower() in ("1", "true", "yes")
# Jazzer's native launcher (`jazzer-linux.tar.gz`) is x86_64-only, so the JVM engine must
# run on an amd64 runtime (native on x86_64 hosts; qemu-emulated on arm64). Empty disables
# the pin (set LOTUS_JVM_PLATFORM="" if you supply an arm64-native Jazzer image).
JVM_PLATFORM = os.environ.get("LOTUS_JVM_PLATFORM", "linux/amd64")

_JAVA_PKG_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
_JAVA_CLASS_RE = re.compile(r"\b(?:public\s+)?(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)")
# public [static] <ret> name(<params>) - method-level entry points.
_JAVA_METHOD_RE = re.compile(
    r"public\s+(?P<static>static\s+)?(?:final\s+)?(?:synchronized\s+)?"
    r"[\w.$<>,\[\]\s]+?\s+(?P<name>[a-zA-Z_]\w*)\s*\((?P<params>[^)]*)\)")
_JAVA_ROLE_PATTERNS = [
    ("deserialize", re.compile(r"deserial|unmarshal|readObject|fromXml|fromJson|readValue|revive", re.I)),
    ("execute", re.compile(r"eval|exec|\brun\b|compile|command|shell|script", re.I)),
    ("render", re.compile(r"render|template|interpolat|expression", re.I)),
    ("decode", re.compile(r"decode|unescape|base64|unquote", re.I)),
    ("parse", re.compile(r"parse|load|read|ingest|process|handle|convert|transform|sanitiz|validate|import", re.I)),
]
# JVM findings we treat as high-signal (RCE/deser/injection-adjacent).
_JAVA_HIGH_SIGNAL = re.compile(
    r"(Remote Code Execution|OS Command Injection|Command Injection|Deserialization|"
    r"Expression Language Injection|Naming Context Lookup|Server Side Request Forgery|"
    r"SQL Injection|LDAP Injection|XPath Injection|ReflectiveCall|ScriptEngine|"
    r"ProcessBuilder|Runtime\.exec|readObject|InvocationTargetException)", re.I)


def _classify_java_role(name: str) -> Optional[str]:
    for role, rx in _JAVA_ROLE_PATTERNS:
        if rx.search(name):
            return role
    return None


def _java_primary_arg(params: str) -> Optional[Tuple[str, str]]:
    """Return (type, kind) for a single-arg untrusted-data method, else None.
    Only single-parameter methods are driven (Java overloads make multi-arg
    driving ambiguous)."""
    parts = [p.strip() for p in (params or "").split(",") if p.strip()]
    if len(parts) != 1:
        return None
    # Strip annotations/final, then take the type token (first word).
    tok = re.sub(r"@\w+\s*", "", parts[0]).replace("final ", "").strip()
    m = re.match(r"([\w.$<>,\[\]]+)\s+[A-Za-z_]\w*$", tok)
    if not m:
        return None
    t = m.group(1)
    if "byte[]" in t:
        return t, "bytes"
    if "InputStream" in t:
        return t, "stream"
    if "Reader" in t:
        return t, "reader"
    if t in ("String", "CharSequence") or t.endswith(".String"):
        return t, "string"
    return None


def discover_java_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find public single-arg Java methods that ingest untrusted data (parse/
    deserialize/read/decode) and can be driven by Jazzer. Prioritises deser/exec."""
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    skip = {"test", "tests", "spec", "target", "build", ".git", "generated",
            "node_modules", "vendor", "examples", "example"}
    for jf in dest.rglob("*.java"):
        try:
            rel = jf.relative_to(dest)
        except ValueError:
            continue
        if {p.lower() for p in rel.parts} & skip:
            continue
        if jf.name.endswith(("Test.java", "Tests.java", "IT.java")):
            continue
        try:
            text = jf.read_text(errors="ignore")
        except Exception:
            continue
        pkg_m = _JAVA_PKG_RE.search(text)
        cls_m = _JAVA_CLASS_RE.search(text)
        if not cls_m:
            continue
        cls = cls_m.group(1)
        pkg = pkg_m.group(1) if pkg_m else ""
        fqcn = f"{pkg}.{cls}" if pkg else cls
        rel_posix = rel.as_posix()
        for m in _JAVA_METHOD_RE.finditer(text):
            name = m.group("name")
            if name in ("if", "for", "while", "switch", "catch", "synchronized", "new"):
                continue
            role = _classify_java_role(name)
            if role is None:
                continue
            prim = _java_primary_arg(m.group("params"))
            if not prim:
                continue
            _, kind = prim
            is_static = bool(m.group("static"))
            line = text.count("\n", 0, m.start()) + 1
            conf = "high" if role in ("deserialize", "execute") else "medium"
            # Encode static-ness in the signature so the synthesizer can branch.
            sig = ("static " if is_static else "") + m.group(0).strip()
            ep = ParseEntryPoint(
                language="java", file=rel_posix, line=line, package=fqcn,
                symbol=name, input_kind=kind, signature=sig, role=role, confidence=conf,
            )
            if ep.key() in seen:
                continue
            seen.add(ep.key())
            out.append(ep)
    role_rank = {"deserialize": 0, "execute": 1, "render": 2, "decode": 3, "parse": 4}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda e: (conf_rank[e.confidence], role_rank.get(e.role, 9)))
    return out


def synthesize_jvm_harness(ep: ParseEntryPoint) -> Harness:
    """Generate a Jazzer fuzz target driving ``ep.package.ep.symbol`` with an
    untrusted argument. Handles static vs. instance methods and the four input
    kinds (bytes / InputStream / String / Reader). Benign validation exceptions
    are swallowed; everything else propagates to Jazzer as a finding."""
    arg = {
        "bytes": "data.consumeRemainingAsBytes()",
        "stream": "new java.io.ByteArrayInputStream(data.consumeRemainingAsBytes())",
        "string": "data.consumeRemainingAsString()",
        "reader": "new java.io.StringReader(data.consumeRemainingAsString())",
    }.get(ep.input_kind, "data.consumeRemainingAsBytes()")
    simple = ep.package.rsplit(".", 1)[-1]
    is_static = ep.signature.startswith("static ")
    invoke = (f"{simple}.{ep.symbol}({arg});" if is_static
              else f"new {simple}().{ep.symbol}({arg});")
    cls_name = f"LotusFuzz_{_sanitize(ep.symbol)}"
    src = (
        "import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n"
        + (f"import {ep.package};\n\n" if "." in ep.package else "\n")
        + f"public class {cls_name} {{\n"
        "  public static void fuzzerTestOneInput(FuzzedDataProvider data) {\n"
        "    try {\n"
        f"      {invoke}\n"
        "    } catch (IllegalArgumentException | NullPointerException "
        "| IndexOutOfBoundsException e) {\n"
        "      // expected input-validation errors are not bugs\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    return Harness(language="java", entry=ep, pkg_dir=".",
                   filename=f"{cls_name}.java", source=src, fuzz_func=ep.symbol)


def parse_jazzer_output(out: str) -> Dict[str, Any]:
    """Detect a Jazzer (JVM) crash / bug-detector finding and extract its class."""
    out = out or ""
    crashed = (
        "== Java Exception:" in out
        or "== libFuzzer crashing input" in out
        or "Security Issue:" in out
        or "ERROR: libFuzzer: deadly signal" in out
        or re.search(r"^==\d+== ERROR", out, re.M) is not None
        or bool(re.search(r"(Remote Code Execution|OS Command Injection|Deserialization|"
                          r"Server Side Request Forgery|Expression Language Injection|"
                          r"Naming Context Lookup|SQL Injection|LDAP Injection)", out, re.I))
    )
    exc = ""
    m = (re.search(r"== Java Exception:\s*([\w.$]+)", out)
         or re.search(r"Security Issue:\s*([^\n]+)", out)
         or re.search(r"\n([\w.$]+(?:Exception|Error))", out))
    if m:
        exc = m.group(1).strip()
    crash_file = None
    mf = re.search(r"(?:Test unit written to|artifact_prefix.*?)\s*(\S*crash-\w+)", out)
    if mf:
        crash_file = mf.group(1)
    return {"crashed": crashed, "exception": exc or "exception",
            "crash_file": crash_file, "high_signal": bool(_JAVA_HIGH_SIGNAL.search(out))}


def _detect_jvm_build(dest: Path) -> Optional[str]:
    """Return the build system ('maven'|'gradle') we can use to produce a classpath."""
    dest = Path(dest)
    if (dest / "pom.xml").exists():
        return "maven"
    if (dest / "build.gradle").exists() or (dest / "build.gradle.kts").exists():
        return "gradle"
    return None


async def _emit_jazzer_result(result: "ExplorationResult", h: "Harness", out: str,
                              repro_b64: Optional[str], fuzztime_s: int,
                              send=None, repo_id: int = 0) -> bool:
    """Shared Jazzer (JVM) crash doctrine for the Docker and Kubernetes runtimes.

    Parses the engine output, emits a QUALIFIED crash finding + reproducer
    artifact on a validated crash, and reports pass/fail via ``send``. Returns
    True when a crash/finding was emitted."""
    parsed = parse_jazzer_output(out)
    cls = re.sub(r"\.java$", "", h.filename)
    if not parsed["crashed"]:
        if send:
            await send(repo_id, f"✓ {h.entry.symbol}: no crash in {fuzztime_s}s",
                       detail_id=f"{repo_id}-task-jazzer")
        return False
    exc = parsed["exception"]
    hi = parsed["high_signal"]
    # DOCTRINE (same as Atheris/Go/Node): a reproduced crash proves a *defect*,
    # not exploitation. A crash/bug-detector hit reaching an RCE / deser / injection
    # sink is a strong LEAD - capped below the 7.0 report threshold, kept QUALIFIED
    # until Phase 2 lands a real exploit oracle.
    cvss = 6.5 if hi else 5.3
    cls_label = "rce/deser/injection-adjacent" if hi else "unhandled-exception"
    result.findings.append({
        "tool": "jazzer",
        "title": (f"Coverage-guided crash in {h.entry.symbol}: {exc} "
                  + ("(candidate RCE/deser/injection - PoC required)" if hi
                     else "(robustness/DoS)")),
        "cvss": cvss,
        "description": (
            f"Jazzer drove untrusted input into {h.entry.package}.{h.entry.symbol} "
            f"({h.entry.signature}) and reached {exc}. "
            + ("A JVM bug detector or traceback references an RCE / deserialization / "
               "injection sink. HIGH-PRIORITY LEAD, not a confirmed RCE: confirming "
               "impact requires an exploit PoC with a concrete oracle in Phase 2; CVSS "
               "stays below the report threshold until then." if hi else
               "Reproduced defect (unhandled exception -> availability/robustness). "
               "Confirm any higher impact in Phase 2.")
        ),
        "file": h.entry.file, "line": h.entry.line,
        "confidence": "high" if hi else "medium",
        "discovery_technique": "coverage-guided-fuzz",
        "qualification": "QUALIFIED",
        "conviction_level": 2 if hi else 1,
        "rce_lead": bool(hi),
        "needs_exploit_poc": bool(hi),
        "proven_in_lab": True,
        "lab_evidence": [{"path": "jazzer", "params": {"symbol": h.entry.key()},
                          "snippet": exc, "anomaly_type": cls_label, "method": "fuzz"}],
        "poc": {"command": f"jazzer --target_class={cls}", "harness": h.filename},
        "poc_result": "triggered",
    })
    if repro_b64:
        result.artifacts.append({"type": "reproducer", "target": h.entry.key(),
                                 "encoding": "base64", "data": repro_b64})
    if send:
        await send(repo_id, f"✗ CRASH in {h.entry.symbol}: {exc} ({cls_label}, cvss~{cvss})",
                   level="warning", detail_id=f"{repo_id}-task-jazzer")
    return True


async def run_jvm_fuzz(
    dest: Path,
    harnesses: List[Harness],
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    send=None,
    repo_id: int = 0,
) -> ExplorationResult:
    """Build the target (maven/gradle) to obtain its classpath, download Jazzer,
    compile each harness against it, and fuzz. Degrades gracefully if Docker/image/
    build/download is unavailable."""
    result = ExplorationResult(language="java", engine="jazzer")
    dest = Path(dest)
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no java entrypoints"}
        return result
    build = _detect_jvm_build(dest)
    if not build:
        result.stats = {"status": "skipped", "reason": "no maven/gradle build detected"}
        return result

    # Kubernetes-first: when Kubernetes is the selected runtime, build + fuzz in
    # a Job (see backend.k8s_dynamic.run_jvm_k8s). Docker stays the break-glass
    # on hosts without a cluster.
    from backend.k8s_runtime import use_k8s_runtime
    _use_k8s = await use_k8s_runtime(repo_id)
    if _use_k8s:
        from backend import k8s_dynamic
        return await k8s_dynamic.run_jvm_k8s(dest, harnesses, fuzztime_s,
                                             send=send, repo_id=repo_id)

    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", JVM_IMAGE], 20)
        return bool(o.strip())

    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/jvm image unavailable"}
        return result

    hdir = dest / ".lotus_harness"
    try:
        hdir.mkdir(exist_ok=True)
    except Exception as e:
        result.stats = {"status": "skipped", "reason": f"cannot write harness dir: {e}"}
        return result
    for h in harnesses:
        try:
            (hdir / h.filename).write_text(h.source)
            result.harnesses.append({"target": h.entry.key(), "class": h.entry.package,
                                     "symbol": h.entry.symbol, "file": h.filename,
                                     "input_kind": h.entry.input_kind})
        except Exception:
            pass

    if build == "maven":
        build_cmd = (
            "mvn -q -DskipTests compile 2>&1 | tail -5; "
            "mvn -q dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt 2>&1 | tail -3; "
            "export PROJCP=target/classes:$(cat /tmp/cp.txt 2>/dev/null); "
        )
    else:
        build_cmd = (
            "(./gradlew -q compileJava 2>&1 | tail -5 || gradle -q compileJava 2>&1 | tail -5); "
            "export PROJCP=build/classes/java/main:$(find . -name '*.jar' 2>/dev/null | tr '\\n' ':'); "
        )
    jzurl = (f"https://github.com/CodeIntelligenceTesting/jazzer/releases/download/"
             f"v{JAZZER_VERSION}/jazzer-linux.tar.gz")

    def _jazzer_dl(dest_dir: str) -> str:
        return (f"curl -sSL {jzurl} -o /tmp/j.tgz 2>/dev/null; "
                f"mkdir -p {dest_dir} && tar xzf /tmp/j.tgz -C {dest_dir} 2>/dev/null "
                f"|| echo __JAZZER_DL_FAIL__; ")

    # Fallback (no cache): build + download Jazzer to /tmp/jazzer on every harness.
    run_image = JVM_IMAGE
    jazzer_dir = "/tmp/jazzer"
    per_harness_prefix = "set +e; cd /src; " + build_cmd + _jazzer_dl("/tmp/jazzer")
    cache_status = "disabled"
    if JVM_CACHE:
        tag = _jvm_cache_tag(repo_id, dest)
        cached = await _image_exists(tag)
        if not cached:
            if send:
                await send(repo_id, "▶ Building JVM cache image (deps + Jazzer, one-time per repo)...",
                           detail_id=f"{repo_id}-task-jazzer")
            # Warm the maven/gradle dependency cache (~/.m2 or ~/.gradle) and bake
            # Jazzer at /opt/jazzer; both persist in the committed image.
            cache_install = "set +e; cd /src; " + build_cmd + _jazzer_dl("/opt/jazzer")
            cached = await _build_cache_image(dest, tag, cache_install, JVM_IMAGE,
                                              commit_env=["JAZZER_DIR=/opt/jazzer"],
                                              platform=JVM_PLATFORM or None,
                                              repo_id=repo_id)
            if cached:
                await _prune_cache_images(_JVM_CACHE_REPO, CACHE_MAX_IMAGES, keep_tag=tag)
        if cached:
            run_image = tag
            jazzer_dir = "/opt/jazzer"
            # The cache image already contains compiled target classes and the
            # dependency classpath generated by ``build_cmd``.  Re-running
            # Maven/Gradle for every harness made a large JVM repo spend many
            # minutes under emulation before each 30-second fuzz window.  Reuse
            # those immutable artifacts; a cache miss still takes the original
            # best-effort build path below.
            per_harness_prefix = (
                "set +e; cd /src; "
                "export PROJCP=target/classes:$(cat /tmp/cp.txt 2>/dev/null); "
                "if [ -d build/classes/java/main ]; then "
                "export PROJCP=build/classes/java/main:$(find . -name '*.jar' 2>/dev/null | tr '\\n' ':'); fi; "
            )
            cache_status = "hit"
        else:
            cache_status = "miss-fallback"

    crashes = 0
    corpus_seeded = corpus_new = 0
    for h in harnesses:
        cls = re.sub(r"\.java$", "", h.filename)
        cname = _sanitize(h.entry.key())
        corpus_run = hdir / f"corpus_{cname}"
        persist = persistent_corpus_dir(repo_id, "jazzer", h.entry.key()) if PERSIST_CORPUS else None
        corpus_seeded += seed_corpus(persist, corpus_run)
        if send:
            await send(repo_id, f"▶ Jazzer (JVM) fuzzing {h.entry.package}.{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-jazzer")
        run_one = (
            f"mkdir -p .lotus_harness/corpus_{cname}; "
            f"javac -cp {jazzer_dir}/jazzer_standalone.jar:$PROJCP -d .lotus_harness "
            f".lotus_harness/{h.filename} 2>&1 | tail -20; "
            f"timeout {fuzztime_s + 40} {jazzer_dir}/jazzer --cp=.lotus_harness:$PROJCP "
            f"--target_class={cls} .lotus_harness/corpus_{cname} -max_total_time={fuzztime_s} "
            f"-artifact_prefix=.lotus_harness/ 2>&1 | tail -60; echo __JAZZER_DONE__"
        )
        plat = ["--platform", JVM_PLATFORM] if JVM_PLATFORM else []
        cmd = [
            "docker", "run", "--rm", *_container_runtime_args(repo_id)] + plat + [
            "-v", f"{dest}:/src", "-w", "/src",
            "--network", "bridge", run_image, "bash", "-c", per_harness_prefix + run_one,
        ]
        out, _ = await _run(cmd, timeout=fuzztime_s + 900)  # builds can be slow
        corpus_new += harvest_corpus(corpus_run, persist)
        if await _emit_jazzer_result(result, h, out, _read_atheris_repro(hdir),
                                     fuzztime_s, send, repo_id):
            crashes += 1

    try:
        shutil.rmtree(hdir, ignore_errors=True)
    except Exception:
        pass
    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s, "build": build,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "image_cache": cache_status}
    return result


# ===========================================================================
# RUBY ENGINE (coverage-guided mutational fuzzer built on Ruby's stdlib
# `Coverage` module - no native/libFuzzer build needed, so it runs in a plain
# ruby image). Mirrors the Node/JVM engines and obeys the crash=lead doctrine.
# ===========================================================================
RUBY_IMAGE = os.environ.get("LOTUS_RUBY_IMAGE", "ruby:3.3-slim")

# class/module openers and method defs (indentation drives nesting; see discovery).
_RUBY_SCOPE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<kind>class|module)\s+(?P<name>[A-Z]\w*(?:::[A-Z]\w*)*)")
_RUBY_DEF_RE = re.compile(
    r"^(?P<indent>[ \t]*)def\s+(?:(?P<recv>self)\.)?(?P<name>[a-zA-Z_]\w*[!?]?)"
    r"\s*(?:\((?P<params>[^)]*)\)|(?P<bare>[^\n#]*))?")
_RUBY_ROLE_PATTERNS = [
    ("deserialize", re.compile(r"deserial|unmarshal|marshal|from_?yaml|from_?json|load_?yaml|unsafe_load|revive", re.I)),
    ("execute", re.compile(r"eval|exec|\brun\b|command|shell|constantize|render_?erb", re.I)),
    ("render", re.compile(r"render|template|compile|interpolat|erb", re.I)),
    ("decode", re.compile(r"decode|unescape|unquote|base64|from_?hex", re.I)),
    ("parse", re.compile(r"parse|load|read|import|ingest|process|handle|convert|transform|sanitiz|deserialize", re.I)),
]
# Ruby exceptions treated as benign input-validation errors (not defects), mirroring
# the ValueError/TypeError swallow in Atheris. Everything else is a defect lead.
_RUBY_BENIGN = ("ArgumentError", "TypeError", "KeyError", "RangeError", "IndexError",
                "NotImplementedError", "NoMethodError")
# Backtrace/message tokens that mark a crash as RCE/deserialization-adjacent (high signal).
_RUBY_HIGH_SIGNAL = re.compile(
    r"(\beval\b|instance_eval|class_eval|module_eval|\bsystem\b|Kernel|Open3|IO\.popen|"
    r"Marshal|Psych|YAML\.load|constantize|\bsend\b|__send__|ERB|Process\.)", re.I)


def _classify_ruby_role(name: str) -> Optional[str]:
    for role, rx in _RUBY_ROLE_PATTERNS:
        if rx.search(name):
            return role
    return None


def _ruby_primary_arg(params: Optional[str]) -> Optional[str]:
    """Return the first positional arg name if the method is drivable with a single
    untrusted scalar, else None. Rejects splat/block/required-keyword first args and
    any additional *required* positional/keyword args."""
    parts = [p.strip() for p in (params or "").split(",") if p.strip()]
    if not parts:
        return None
    first = parts[0]
    if first[0] in "*&" or ":" in first or first.startswith("("):
        return None  # splat/block/keyword/destructured - not a single scalar
    name = first.split("=", 1)[0].strip()
    if not re.match(r"^[a-zA-Z_]\w*$", name):
        return None
    for extra in parts[1:]:
        # extra required if it has no default and is not a splat/block
        if extra[0] in "*&":
            continue
        if extra.endswith(":"):
            return None  # required keyword
        if "=" not in extra and ":" not in extra:
            return None  # required positional
    return name


def discover_ruby_parse_entrypoints(dest: Path) -> List[ParseEntryPoint]:
    """Find Ruby methods that ingest untrusted data (parse/load/deserialize/eval)
    and can be driven with a single positional argument. Enclosing class/module is
    resolved by *indentation* (a def at indent D is enclosed by class/module lines
    with indent < D) - robust for idiomatic Ruby without matching `end` tokens.

    `package` holds the receiver path (``Mod::Class`` or "" for a top-level def);
    `signature` is prefixed with ``self `` for class methods so the synthesizer can
    branch class-method vs. instance-method invocation."""
    dest = Path(dest)
    out: List[ParseEntryPoint] = []
    seen = set()
    skip = {"test", "tests", "spec", "vendor", ".git", "node_modules", "tmp",
            "db", "config", "log", "coverage", "examples", "example"}
    for rb in dest.rglob("*.rb"):
        try:
            rel = rb.relative_to(dest)
        except ValueError:
            continue
        if {p.lower() for p in rel.parts} & skip:
            continue
        if rb.name.endswith(("_test.rb", "_spec.rb")):
            continue
        try:
            text = rb.read_text(errors="ignore")
        except Exception:
            continue
        rel_posix = rel.as_posix()
        stack: List[Tuple[int, str]] = []  # (indent, name)
        for i, line in enumerate(text.splitlines()):
            msc = _RUBY_SCOPE_RE.match(line)
            if msc:
                ind = len(msc.group("indent").expandtabs())
                while stack and stack[-1][0] >= ind:
                    stack.pop()
                stack.append((ind, msc.group("name")))
                continue
            md = _RUBY_DEF_RE.match(line)
            if not md:
                continue
            name = md.group("name")
            if name.startswith("_"):
                continue
            role = _classify_ruby_role(name)
            if role is None:
                continue
            params = md.group("params")
            if params is None and md.group("bare") is not None:
                params = md.group("bare").strip()
            prim = _ruby_primary_arg(params)
            if not prim:
                continue
            ind = len(md.group("indent").expandtabs())
            receiver = "::".join(n for (si, n) in stack if si < ind)
            is_class_method = md.group("recv") == "self"
            conf = "high" if role in ("deserialize", "execute", "render") else "medium"
            sig = ("self " if is_class_method else "") + line.strip()
            ep = ParseEntryPoint(
                language="ruby", file=rel_posix, line=i + 1, package=receiver,
                symbol=name, input_kind="string", signature=sig, role=role, confidence=conf,
            )
            if ep.key() in seen:
                continue
            seen.add(ep.key())
            out.append(ep)
    role_rank = {"deserialize": 0, "execute": 1, "render": 2, "decode": 3, "parse": 4}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda e: (conf_rank[e.confidence], role_rank.get(e.role, 9)))
    return out


def _ruby_invoke_body(receiver: str, symbol: str, is_class_method: bool) -> str:
    """Ruby source for the body of the invoke wrapper (calls target with `input`)."""
    if not receiver:
        # Top-level def -> a private method on the main Object; callable bare.
        return f"  {symbol}(input)\n"
    if is_class_method:
        return f"  {receiver}.{symbol}(input)\n"
    # Instance method: construct defensively (a ctor needing args is a benign skip).
    return (f"  obj = ({receiver}.new rescue nil)\n"
            f"  return if obj.nil?\n"
            f"  obj.{symbol}(input)\n")


def synthesize_ruby_fuzz_script(target_abs: str, receiver: str, symbol: str,
                                is_class_method: bool) -> str:
    """Generate a self-contained coverage-guided Ruby fuzz driver.

    Uses the stdlib ``Coverage`` module (started BEFORE requiring the target so the
    target is instrumented) to run a simple coverage-feedback mutational loop: inputs
    that increase covered-line count are kept in the corpus. Benign validation errors
    are swallowed; any other exception is reported as a defect lead with a written
    reproducer. Reads seed inputs from ``ARGV[0]`` and writes crashers to ``ARGV[1]``;
    the time budget comes from ``LOTUS_RUBY_MAXTIME``."""
    invoke = _ruby_invoke_body(receiver, symbol, is_class_method)
    benign = ", ".join(_RUBY_BENIGN)
    script = r'''require 'coverage'
Coverage.start(lines: true)
TARGET = '__TARGET_ABS__'
begin
  require TARGET
rescue Exception => e
  STDERR.puts "load: #{e.class}: #{e.message}"
  puts "__RUBY_LOAD_FAILED__"
  exit 0
end

def __lotus_invoke__(input)
__INVOKE_BODY__end

BENIGN = [__BENIGN__]
corpus_dir = ARGV[0] || '.'
artifact_dir = ARGV[1] || '.'
max_time = (ENV['LOTUS_RUBY_MAXTIME'] || '20').to_f

def __lotus_cov_count__
  total = 0
  Coverage.peek_result.each do |_f, data|
    lines = data.is_a?(Hash) ? data[:lines] : data
    next unless lines
    lines.each { |c| total += 1 if c && c > 0 }
  end
  total
end

def __lotus_mutate__(base, rng)
  b = base.dup.force_encoding('ASCII-8BIT')
  op = rng.rand(6)
  return b + rng.bytes(rng.rand(8) + 1) if op == 0 || b.empty?
  i = rng.rand(b.bytesize)
  case op
  when 1 then b.setbyte(i, rng.rand(256))
  when 2 then b = b[0...i].to_s + rng.bytes(rng.rand(4) + 1) + b[i..-1].to_s
  when 3 then b = (b.bytesize > 1) ? (b[0...i].to_s + b[(i + 1)..-1].to_s) : b
  when 4 then b = b * 2
  else b.setbyte(i, b.getbyte(i) ^ (1 << rng.rand(8)))
  end
  b
end

seeds = []
Dir.glob(File.join(corpus_dir, '*')).each do |f|
  next unless File.file?(f)
  begin; seeds << File.binread(f); rescue StandardError; end
end
seeds.concat(["", "{}", "0", "null", "a" * 64, "\x00\x01\x02".b, "--- !ruby/object {}\n"])
corpus = seeds.uniq

require 'digest'
rng = Random.new(0)
best = __lotus_cov_count__
start = Time.now
iter = 0
while Time.now - start < max_time
  iter += 1
  base = corpus[rng.rand(corpus.size)]
  input = __lotus_mutate__(base, rng)
  s = input.dup.force_encoding('UTF-8')
  begin
    __lotus_invoke__(s)
  rescue *BENIGN
    # benign input-validation error - not a defect
  rescue Exception => e
    h = Digest::SHA1.hexdigest(input)[0, 16]
    path = File.join(artifact_dir, "crash-#{h}")
    begin; File.binwrite(path, input); rescue StandardError; end
    puts "== Ruby Exception: #{e.class}: #{e.message}"
    (e.backtrace || []).first(15).each { |l| puts l }
    puts "Test unit written to #{path}"
    puts "__RUBY_CRASH__"
    exit 0
  end
  now = __lotus_cov_count__
  if now > best
    best = now
    corpus << input
  end
end
puts "iterations=#{iter} coverage=#{best}"
puts "__RUBY_DONE__"
'''
    return (script.replace("__TARGET_ABS__", target_abs)
                  .replace("__INVOKE_BODY__", invoke)
                  .replace("__BENIGN__", benign))


def synthesize_ruby_harness(ep: ParseEntryPoint) -> Harness:
    """Wrap the coverage-guided Ruby driver into a Harness for the orchestrator."""
    target_abs = "/src/" + re.sub(r"\.rb$", "", ep.file)
    is_class_method = ep.signature.startswith("self ")
    src = synthesize_ruby_fuzz_script(target_abs, ep.package, ep.symbol, is_class_method)
    return Harness(language="ruby", entry=ep, pkg_dir=".",
                   filename=f"lotus_ruby_{_sanitize(ep.symbol)}.rb",
                   source=src, fuzz_func=ep.symbol)


def parse_ruby_output(out: str) -> Dict[str, Any]:
    """Detect a crash from the Ruby driver and extract the exception class."""
    out = out or ""
    crashed = "__RUBY_CRASH__" in out or "== Ruby Exception:" in out
    exc = "exception"
    m = re.search(r"== Ruby Exception:\s*([\w:]+):", out)
    if m:
        exc = m.group(1).strip()
    crash_file = None
    mf = re.search(r"Test unit written to\s+(\S+)", out)
    if mf:
        crash_file = mf.group(1)
    return {"crashed": crashed, "exception": exc, "crash_file": crash_file,
            "high_signal": bool(_RUBY_HIGH_SIGNAL.search(out)),
            "load_failed": "__RUBY_LOAD_FAILED__" in out}


async def _emit_ruby_result(result: "ExplorationResult", h: "Harness", out: str,
                            repro_b64: Optional[str], fuzztime_s: int,
                            send=None, repo_id: int = 0) -> str:
    """Shared Ruby crash doctrine for the Docker and Kubernetes runtimes.

    Parses the driver output and emits a QUALIFIED crash finding + reproducer on
    a validated crash. Returns ``"crash"``, ``"load_failed"`` (target could not
    be required - benign skip), or ``"clean"``."""
    parsed = parse_ruby_output(out)
    if parsed["load_failed"] and not parsed["crashed"]:
        if send:
            await send(repo_id, f"• {h.entry.symbol}: target failed to load (skipped)",
                       detail_id=f"{repo_id}-task-ruby")
        return "load_failed"
    if not parsed["crashed"]:
        if send:
            await send(repo_id, f"✓ {h.entry.symbol}: no crash in {fuzztime_s}s",
                       detail_id=f"{repo_id}-task-ruby")
        return "clean"
    exc = parsed["exception"]
    hi = parsed["high_signal"]
    # DOCTRINE (same as Atheris/Go/Node/JVM): a reproduced crash proves a
    # *defect*, not exploitation. A crash whose backtrace reaches an eval/
    # deserialization/command sink is a strong LEAD - capped below the 7.0
    # report threshold and kept QUALIFIED until Phase 2 lands an exploit oracle.
    cvss = 6.5 if hi else 5.3
    cls_label = "rce/deser/injection-adjacent" if hi else "unhandled-exception"
    recv = (h.entry.package + ".") if h.entry.package else ""
    result.findings.append({
        "tool": "ruby-cov",
        "title": (f"Coverage-guided crash in {recv}{h.entry.symbol}: {exc} "
                  + ("(candidate RCE/deser/injection - PoC required)" if hi
                     else "(robustness/DoS)")),
        "cvss": cvss,
        "description": (
            f"A coverage-guided mutational fuzzer drove untrusted input into "
            f"{recv}{h.entry.symbol} ({h.entry.signature}) and reached {exc}. "
            + ("The backtrace references an eval / deserialization / command sink. "
               "HIGH-PRIORITY LEAD, not a confirmed RCE: confirming impact requires "
               "an exploit PoC with a concrete oracle in Phase 2; CVSS stays below the "
               "report threshold until then." if hi else
               "Reproduced defect (unhandled exception -> likely 500/worker crash = "
               "availability/robustness). Confirm any higher impact in Phase 2.")
        ),
        "file": h.entry.file, "line": h.entry.line,
        "confidence": "high" if hi else "medium",
        "discovery_technique": "coverage-guided-fuzz",
        "qualification": "QUALIFIED",
        "conviction_level": 2 if hi else 1,
        "rce_lead": bool(hi),
        "needs_exploit_poc": bool(hi),
        "proven_in_lab": True,
        "lab_evidence": [{"path": "ruby-cov", "params": {"symbol": h.entry.key()},
                          "snippet": exc, "anomaly_type": cls_label, "method": "fuzz"}],
        "poc": {"command": f"ruby .lotus_harness/{h.filename}", "harness": h.filename},
        "poc_result": "triggered",
    })
    if repro_b64:
        result.artifacts.append({"type": "reproducer", "target": h.entry.key(),
                                 "encoding": "base64", "data": repro_b64})
    if send:
        await send(repo_id, f"✗ CRASH in {h.entry.symbol}: {exc} ({cls_label}, cvss~{cvss})",
                   level="warning", detail_id=f"{repo_id}-task-ruby")
    return "crash"


async def run_ruby_fuzz(
    dest: Path,
    harnesses: List[Harness],
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    send=None,
    repo_id: int = 0,
) -> ExplorationResult:
    """Run the coverage-guided Ruby driver for each harness in a ruby pod.
    Best-effort ``bundle install`` when a Gemfile is present. Degrades gracefully
    if Docker/image is unavailable or the target fails to load."""
    result = ExplorationResult(language="ruby", engine="ruby-cov")
    dest = Path(dest)
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no ruby entrypoints"}
        return result

    # Kubernetes-first: when Kubernetes is the selected runtime, run the
    # coverage-guided driver in a Job (see backend.k8s_dynamic.run_ruby_k8s).
    # Docker is used only when explicitly selected.
    from backend.k8s_runtime import use_k8s_runtime
    _use_k8s = await use_k8s_runtime(repo_id)
    if _use_k8s:
        from backend import k8s_dynamic
        return await k8s_dynamic.run_ruby_k8s(dest, harnesses, fuzztime_s,
                                              send=send, repo_id=repo_id)

    async def _img_present():
        o, _ = await _run(["docker", "images", "-q", RUBY_IMAGE], 20)
        return bool(o.strip())

    if not docker_available() or not await _img_present():
        result.stats = {"status": "skipped", "reason": "docker/ruby image unavailable"}
        return result

    hdir = dest / ".lotus_harness"
    try:
        hdir.mkdir(exist_ok=True)
    except Exception as e:
        result.stats = {"status": "skipped", "reason": f"cannot write harness dir: {e}"}
        return result
    for h in harnesses:
        try:
            (hdir / h.filename).write_text(h.source)
            result.harnesses.append({"target": h.entry.key(), "receiver": h.entry.package,
                                     "symbol": h.entry.symbol, "file": h.filename,
                                     "input_kind": h.entry.input_kind})
        except Exception:
            pass

    # Bundle the target's own deps once (best-effort); a missing/failed bundle just
    # means the target may fail to load, which the driver reports as a benign skip.
    install = ("set +e; cd /src; "
               "[ -f Gemfile ] && (bundle install --quiet 2>&1 | tail -3 || echo __BUNDLE_BESTEFFORT__); ")
    crashes = 0
    skipped_load = 0
    corpus_seeded = corpus_new = 0
    for h in harnesses:
        cname = _sanitize(h.entry.key())
        corpus_run = hdir / f"corpus_{cname}"
        persist = persistent_corpus_dir(repo_id, "ruby-cov", h.entry.key()) if PERSIST_CORPUS else None
        corpus_seeded += seed_corpus(persist, corpus_run)
        if send:
            await send(repo_id, f"▶ Ruby (coverage-guided) fuzzing "
                                f"{(h.entry.package + '.') if h.entry.package else ''}{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-ruby")
        run_one = (
            f"mkdir -p .lotus_harness/corpus_{cname}; "
            f"LOTUS_RUBY_MAXTIME={fuzztime_s} timeout {fuzztime_s + 40} ruby "
            f".lotus_harness/{h.filename} .lotus_harness/corpus_{cname} .lotus_harness "
            f"2>&1 | tail -60; echo __RUBY_OUTER_DONE__"
        )
        cmd = [
            "docker", "run", "--rm", *_container_runtime_args(repo_id),
            "-v", f"{dest}:/src", "-w", "/src",
            "--network", "bridge", RUBY_IMAGE, "bash", "-c", install + run_one,
        ]
        out, _ = await _run(cmd, timeout=fuzztime_s + 420)
        corpus_new += harvest_corpus(corpus_run, persist)
        status = await _emit_ruby_result(result, h, out, _read_atheris_repro(hdir),
                                         fuzztime_s, send, repo_id)
        if status == "crash":
            crashes += 1
        elif status == "load_failed":
            skipped_load += 1

    try:
        shutil.rmtree(hdir, ignore_errors=True)
    except Exception:
        pass
    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "skipped_load_failed": skipped_load,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new}
    return result


# ===========================================================================
# DANGER-SINK MAP (grep-based) for node/java/ruby/scala/kotlin - supplements the
# fuzz engines with Phase-2 tracing intel for sinks reached indirectly or in code
# we could not drive directly (and is the sole signal for langs without an engine).
# ===========================================================================
_NODE_SINK_RE = re.compile(
    r"\b(JSON\.parse|vm\.runInNewContext|vm\.runInThisContext|child_process\.\w+|"
    r"eval|Function\s*\(|deserialize|unserialize|require\s*\(|_\.merge|Object\.assign)\b")
_JAVA_SINK_RE = re.compile(
    r"\b(readObject|ObjectInputStream|XMLDecoder|readUnshared|Runtime\.getRuntime\(\)\.exec|"
    r"ProcessBuilder|ScriptEngine|GroovyShell|SpelExpressionParser|Class\.forName|"
    r"InitialContext|lookup|Unmarshaller|readValue|autoType)\b")
_RUBY_SINK_RE = re.compile(
    r"\b(Marshal\.load|YAML\.load|Psych\.unsafe_load|eval|instance_eval|system|`|"
    r"Kernel\.system|send\s*\(|constantize|ERB\.new)\b")


def discover_dangerous_sinks(dest: Path, language: str, max_hits: int = 200) -> List[Dict[str, Any]]:
    """Grep-level danger sink map for languages whose coverage-guided engines are
    not yet wired (Node/Java/Ruby). This is *tracing intel for Phase 2*, not a
    finding: it tells Phase 2 exactly which untrusted-data sinks to target with a
    harness or live PoC. Prioritises RCE/deser sinks."""
    dest = Path(dest)
    pat, globs = {
        "node": (_NODE_SINK_RE, ["*.js", "*.ts", "*.mjs", "*.cjs"]),
        "java": (_JAVA_SINK_RE, ["*.java", "*.scala", "*.kt"]),
        "scala": (_JAVA_SINK_RE, ["*.java", "*.scala"]),
        "ruby/rails": (_RUBY_SINK_RE, ["*.rb", "*.erb"]),
        "ruby": (_RUBY_SINK_RE, ["*.rb", "*.erb"]),
    }.get(language, (None, []))
    if pat is None:
        return []
    skip = {"node_modules", "vendor", ".git", "test", "tests", "spec", "__pycache__",
            "dist", "build", ".venv"}
    hits: List[Dict[str, Any]] = []
    for g in globs:
        for f in dest.rglob(g):
            try:
                rel = f.relative_to(dest)
            except ValueError:
                continue
            # Filter on repo-RELATIVE parts only (absolute prefix must not match).
            if {p.lower() for p in rel.parts} & skip:
                continue
            try:
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append({"file": str(rel), "line": line,
                             "sink": m.group(1) if m.groups() else m.group(0),
                             "language": language})
                if len(hits) >= max_hits:
                    return hits
    return hits


# ===========================================================================
# ORCHESTRATOR
# ===========================================================================
async def explore_paths(
    dest: Path,
    language: str,
    fuzztime_s: int = DEFAULT_FUZZTIME_S,
    max_harnesses: int = MAX_HARNESSES,
    send=None,
    repo_id: int = 0,
    sinks_only: bool = False,
) -> ExplorationResult:
    """Discover untrusted-data parse entry points, synthesize coverage-guided
    harnesses, and exercise them in a lab pod. Returns findings + code-path intel.

    ``sinks_only`` forces the cheap grep danger-sink map even for languages that
    have a wired fuzz engine (used when the caller has not opted into fuzzing or
    the audit depth is too shallow), so fuzzing stays strictly gated upstream.
    """
    if sinks_only:
        res = ExplorationResult(language=language, engine="sink-map")
        sinks = discover_dangerous_sinks(Path(dest), language)
        res.artifacts = [{"type": "danger-sink-map", "count": len(sinks), "sinks": sinks[:200]}]
        res.stats = {"status": "completed" if sinks else "skipped",
                     "reason": None if sinks else f"no sinks for '{language}'",
                     "sink_count": len(sinks)}
        return res
    if language == "go":
        eps = discover_go_parse_entrypoints(Path(dest))[:max_harnesses]
        harnesses = [synthesize_go_fuzz_harness(e) for e in eps]
        result = await run_go_fuzz(Path(dest), harnesses, fuzztime_s=fuzztime_s,
                                   send=send, repo_id=repo_id)
        result.entrypoints = eps
        return result
    if language == "python":
        eps = discover_python_parse_entrypoints(Path(dest))[:max_harnesses]
        harnesses = [synthesize_python_harness(e) for e in eps]
        result = await run_atheris(Path(dest), harnesses, fuzztime_s=fuzztime_s,
                                   send=send, repo_id=repo_id)
        result.entrypoints = eps
        return result
    if language == "node":
        eps = discover_node_parse_entrypoints(Path(dest))[:max_harnesses]
        harnesses = [synthesize_node_harness(e) for e in eps]
        result = await run_node_fuzz(Path(dest), harnesses, fuzztime_s=fuzztime_s,
                                     send=send, repo_id=repo_id)
        result.entrypoints = eps
        # Always attach the danger-sink map as supplementary Phase-2 tracing intel
        # (covers sinks reached indirectly / in code we could not fuzz directly).
        sinks = discover_dangerous_sinks(Path(dest), "node")
        if sinks:
            result.artifacts.append({"type": "danger-sink-map", "count": len(sinks),
                                     "sinks": sinks[:200]})
            result.stats.setdefault("sink_count", len(sinks))
        return result
    if language == "java":
        eps = discover_java_parse_entrypoints(Path(dest))[:max_harnesses]
        harnesses = [synthesize_jvm_harness(e) for e in eps]
        result = await run_jvm_fuzz(Path(dest), harnesses, fuzztime_s=fuzztime_s,
                                    send=send, repo_id=repo_id)
        result.entrypoints = eps
        # Supplementary danger-sink map for Phase-2 targeting (also covers Scala/Kotlin
        # sources and sinks reached indirectly / in code we could not fuzz directly).
        sinks = discover_dangerous_sinks(Path(dest), "java")
        if sinks:
            result.artifacts.append({"type": "danger-sink-map", "count": len(sinks),
                                     "sinks": sinks[:200]})
            result.stats.setdefault("sink_count", len(sinks))
        return result
    if language in ("ruby", "ruby/rails"):
        eps = discover_ruby_parse_entrypoints(Path(dest))[:max_harnesses]
        harnesses = [synthesize_ruby_harness(e) for e in eps]
        result = await run_ruby_fuzz(Path(dest), harnesses, fuzztime_s=fuzztime_s,
                                     send=send, repo_id=repo_id)
        result.entrypoints = eps
        # Supplementary danger-sink map for Phase-2 targeting (covers sinks reached
        # indirectly / in code we could not drive directly).
        sinks = discover_dangerous_sinks(Path(dest), language)
        if sinks:
            result.artifacts.append({"type": "danger-sink-map", "count": len(sinks),
                                     "sinks": sinks[:200]})
            result.stats.setdefault("sink_count", len(sinks))
        return result
    if language in ("c/cpp", "c", "cpp"):
        # KLEE symbolic execution is single-shot per translation unit, not a
        # per-harness fuzz loop. Discover a drivable parse function, synthesize
        # a driver that marks its input symbolic, and run KLEE on it. Real
        # projects often have TUs that need a generated config.h / external
        # deps, so try candidates until one actually compiles to bitcode.
        eps = discover_c_parse_entrypoints(Path(dest))[:max_harnesses]
        last: Optional[ExplorationResult] = None
        for ep in eps:
            driver = synthesize_klee_driver(ep)
            res = await run_klee(Path(dest), ep.file, entry_func="main",
                                 max_time_s=fuzztime_s, send=send, repo_id=repo_id,
                                 driver_source=driver)
            res.entrypoints = [ep]
            if res.stats.get("compile_failed"):
                last = res  # remember but keep looking for a compilable TU
                continue
            return res
        if last is not None:
            last.entrypoints = eps
            return last
        res = ExplorationResult(language=language, engine="klee")
        res.entrypoints = eps
        res.stats = {"status": "skipped",
                     "reason": "no drivable C parse entry point found"}
        return res
    # Languages without a wired coverage-guided engine yet: emit danger-sink
    # tracing intel so Phase 2 still gets actionable targets.
    res = ExplorationResult(language=language, engine="sink-map")
    sinks = discover_dangerous_sinks(Path(dest), language)
    res.artifacts = [{"type": "danger-sink-map", "count": len(sinks), "sinks": sinks[:200]}]
    res.stats = {"status": "completed" if sinks else "skipped",
                 "reason": None if sinks else f"no engine/sinks for '{language}'",
                 "sink_count": len(sinks)}
    return res
