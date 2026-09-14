"""Kubernetes execution for the dynamic path-exploration engines (fuzzing).

The Docker path bind-mounts the target tree read-write, writes generated
harnesses + seed corpus into it, runs a libFuzzer-based engine, and reads the
reproducer/corpus back out of the same directory.  Kubernetes has none of that:
the source arrives on a **read-only** PVC, pods run under PodSecurity
``restricted``, and there is no host bind mount to harvest artifacts from.

This module rebuilds that workflow with cluster-native primitives, reusing the
Stage-3a/3b machinery:

* **Writable workspace** -- the read-only source PVC is copied once into a
  writable ``emptyDir`` at ``/work`` (via ``writable_paths`` on
  :func:`backend.k8s_runtime.run_to_completion`); harnesses, corpus and
  reproducers are written there.
* **Per-repo deps image** -- the ``docker commit`` cache image (atheris + clang
  + best-effort target deps) becomes a **kaniko-built image** pushed to the
  in-cluster registry (:mod:`backend.k8s_builder`); ``image_exists`` is the
  cache hit.  This is the k8s replacement for ``_build_atheris_cache``.
* **Framed I/O over stdout** -- harnesses and (bounded) seed corpus are embedded
  base64 in the run script; each harness's engine output and a ``tar+base64`` of
  its corpus/reproducers are emitted between per-index markers, so the host
  reconstructs exactly what the Docker path harvested from the bind mount.

Only the *execution substrate* changes: discovery, harness synthesis, output
parsing, crash classification and corpus persistence are the shared, unit-tested
functions in :mod:`backend.dynamic_explorer`.
"""
from __future__ import annotations

import base64
import gzip
import io
import os
import re
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

# Per-index stdout framing (index -> harness, so the markers never depend on the
# target key's characters). BEGIN/END bracket the engine output; ART brackets a
# tar+base64 of the harness's corpus dir + crash artifacts.
_H_RE = re.compile(r"__LOTUS_H_(\d+)__BEGIN__\n(.*?)\n?__LOTUS_H_\1__END__", re.S)
_ART_RE = re.compile(r"__LOTUS_ART_(\d+)__BEGIN__\n(.*?)\n?__LOTUS_ART_\1__END__", re.S)

# Bound the seed corpus embedded in the Job manifest: the whole pod command must
# stay well under the ~1.5 MB etcd object limit. Harvest (out) is unbounded here
# because it streams back over pod logs, not the manifest.
_SEED_EMBED_MAX_BYTES = int(os.environ.get("LOTUS_K8S_FUZZ_SEED_EMBED_BYTES", "196608") or 196608)

# Pod output is untrusted. Limit both encoded transport and expanded archives;
# a small compressed result must not exhaust the controller's memory or disk.
_ART_ENCODED_MAX_BYTES = 8 * 1024 * 1024
_ART_EXPANDED_MAX_BYTES = 32 * 1024 * 1024
_ART_FILE_MAX_BYTES = 8 * 1024 * 1024
_ART_MAX_MEMBERS = 4096


def _sh_squote(b64: str) -> str:
    """base64 text is single-quote-safe (alphabet is [A-Za-z0-9+/=])."""
    return "'" + b64 + "'"


def _tar_b64_dir(path: Path, *, max_bytes: int) -> Tuple[str, int]:
    """gzip-tar the *contents* of ``path`` (flat files only) into base64, capped.

    Returns ``(b64, file_count)``; ``("", 0)`` when empty/absent. Crash
    reproducers are excluded (seed corpus only), mirroring ``seed_corpus``.
    """
    if not path or not path.is_dir():
        return "", 0
    buf = io.BytesIO()
    count = 0
    try:
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for f in sorted(path.glob("*")):
                if not f.is_file() or f.name.startswith("crash-"):
                    continue
                if buf.tell() >= max_bytes:
                    break
                tar.add(str(f), arcname=f.name)
                count += 1
    except Exception:
        return "", 0
    if count == 0:
        return "", 0
    return base64.b64encode(buf.getvalue()).decode(), count


def _extract_art(b64: str, into: Path) -> None:
    """Import only bounded regular artifacts into a new private directory.

    Never apply archive links, device nodes, ownership, or modes to the
    controller. Validate the whole archive before publishing any artifacts;
    invalid output is an explicit task failure, not a partial evidence set.
    """
    try:
        into = Path(into)
        if into.is_symlink() or not into.is_dir() or any(into.iterdir()):
            raise ValueError("artifact destination must be an empty private directory")
        if not isinstance(b64, str) or len(b64) > _ART_ENCODED_MAX_BYTES:
            raise ValueError("encoded artifact exceeds its limit")
        raw = base64.b64decode("".join(b64.split()), validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            expanded = compressed.read(_ART_EXPANDED_MAX_BYTES + 1)
        if len(expanded) > _ART_EXPANDED_MAX_BYTES:
            raise ValueError("expanded artifact exceeds its limit")
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            members = []
            seen = set()
            for member in archive:
                if len(members) >= _ART_MAX_MEMBERS:
                    raise ValueError("artifact has too many entries")
                path = PurePosixPath(member.name)
                if (not member.name or path.is_absolute() or ".." in path.parts
                        or "\\" in member.name or "\x00" in member.name
                        or not path.parts
                        or path in seen or not (member.isfile() or member.isdir())
                        or member.issparse()
                        or member.size < 0 or member.size > _ART_FILE_MAX_BYTES
                        or (member.isdir() and member.size)):
                    raise ValueError("artifact contains an unsafe or unsupported entry")
                seen.add(path)
                members.append((member, path))
            if not members:
                # A successful package run with no recorded reproducer emits
                # an ordinary empty tar archive.
                return
            # Staging is private and starts empty; no repository-controlled
            # symlinks can be traversed by these ordinary file writes.
            with tempfile.TemporaryDirectory(prefix="lotus-artifact-", dir=into.parent) as stage:
                for member, path in members:
                    target = Path(stage).joinpath(*path.parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        source = archive.extractfile(member)
                        if source is None:
                            raise ValueError("artifact file content is missing")
                        with source, target.open("xb") as output:
                            output.write(source.read(_ART_FILE_MAX_BYTES + 1))
                        target.chmod(0o600)
                        # Selection of the newest recorded artifact relies on
                        # its timestamp; file ownership and modes remain local.
                        os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
                os.replace(stage, into)
    except (OSError, EOFError, ValueError, OverflowError, tarfile.TarError, zlib.error) as exc:
        raise ValueError("Kubernetes artifact import rejected invalid or oversized output") from exc


def _frames(stdout: str, regex: re.Pattern) -> Dict[int, str]:
    return {int(m.group(1)): m.group(2) for m in regex.finditer(stdout or "")}


# ---------------------------------------------------------------------------
# Atheris (Python) -- the reference engine.
# ---------------------------------------------------------------------------
_ATHERIS_DOCKERFILE = """\
FROM {base}
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Atheris ships no wheel for some arches and must compile its native module
# against a libFuzzer-capable clang; install the distro clang and point at it.
RUN (command -v clang >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq clang)) || true
ENV CLANG_BIN=/usr/bin/clang
RUN pip install --quiet atheris
COPY . /src
WORKDIR /src
# Best-effort target install so 3rd-party deps are baked into the image; the
# actual (current) code is provided at run time via PYTHONPATH=/work.
RUN (pip install --quiet -e . 2>&1 | tail -5) || (pip install --quiet . 2>&1 | tail -5) || true
ENV PYTHONPATH=/src:/src/src
"""


async def build_atheris_image(repo_id: int, dest: Path, send=None) -> Tuple[Optional[str], str]:
    """kaniko-build (or reuse) the per-repo atheris deps image. Returns
    ``(image_ref, cache_status)`` where status is hit/built/build-failed."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_builder as kb

    key = dpe._repo_cache_key(repo_id, dest)
    host = await kb.ensure_registry(send=send, repo_id=repo_id)
    if not host:
        return None, "registry-unavailable"
    if await kb.image_exists(repo_id, "atheris", key):
        return kb.image_ref(host, repo_id, "atheris", key), "hit"
    if send:
        await send(repo_id, "▶ Building Atheris deps image (one-time per repo)...",
                   detail_id=f"{repo_id}-task-atheris")
    dockerfile = _ATHERIS_DOCKERFILE.format(base=dpe.ATHERIS_IMAGE)
    df = Path(dest) / "Dockerfile.lotus-atheris"
    di = Path(dest) / ".dockerignore"
    wrote_di = not di.exists()
    try:
        df.write_text(dockerfile)
        if wrote_di:
            di.write_text(".git\ndata\nnode_modules\n.venv\n")
    except Exception as exc:
        return None, f"context-write-failed: {exc}"
    try:
        ref = await kb.build_image(repo_id, "atheris", Path(dest), tag=key,
                                   dockerfile="Dockerfile.lotus-atheris",
                                   timeout=1800, send=send)
        return (ref, "built") if ref else (None, "build-failed")
    finally:
        for p, remove in ((df, True), (di, wrote_di)):
            if remove:
                try:
                    p.unlink()
                except Exception:
                    pass


def _fuzz_script(harnesses: List, seeds: Dict[int, str], *,
                 setup_lines: List[str], run_cmd) -> str:
    """In-pod bash shared by every libFuzzer-style engine.

    Copies the read-only source into the writable ``/work``, runs the engine's
    ``setup_lines`` (deps install / env), writes each harness (base64), then per
    harness seeds its corpus, runs it via ``run_cmd`` -- a
    ``(harness, corpus_dir) -> command`` callable -- and emits the framed engine
    output plus a ``tar`` of the harness's corpus + crash artifacts, so the host
    reconstructs exactly what the Docker bind mount would have exposed.
    """
    from backend import dynamic_explorer as dpe

    lines: List[str] = [
        "set +e",
        "cp -a /src/. /work/ 2>/dev/null || true",
        "cd /work",
    ]
    lines += list(setup_lines or [])
    lines.append("mkdir -p .lotus_harness")
    for h in harnesses:
        src_b64 = base64.b64encode(h.source.encode()).decode()
        lines.append(f"printf '%s' {_sh_squote(src_b64)} | base64 -d > .lotus_harness/{h.filename}")
    for i, h in enumerate(harnesses):
        cname = dpe._sanitize(h.entry.key())
        corpus = f".lotus_harness/corpus_{cname}"
        seed = seeds.get(i, "")
        lines.append(f"echo; echo __LOTUS_H_{i}__BEGIN__")
        lines.append("rm -f .lotus_harness/crash-* .lotus_harness/oom-* "
                     ".lotus_harness/leak-* .lotus_harness/timeout-* 2>/dev/null")
        lines.append(f"mkdir -p {corpus}")
        if seed:
            lines.append(f"printf '%s' {_sh_squote(seed)} | base64 -d 2>/dev/null "
                         f"| tar xzf - -C {corpus} 2>/dev/null || true")
        lines.append(run_cmd(h, corpus))
        lines.append(f"echo; echo __LOTUS_H_{i}__END__")
        lines.append(f"echo __LOTUS_ART_{i}__BEGIN__")
        lines.append(
            f"tar czf - -C /work {corpus} "
            f"$(ls .lotus_harness/crash-* .lotus_harness/oom-* .lotus_harness/leak-* 2>/dev/null) "
            f"2>/dev/null | base64")
        lines.append(f"echo; echo __LOTUS_ART_{i}__END__")
    lines.append("exit 0")
    return "\n".join(lines)


def _seed_corpus(repo_id: int, engine: str, harnesses: List
                 ) -> Tuple[Dict[int, str], int, Dict[int, Optional[Path]]]:
    """Build per-harness embedded seed tars from the persistent corpus store.
    Returns ``(seeds_by_index, total_seeded, persist_dirs_by_index)``."""
    from backend import dynamic_explorer as dpe
    seeds: Dict[int, str] = {}
    persists: Dict[int, Optional[Path]] = {}
    total = 0
    per_harness_cap = _SEED_EMBED_MAX_BYTES // max(1, len(harnesses))
    for i, h in enumerate(harnesses):
        persist = (dpe.persistent_corpus_dir(repo_id, engine, h.entry.key())
                   if dpe.PERSIST_CORPUS else None)
        persists[i] = persist
        if persist:
            b64, n = _tar_b64_dir(persist, max_bytes=per_harness_cap)
            if b64:
                seeds[i] = b64
                total += n
    return seeds, total, persists


def _harvest_harness(i: int, h, h_out: Dict[int, str], h_art: Dict[int, str],
                     persist: Optional[Path]) -> Tuple[str, Optional[str], int]:
    """Reconstruct one harness's ``(engine_output, reproducer_b64,
    new_corpus_count)`` from the framed pod stdout, mirroring the Docker
    bind-mount harvest (harvest new corpus back to the persistent store and read
    the newest crash reproducer)."""
    from backend import dynamic_explorer as dpe
    out = h_out.get(i, "")
    repro_b64: Optional[str] = None
    corpus_new = 0
    art = h_art.get(i, "")
    if art:
        with tempfile.TemporaryDirectory(prefix="lotus-fuzz-") as td:
            _extract_art(art, Path(td))
            hdir = Path(td) / ".lotus_harness"
            cname = dpe._sanitize(h.entry.key())
            corpus_new = dpe.harvest_corpus(hdir / f"corpus_{cname}", persist)
            repro_b64 = dpe._read_atheris_repro(hdir)
    return out, repro_b64, corpus_new


async def run_atheris_k8s(dest: Path, harnesses: List, fuzztime_s: int,
                          send=None, repo_id: int = 0):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_atheris`.

    Never raises: any infra failure degrades to a skipped result so the audit is
    never blocked (same contract as the Docker path)."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr

    result = dpe.ExplorationResult(language="python", engine="atheris")
    dest = Path(dest)
    for h in harnesses:
        result.harnesses.append({"target": h.entry.key(), "module": h.entry.package,
                                 "symbol": h.entry.symbol, "file": h.filename,
                                 "input_kind": h.entry.input_kind})
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no python entrypoints"}
        return result

    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result

    image, cache_status = await build_atheris_image(repo_id, dest, send)
    if not image:
        result.stats = {"status": "skipped",
                        "reason": f"k8s atheris image unavailable ({cache_status})"}
        return result

    seeds, corpus_seeded, persists = _seed_corpus(repo_id, "atheris", harnesses)
    for h in harnesses:
        if send:
            await send(repo_id, f"▶ Atheris fuzzing {h.entry.package}.{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-atheris")

    def _run_cmd(h, corpus: str) -> str:
        return (f"timeout {fuzztime_s + 20} python .lotus_harness/{h.filename} {corpus} "
                f"-max_total_time={fuzztime_s} -artifact_prefix=.lotus_harness/ 2>&1 | tail -60")

    script = _fuzz_script(harnesses, seeds, setup_lines=[], run_cmd=_run_cmd)
    job_timeout = len(harnesses) * (fuzztime_s + 60) + 420
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "atheris", image, script=script, workdir="/work",
        timeout=job_timeout, allow_egress=True,
        mem_limit=str(os.environ.get("LOTUS_K8S_FUZZ_MEM") or "3Gi"),
        cpu_limit="2", mem_request="512Mi", cpu_request="500m",
        writable_paths=["/work"], env={"HOME": "/tmp", "PYTHONPATH": "/work:/work/src"},
    )
    if rc == -1:
        result.stats = {"status": "skipped", "reason": "k8s atheris job failed to run",
                        "image_cache": cache_status}
        return result

    h_out = _frames(stdout, _H_RE)
    h_art = _frames(stdout, _ART_RE)
    crashes = corpus_new = 0
    for i, h in enumerate(harnesses):
        out, repro_b64, cn = _harvest_harness(i, h, h_out, h_art, persists.get(i))
        corpus_new += cn
        if await dpe._emit_atheris_result(result, h, out, repro_b64, fuzztime_s, send, repo_id):
            crashes += 1

    skipped = result.stats.get("skipped_targets", []) if isinstance(result.stats, dict) else []
    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "skipped_import_failed": len(skipped), "skipped_targets": skipped,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "image_cache": cache_status, "runtime": "k8s"}
    return result


# ---------------------------------------------------------------------------
# Jazzer.js (Node) -- same libFuzzer harness/corpus/reproducer model as Atheris.
# Unlike Python (global site-packages), Node deps live *in-tree* (node_modules),
# which the read-only source-PVC mount would shadow -- so, exactly like the
# Docker path (which has no node cache image either), dependencies are installed
# at run time into the writable /work. No kaniko image is built; the public
# node image runs directly.
# ---------------------------------------------------------------------------
async def run_node_k8s(dest: Path, harnesses: List, fuzztime_s: int,
                       send=None, repo_id: int = 0):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_node_fuzz`.

    Never raises: any infra failure degrades to a skipped result."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr

    result = dpe.ExplorationResult(language="node", engine="jazzer.js")
    dest = Path(dest)
    for h in harnesses:
        result.harnesses.append({"target": h.entry.key(), "module": h.entry.package,
                                 "symbol": h.entry.symbol, "file": h.filename,
                                 "input_kind": h.entry.input_kind})
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no node entrypoints"}
        return result
    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result

    seeds, corpus_seeded, persists = _seed_corpus(repo_id, "jazzer.js", harnesses)
    for h in harnesses:
        if send:
            await send(repo_id, f"▶ Jazzer.js fuzzing {h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-jazzerjs")

    # Best-effort target deps + Jazzer.js into the writable workspace (needs egress).
    setup = [
        "[ -f package.json ] && (npm install --no-audit --no-fund --silent 2>&1 | tail -5)",
        "npm install --no-audit --no-fund --silent --prefix /work/.jz @jazzer.js/core "
        "2>&1 | tail -5 || echo __INSTALL_BESTEFFORT__",
    ]

    def _run_cmd(h, corpus: str) -> str:
        stem = re.sub(r"\.js$", "", h.filename)
        return (f"timeout {fuzztime_s + 30} /work/.jz/node_modules/.bin/jazzer "
                f".lotus_harness/{stem} {corpus} -- -max_total_time={fuzztime_s} "
                f"-artifact_prefix=.lotus_harness/ 2>&1 | tail -60")

    script = _fuzz_script(harnesses, seeds, setup_lines=setup, run_cmd=_run_cmd)
    # Node's per-run npm install needs a wider slack than Atheris's baked image.
    job_timeout = len(harnesses) * (fuzztime_s + 90) + 600
    image = str(os.environ.get("LOTUS_NODE_IMAGE") or dpe.NODE_IMAGE)
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "jazzerjs", image, script=script, workdir="/work",
        timeout=job_timeout, allow_egress=True,
        mem_limit=str(os.environ.get("LOTUS_K8S_FUZZ_MEM") or "3Gi"),
        cpu_limit="2", mem_request="512Mi", cpu_request="500m",
        writable_paths=["/work"],
        env={"HOME": "/tmp", "npm_config_cache": "/tmp/.npm",
             "NODE_PATH": "/work/.jz/node_modules:/work/node_modules"},
    )
    if rc == -1:
        result.stats = {"status": "skipped", "reason": "k8s jazzer.js job failed to run"}
        return result

    h_out = _frames(stdout, _H_RE)
    h_art = _frames(stdout, _ART_RE)
    crashes = corpus_new = 0
    for i, h in enumerate(harnesses):
        out, repro_b64, cn = _harvest_harness(i, h, h_out, h_art, persists.get(i))
        corpus_new += cn
        if await dpe._emit_jazzerjs_result(result, h, out, repro_b64, fuzztime_s, send, repo_id):
            crashes += 1

    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "runtime": "k8s"}
    return result


# ---------------------------------------------------------------------------
# Native Go `go test -fuzz` -- unlike the libFuzzer engines, harnesses are
# written into their own package directory (so they can call unexported target
# symbols), the corpus/reproducers live under ``testdata/fuzz/<FuzzFunc>/``, and
# each harness runs a fuzz pass *and* a coverage pass framed by the shared
# ``__FUZZ_RC__``/``__COVER_RC__`` markers. Module downloads + the auto-fetched
# toolchain are expensive, so a persistent cross-audit module/build cache PVC is
# mounted at ``/go`` (the k8s equivalent of the Docker ``lotus-go-cache``
# volume); it degrades to an ephemeral emptyDir when the PVC cannot be created.
# ---------------------------------------------------------------------------
_GO_CACHE_PVC = os.environ.get("LOTUS_K8S_GO_CACHE_PVC", "lotus-go-cache")
_GO_CACHE_SIZE = os.environ.get("LOTUS_K8S_GO_CACHE_SIZE", "10Gi")


def _go_fuzz_script(harnesses: List, fuzztime_s: int) -> str:
    """In-pod bash for native Go fuzzing.

    Copies the read-only source into the writable ``/work``, writes each harness
    into its package directory, then per harness runs ``go test -fuzz`` followed
    by a coverage pass -- both framed with the ``__FUZZ_RC__``/``__COVER_RC__``
    return-code markers :func:`backend.dynamic_explorer._split_go_output`
    expects -- and finally emits a ``tar`` of that harness's
    ``testdata/fuzz/<FuzzFunc>/`` dir (the reproducer Go writes on a crash)."""
    lines: List[str] = [
        "set +e",
        # emptyDir's mount root belongs to root with a writable fsGroup. Archive
        # mode attempts to change that root's timestamps and fails for the
        # restricted UID even after a successful content copy.
        "cp -R /src/. /work/ || { echo 'Source workspace copy failed; no package tests were run' >&2; exit 73; }",
        # Sealed snapshots have read-only files/directories. The private copy
        # must accept generated inputs without changing /src or executable
        # bits. Never follow links or chmod the root-owned emptyDir mount.
        "find /work -mindepth 1 -type d -exec chmod u+rwx {} + || { echo 'Source workspace preparation failed; no package tests were run' >&2; exit 73; }",
        "find /work -mindepth 1 -type f -exec chmod u+rw {} + || { echo 'Source workspace preparation failed; no package tests were run' >&2; exit 73; }",
        "cd /work || exit 73",
        'export PATH="/usr/local/go/bin:$PATH"',
        "export GOTOOLCHAIN=local",
        "mkdir -p /go/gotmp",
        "GOPROXY=off GOSUMDB=off go list -m >/dev/null || { echo 'Captured Go module/toolchain prerequisites did not pass; no package tests were run' >&2; exit 69; }",
    ]
    for h in harnesses:
        src_b64 = base64.b64encode(h.source.encode()).decode()
        lines.append(f"mkdir -p {h.pkg_dir}")
        lines.append(f"printf '%s' {_sh_squote(src_b64)} | base64 -d > {h.pkg_dir}/{h.filename}")
    for i, h in enumerate(harnesses):
        relpkg = "./" + h.pkg_dir if h.pkg_dir != "." else "."
        cov = f"/work/.lotus_cover_{h.fuzz_func}.out"
        testdata = f"{h.pkg_dir}/testdata/fuzz/{h.fuzz_func}"
        lines.append(f"echo; echo __LOTUS_H_{i}__BEGIN__")
        lines.append(f"go test -parallel=1 -run='^$' -fuzz='^{h.fuzz_func}$' -fuzztime={fuzztime_s}s {relpkg} 2>&1")
        lines.append('fuzz_rc=$?; printf \'\\n__FUZZ_RC__=%s\\n\' "$fuzz_rc"')
        lines.append(f"go test -parallel=1 -run='^{h.fuzz_func}$' -coverprofile={cov} {relpkg} 2>&1")
        lines.append('cover_rc=$?; printf \'\\n__COVER_RC__=%s\\n\' "$cover_rc"')
        lines.append(f'if [ "$cover_rc" -eq 0 ] && [ -f {cov} ]; then go tool cover -func={cov} 2>&1 | tail -40; fi')
        lines.append(f"rm -f {cov}")
        lines.append(f"echo; echo __LOTUS_H_{i}__END__")
        lines.append(f"echo __LOTUS_ART_{i}__BEGIN__")
        lines.append(f"tar czf - -C /work {testdata} 2>/dev/null | base64")
        lines.append(f"echo; echo __LOTUS_ART_{i}__END__")
    lines.append("exit 0")
    return "\n".join(lines)


def _go_fuzz_environment(memory_mib: int) -> dict:
    """Bound build/fuzz fan-out and give each Go process a soft GC budget.

    Go's memory limit applies per process, not to the whole Pod. The driver,
    compiler and fuzz worker need separate headroom; cgroups remain the hard
    bound. This does not promise that an arbitrary target can fit the envelope.
    """
    if type(memory_mib) is not int or not 512 <= memory_mib <= 65536:
        raise ValueError("Go fuzz memory must be an integer from 512 to 65536 MiB")
    return {"HOME": "/tmp", "GOFLAGS": "-buildvcs=false -p=1", "GOPATH": "/go",
            "GOMODCACHE": "/go/pkg/mod", "GOCACHE": "/go/cache",
            "GOTMPDIR": "/go/gotmp", "TMPDIR": "/go/gotmp", "GOTOOLCHAIN": "local",
            "GOMAXPROCS": "2", "GOMEMLIMIT": f"{memory_mib // 3}MiB"}


def _go_prerequisite_diagnostic(stderr: str, code: int) -> str:
    """Expose actionable error classes without echoing source-derived secrets."""
    if code == 73:
        for marker, explanation in (
            ("No space left on device", "The writable source volume has insufficient space."),
            ("Read-only file system", "The source destination is mounted read-only."),
            ("Permission denied", "The restricted user cannot write the source destination."),
            ("Operation not permitted", "The source copy requested metadata changes the restricted user cannot perform."),
        ):
            if marker in stderr:
                return explanation
        return "The source copy or workspace selection failed; check source delivery and writable volume permissions."
    version = re.search(r"requires go >= ([0-9.]+).*?running go ([0-9.]+)", stderr)
    if version:
        return f"Captured module requires Go >= {version[1]}; installed Go is {version[2]}."
    return "The captured Go module/workspace was rejected by the installed compiler; check module syntax and the required Go version."


def _harvest_go_repro(art_b64: str, h) -> Optional[str]:
    """Read the newest reproducer Go wrote under ``testdata/fuzz/<FuzzFunc>/``
    from the harvested artifact tar (the k8s analogue of
    :func:`backend.dynamic_explorer._read_go_repro`, which reads it from disk)."""
    if not art_b64:
        return None
    with tempfile.TemporaryDirectory(prefix="lotus-go-") as td:
        _extract_art(art_b64, Path(td))
        d = Path(td) / h.pkg_dir / "testdata" / "fuzz" / h.fuzz_func
        try:
            files = sorted([p for p in d.iterdir() if p.is_file()],
                           key=lambda p: -p.stat().st_mtime)
            if files:
                return base64.b64encode(files[0].read_bytes()).decode()
        except Exception:
            pass
    return None


async def run_go_k8s(dest: Path, harnesses: List, fuzztime_s: int,
                     send=None, repo_id: int = 0):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_go_fuzz`.

    Infrastructure failures remain explicit; incomplete jobs cannot attest harness execution."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr
    from backend.ext_analyzers import prepared_go_image, AnalyzerUnavailable

    result = dpe.ExplorationResult(language="go", engine="go-native-fuzz")
    dest = Path(dest)
    for h in harnesses:
        result.harnesses.append({
            "target": h.entry.key(), "fuzz_func": h.fuzz_func,
            "pkg_dir": h.pkg_dir, "file": h.filename, "input_kind": h.entry.input_kind,
        })
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no go entrypoints"}
        return result
    from backend import analyzer_resources as resources
    policy = resources.selected_tool("gofuzz")
    if policy is None:
        # Audits and their retries must supply the captured policy. Standalone
        # operational helpers retain explicit environment/default behavior.
        policy = next(row for row in resources.snapshot_policy({})["tools"] if row["id"] == "gofuzz")
        if resources.AUDIT_CONTEXT.get() is not None:
            policy.update(state="configuration_invalid", reason="This audit did not capture Go fuzz resources; a new explicit task policy is required")
    policy = await resources.refresh_tool_admission(policy)

    async def resource_block(reason, diagnostic=None):
        result.stats = {"status": "skipped" if policy.get("state") in {"user_disabled", "capability_disabled"} else "failed",
                        "reason": reason, "runtime": "k8s", "harnesses_planned": len(harnesses),
                        "harnesses_run": None, "harnesses_verified": 0,
                        **resources.task_resource_metadata("gofuzz", policy, reason, diagnostic=diagnostic)}
        if send:
            await send(repo_id, reason, level="warning", detail_id=f"{repo_id}-task-gofuzz",
                       detail={"kind": "resource-blocked", **result.stats})
        return result

    if policy.get("state") not in {"ready", "unknown"}:
        return await resource_block(policy.get("reason") or "Go fuzz resources are not available")
    try:
        envelope = resources.go_fuzz_envelope(policy, len(harnesses) * (fuzztime_s + 180) + 600)
    except (ValueError, TypeError) as exc:
        return await resource_block(str(exc))
    try:
        image = await prepared_go_image(True)
    except AnalyzerUnavailable as error:
        result.stats = {"status": "skipped", "reason": str(error)}
        return result
    script = _go_fuzz_script(harnesses, fuzztime_s)
    environment = _go_fuzz_environment(int(policy["effective"]["memory_mb"]))
    execution = resources.execution_identity("gofuzz", image, ".", script, environment, envelope)
    previous = resources.prior_resource_failure(execution)
    if previous:
        return await resource_block("This exact Go fuzz workload and resource envelope previously ended with a verified Pod OOMKilled. "
                                    "Configure sufficient memory and capacity before explicitly retrying this task; coverage remains incomplete.", previous["diagnostic"])
    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result

    # Shared, persistent Go module/build cache (falls back to an ephemeral
    # emptyDir /go when the PVC cannot be provisioned).
    cache = await kr.ensure_cache_pvc(_GO_CACHE_PVC, size=_GO_CACHE_SIZE)
    cache_pvc = (cache, "/go") if cache else None
    writable = ["/work"] if cache else ["/work", "/go"]

    # This is one sequential Job. The fuzz duration excludes dependency
    # downloads, compilation and coverage; report its execution budget after admission.
    job_timeout = envelope["timeout_seconds"]
    if send:
        await send(repo_id, f"Go fuzz job queued: {len(harnesses)} harnesses run sequentially; "
                            f"{fuzztime_s}s fuzz budget each after build, "
                            f"up to {job_timeout}s execution after Pod startup, including setup and coverage; "
                            "one package build and one fuzz worker at a time; "
                            "resource queue time has a separate bounded allowance.",
                   detail_id=f"{repo_id}-task-gofuzz")
    for index, h in enumerate(harnesses, 1):
        if send:
            await send(repo_id, f"◌ Parse path {index}/{len(harnesses)} {h.entry.symbol} "
                                f"({h.entry.input_kind}) queued for the sequential Go job",
                       detail_id=f"{repo_id}-task-gofuzz")

    # Reuse the installed compiler that passed native readiness. Repository
    # dependencies still need resolution, but compilers are never bootstrapped
    # during an audit and the captured module is checked before package tests.
    memory_limit = envelope["mem_limit"]
    diagnostics = []
    resource_envelope = {"memory_limit": memory_limit, "memory_request": envelope["mem_request"],
                         "cpu_limit": "2", "cpu_request": "500m", "timeout_seconds": job_timeout,
                         "queue_timeout_seconds": envelope["queue_timeout_seconds"], "memory_unit": "MiB",
                         "build_parallelism": 1, "fuzz_parallelism": 1,
                         "gomaxprocs": 2, "go_process_soft_memory_limit": environment["GOMEMLIMIT"]}
    def capture_diagnostic(value):
        diagnostic = dict(value)
        if execution:
            diagnostic.update({key: execution[key] for key in (
                "scan_job_id", "target_tree_hash", "target_revision", "target_path", "scope_hash")})
        diagnostics.append(diagnostic)
        try:
            resources.record_resource_failure(execution, diagnostic)
        except OSError:
            diagnostic["receipt_persisted"] = False
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "gofuzz", image, script=script, workdir="/work",
        timeout=job_timeout, allow_egress=True,
        mem_limit=memory_limit,
        cpu_limit="2", mem_request=envelope["mem_request"], cpu_request="500m",
        queue_timeout=envelope["queue_timeout_seconds"],
        writable_paths=writable, cache_pvc=cache_pvc, send=send, diagnostic_sink=capture_diagnostic,
        env=environment,
    )
    if rc in {69, 73}:
        stage = "source-copy" if rc == 73 else "go-module-toolchain"
        reason = ("Captured source could not be copied into its writable workspace; no package tests ran"
                  if rc == 73 else "Installed Go compiler or captured module prerequisites failed; no package tests ran")
        result.stats = {"status": "failed", "reason": reason, "prerequisite_stage": stage, "runtime": "k8s"}
        if send:
            await send(repo_id, reason, level="warning", detail_id=f"{repo_id}-task-gofuzz",
                       detail={"kind": "prerequisite-failure", "stage": stage, "exit_code": rc,
                               "diagnostic": _go_prerequisite_diagnostic(_stderr or "", rc), "package_tests_run": 0})
        return result
    if rc != 0:
        # A terminated outer job cannot prove how many sequential harnesses
        # executed. Do not fabricate per-harness failures or successful coverage
        # from missing frames. Resource diagnoses come only from owned Pod status,
        # never target-controlled output or exit 137 alone.
        diagnostic = diagnostics[-1] if diagnostics else {}
        if not (diagnostic.get("ownership_verified") is True
                and diagnostic.get("provider") == "kubernetes"
                and diagnostic.get("repo_id") == repo_id
                and diagnostic.get("tool_id") == "gofuzz"
                and diagnostic.get("image") == image
                and diagnostic.get("memory_request") == envelope["mem_request"]
                and diagnostic.get("memory_limit") == memory_limit):
            diagnostic = {}
        classification = diagnostic.get("classification")
        reason = ("k8s go fuzz job failed to run" if rc == -1 else
                  f"Go fuzz job exited with code {rc}; harness execution and coverage could not be verified")
        if classification == "oom_killed":
            reason = (f"Go fuzz Pod was OOMKilled with a {memory_limit} memory limit; harness execution and coverage "
                      "could not be verified. Configure Go fuzz memory in Settings (MiB), confirm node capacity, "
                      "and explicitly retry this task when recovery is available.")
        elif classification == "queue_timeout":
            reason = "Go fuzz job exceeded its resource queue allowance; check node capacity, quota, images and volumes before retrying"
        elif rc == 124:
            reason = "Go fuzz job timed out; harness execution and coverage could not be verified"
        # An ordinary process failure has not established a resource cause.
        # Only owned resource classifications may offer resource recovery or
        # participate in the operator's explicit incomplete-resource policy.
        metadata = (resources.task_resource_metadata("gofuzz", policy, reason, failed=True, diagnostic=diagnostic)
                    if classification in {"oom_killed", "queue_timeout", "execution_timeout", "evicted"}
                    else {"runtime_diagnostic": diagnostic} if diagnostic else {})
        result.stats = {"status": "skipped" if rc == -1 else "failed", "reason": reason,
                        "runtime": "k8s", "exit_code": rc, "harnesses_planned": len(harnesses),
                        "harnesses_run": None, "harnesses_verified": 0,
                        "resource_envelope": resource_envelope,
                        **metadata}
        if send and rc != -1:
            await send(repo_id, reason, level="warning", detail_id=f"{repo_id}-task-gofuzz",
                       detail={"kind": "runtime-failure", **result.stats})
        return result

    h_out = _frames(stdout, _H_RE)
    h_art = _frames(stdout, _ART_RE)
    crashes = 0
    harness_failures: List[Dict] = []
    inconclusive: List[Dict] = []
    for i, h in enumerate(harnesses):
        out = h_out.get(i, "")
        art = h_art.get(i, "")
        if await dpe._emit_go_result(result, h, out=out, outer_rc=0, fuzztime_s=fuzztime_s,
                                     harness_failures=harness_failures, inconclusive=inconclusive,
                                     repro_provider=lambda art=art, h=h: _harvest_go_repro(art, h),
                                     send=send, repo_id=repo_id):
            crashes += 1

    result.stats = {
        "status": "failed" if harness_failures else ("inconclusive" if inconclusive else "completed"),
        "harnesses_run": len(harnesses), "crashes": crashes, "fuzztime_s": fuzztime_s,
        "harness_failures": harness_failures, "inconclusive": inconclusive,
        "runtime": "k8s",
        "resource_envelope": resource_envelope,
    }
    return result


# ---------------------------------------------------------------------------
# Jazzer (JVM) -- same libFuzzer harness/corpus/reproducer model as Atheris and
# Jazzer.js, so it reuses the shared ``_fuzz_script`` substrate. The target is
# compiled (maven/gradle) once in ``setup_lines`` to obtain its classpath, the
# Jazzer release is fetched for the pod's *native* arch, and each harness is
# ``javac``-compiled then driven by the ``jazzer`` launcher.
#
# Unlike the Docker path (which pins ``--platform linux/amd64`` and runs Jazzer's
# x86_64-only launcher under qemu), the k8s engine runs on the node's own arch:
# current Jazzer releases ship ``jazzer-linux-{x86-64,arm64}.tar.gz``, so an
# arm64 kind node fuzzes natively. The maven/gradle dependency repos are cached
# on a shared cross-audit PVC (the analogue of the Docker per-repo cache image).
# ---------------------------------------------------------------------------
_JVM_CACHE_PVC = os.environ.get("LOTUS_K8S_JVM_CACHE_PVC", "lotus-jvm-cache")
_JVM_CACHE_SIZE = os.environ.get("LOTUS_K8S_JVM_CACHE_SIZE", "10Gi")
# Jazzer's x86_64-only ``jazzer-linux.tar.gz`` predates arm64 support; the k8s
# engine needs a per-arch release, so it defaults to a version that ships
# ``jazzer-linux-arm64.tar.gz`` (overridable via LOTUS_JAZZER_VERSION).
_JAZZER_K8S_VERSION = os.environ.get("LOTUS_JAZZER_VERSION") or "0.30.0"


def _jvm_setup_lines(build: str, jzver: str, m2repo: str, ghome: str) -> List[str]:
    """One-time in-pod setup: build the target for its classpath, then fetch the
    arch-matched Jazzer release into the writable workspace."""
    if build == "maven":
        build_lines = [
            f"mvn -q -Dmaven.repo.local={m2repo} -DskipTests compile 2>&1 | tail -5",
            f"mvn -q -Dmaven.repo.local={m2repo} dependency:build-classpath "
            "-Dmdep.outputFile=/tmp/cp.txt 2>&1 | tail -3",
            "export PROJCP=target/classes:$(cat /tmp/cp.txt 2>/dev/null)",
        ]
    else:  # gradle
        build_lines = [
            f"export GRADLE_USER_HOME={ghome}",
            "(./gradlew -q compileJava 2>&1 | tail -5 || "
            "gradle -q compileJava 2>&1 | tail -5)",
            "export PROJCP=build/classes/java/main:"
            "$(find . -name '*.jar' 2>/dev/null | tr '\\n' ':')",
        ]
    return build_lines + [
        'ARCH=$(uname -m); case "$ARCH" in aarch64|arm64) JZA=arm64 ;; *) JZA=x86-64 ;; esac',
        f'JZBASE="https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v{jzver}"',
        'curl -sSLf "$JZBASE/jazzer-linux-${JZA}.tar.gz" -o /tmp/j.tgz 2>/dev/null '
        '|| curl -sSLf "$JZBASE/jazzer-linux.tar.gz" -o /tmp/j.tgz 2>/dev/null '
        '|| echo __JAZZER_DL_FAIL__',
        "mkdir -p /work/.jazzer && tar xzf /tmp/j.tgz -C /work/.jazzer 2>/dev/null "
        "&& chmod +x /work/.jazzer/jazzer 2>/dev/null",
    ]


async def run_jvm_k8s(dest: Path, harnesses: List, fuzztime_s: int,
                      send=None, repo_id: int = 0):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_jvm_fuzz`.

    Never raises: any infra failure degrades to a skipped result."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr

    result = dpe.ExplorationResult(language="java", engine="jazzer")
    dest = Path(dest)
    for h in harnesses:
        result.harnesses.append({"target": h.entry.key(), "class": h.entry.package,
                                 "symbol": h.entry.symbol, "file": h.filename,
                                 "input_kind": h.entry.input_kind})
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no java entrypoints"}
        return result
    build = dpe._detect_jvm_build(dest)
    if not build:
        result.stats = {"status": "skipped", "reason": "no maven/gradle build detected"}
        return result
    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result

    # Shared, persistent maven/gradle dependency cache (falls back to an
    # ephemeral writable dir when the PVC cannot be provisioned).
    cache = await kr.ensure_cache_pvc(_JVM_CACHE_PVC, size=_JVM_CACHE_SIZE)
    cache_pvc = (cache, "/cache") if cache else None
    writable = ["/work"] if cache else ["/work", "/cache"]
    m2repo = "/cache/m2" if cache else "/tmp/.m2"
    ghome = "/cache/gradle" if cache else "/tmp/.gradle"

    seeds, corpus_seeded, persists = _seed_corpus(repo_id, "jazzer", harnesses)
    for h in harnesses:
        if send:
            await send(repo_id, f"▶ Jazzer (JVM) fuzzing {h.entry.package}.{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-jazzer")

    setup = _jvm_setup_lines(build, _JAZZER_K8S_VERSION, m2repo, ghome)

    def _run_cmd(h, corpus: str) -> str:
        cls = re.sub(r"\.java$", "", h.filename)
        return (f"javac -cp /work/.jazzer/jazzer_standalone.jar:$PROJCP -d .lotus_harness "
                f".lotus_harness/{h.filename} 2>&1 | tail -20; "
                f"timeout {fuzztime_s + 40} /work/.jazzer/jazzer --cp=.lotus_harness:$PROJCP "
                f"--target_class={cls} {corpus} -max_total_time={fuzztime_s} "
                f"-artifact_prefix=.lotus_harness/ 2>&1 | tail -60")

    script = _fuzz_script(harnesses, seeds, setup_lines=setup, run_cmd=_run_cmd)
    # A cold maven/gradle build (deps download) can be slow; give generous slack
    # on top of the per-harness compile+fuzz budget.
    job_timeout = len(harnesses) * (fuzztime_s + 90) + 1200
    image = str(os.environ.get("LOTUS_JVM_IMAGE") or dpe.JVM_IMAGE)
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "jazzer", image, script=script, workdir="/work",
        timeout=job_timeout, allow_egress=True,
        mem_limit=str(os.environ.get("LOTUS_K8S_FUZZ_MEM") or "4Gi"),
        cpu_limit="2", mem_request="1Gi", cpu_request="500m",
        writable_paths=writable, cache_pvc=cache_pvc,
        env={"HOME": "/tmp", "GRADLE_USER_HOME": ghome,
             "MAVEN_OPTS": f"-Dmaven.repo.local={m2repo}"},
    )
    if rc == -1:
        result.stats = {"status": "skipped", "reason": "k8s jazzer job failed to run",
                        "build": build}
        return result

    h_out = _frames(stdout, _H_RE)
    h_art = _frames(stdout, _ART_RE)
    crashes = corpus_new = 0
    for i, h in enumerate(harnesses):
        out, repro_b64, cn = _harvest_harness(i, h, h_out, h_art, persists.get(i))
        corpus_new += cn
        if await dpe._emit_jazzer_result(result, h, out, repro_b64, fuzztime_s,
                                         send, repo_id):
            crashes += 1

    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s, "build": build,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "runtime": "k8s"}
    return result


# ---------------------------------------------------------------------------
# Ruby (coverage-guided) -- a self-contained mutational driver built on the
# stdlib ``Coverage`` module (no native/libFuzzer build), so it runs in a plain
# ruby image and reuses the shared ``_fuzz_script`` substrate. The synthesized
# harness ``require``s the target via an absolute ``/src/...`` path, which still
# resolves against the read-only source mount (``require`` only reads). A
# best-effort ``bundle install`` into the writable workspace covers targets with
# a Gemfile; a missing/failed bundle just surfaces as a benign load-skip.
# ---------------------------------------------------------------------------
async def run_ruby_k8s(dest: Path, harnesses: List, fuzztime_s: int,
                       send=None, repo_id: int = 0):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_ruby_fuzz`.

    Never raises: any infra failure degrades to a skipped result."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr

    result = dpe.ExplorationResult(language="ruby", engine="ruby-cov")
    dest = Path(dest)
    for h in harnesses:
        result.harnesses.append({"target": h.entry.key(), "receiver": h.entry.package,
                                 "symbol": h.entry.symbol, "file": h.filename,
                                 "input_kind": h.entry.input_kind})
    if not harnesses:
        result.stats = {"status": "skipped", "reason": "no ruby entrypoints"}
        return result
    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result

    seeds, corpus_seeded, persists = _seed_corpus(repo_id, "ruby-cov", harnesses)
    for h in harnesses:
        if send:
            await send(repo_id, f"▶ Ruby (coverage-guided) fuzzing "
                                f"{(h.entry.package + '.') if h.entry.package else ''}{h.entry.symbol} "
                                f"({h.entry.role}) for {fuzztime_s}s ...",
                       detail_id=f"{repo_id}-task-ruby")

    # Best-effort bundle install into the writable workspace (the read-only root
    # fs cannot host the default gem home). ``bundle exec`` puts the isolated
    # bundle on the load path when a Gemfile is present.
    has_gemfile = (dest / "Gemfile").exists()
    setup: List[str] = []
    if has_gemfile:
        setup = [
            "bundle config set --local path /work/.bundle 2>/dev/null || true",
            "bundle install --quiet 2>&1 | tail -3 || echo __BUNDLE_BESTEFFORT__",
        ]
    ruby = "bundle exec ruby" if has_gemfile else "ruby"

    def _run_cmd(h, corpus: str) -> str:
        return (f"LOTUS_RUBY_MAXTIME={fuzztime_s} timeout {fuzztime_s + 40} {ruby} "
                f".lotus_harness/{h.filename} {corpus} .lotus_harness 2>&1 | tail -60")

    script = _fuzz_script(harnesses, seeds, setup_lines=setup, run_cmd=_run_cmd)
    job_timeout = len(harnesses) * (fuzztime_s + 90) + 600
    image = str(os.environ.get("LOTUS_RUBY_IMAGE") or dpe.RUBY_IMAGE)
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "ruby", image, script=script, workdir="/work",
        timeout=job_timeout, allow_egress=True,
        mem_limit=str(os.environ.get("LOTUS_K8S_FUZZ_MEM") or "2Gi"),
        cpu_limit="2", mem_request="256Mi", cpu_request="250m",
        writable_paths=["/work"],
        env={"HOME": "/tmp", "BUNDLE_USER_HOME": "/work/.bundle",
             "BUNDLE_APP_CONFIG": "/work/.bundle"},
    )
    if rc == -1:
        result.stats = {"status": "skipped", "reason": "k8s ruby job failed to run"}
        return result

    h_out = _frames(stdout, _H_RE)
    h_art = _frames(stdout, _ART_RE)
    crashes = skipped_load = corpus_new = 0
    for i, h in enumerate(harnesses):
        out, repro_b64, cn = _harvest_harness(i, h, h_out, h_art, persists.get(i))
        corpus_new += cn
        status = await dpe._emit_ruby_result(result, h, out, repro_b64,
                                             fuzztime_s, send, repo_id)
        if status == "crash":
            crashes += 1
        elif status == "load_failed":
            skipped_load += 1

    result.stats = {"status": "completed", "harnesses_run": len(harnesses),
                    "crashes": crashes, "fuzztime_s": fuzztime_s,
                    "skipped_load_failed": skipped_load,
                    "corpus_seeded": corpus_seeded, "corpus_new": corpus_new,
                    "runtime": "k8s"}
    return result


# ---------------------------------------------------------------------------
# KLEE (C/C++ symbolic execution) -- a single-shot compile+run, not a per-harness
# libFuzzer loop, so it does not use the ``_fuzz_script`` substrate. The target
# is compiled to LLVM bitcode (``clang -emit-llvm``) and symbolically executed;
# KLEE writes ``klee-out-*``/``klee-last`` into the writable workspace and prints
# path stats + ``KLEE: ERROR:`` lines that :func:`parse_klee_output` parses. No
# egress is needed (no deps to fetch). The Docker ``--ulimit stack=-1`` has no
# portable pod-spec equivalent, so a best-effort ``ulimit -s`` is set in-script.
# ---------------------------------------------------------------------------
async def run_klee_k8s(dest: Path, target_c_rel: str, entry_func: str = "main",
                       max_time_s: int = 120, send=None, repo_id: int = 0,
                       driver_source: Optional[str] = None):
    """Kubernetes port of :func:`backend.dynamic_explorer.run_klee`.

    When ``driver_source`` is given it is written into the writable ``/work``
    copy and compiled with ``-I /work`` so its ``#include "<repo-rel target>"``
    resolves. Never raises: any infra failure degrades to a skipped result."""
    from backend import dynamic_explorer as dpe
    from backend import k8s_runtime as kr

    result = dpe.ExplorationResult(language="c/cpp", engine="klee")
    dest = Path(dest)
    if not await kr.ensure_source_pvc(repo_id, dest, send):
        result.stats = {"status": "skipped", "reason": "k8s source volume unavailable"}
        return result
    if send:
        await send(repo_id, f"▶ KLEE symbolic execution on {target_c_rel} ({max_time_s}s)...",
                   detail_id=f"{repo_id}-task-klee")

    bc = "/work/lotus_klee.bc"
    if driver_source is not None:
        import base64 as _b64mod
        _drv = "/work/lotus_klee_driver.c"
        _b64 = _b64mod.b64encode(driver_source.encode()).decode()
        _compile = (
            f"echo '{_b64}' | base64 -d > {_drv}; "
            f"clang -I /usr/local/include -I /work -emit-llvm -c -g -O0 "
            f"-Xclang -disable-O0-optnone '{_drv}' -o {bc}"
        )
    else:
        _compile = (
            f"clang -I /usr/local/include -emit-llvm -c -g -O0 "
            f"-Xclang -disable-O0-optnone '{target_c_rel}' -o {bc}"
        )
    script = (
        "set +e; ulimit -s unlimited 2>/dev/null || true; "
        "cp -a /src/. /work/ 2>/dev/null || true; cd /work; "
        f"{_compile} 2>&1 || {{ echo __COMPILE_FAIL__; exit 0; }}; "
        f"klee --only-output-states-covering-new --max-time={max_time_s}s "
        f"--libc=uclibc --posix-runtime {bc} 2>&1 | tail -60; "
        f"echo __KLEE_DONE__"
    )
    image = str(os.environ.get("LOTUS_KLEE_IMAGE") or dpe.KLEE_IMAGE)
    # activeDeadlineSeconds bounds the *whole* pod lifetime including the image
    # pull; the klee/klee toolchain image is large, so give generous slack for a
    # cold pull on top of the symbolic-execution budget.
    stdout, _stderr, rc = await kr.run_to_completion(
        repo_id, "klee", image, script=script, workdir="/work",
        timeout=max_time_s + 1500, allow_egress=False,
        mem_limit=str(os.environ.get("LOTUS_K8S_KLEE_MEM") or "4Gi"),
        cpu_limit="2", mem_request="512Mi", cpu_request="500m",
        writable_paths=["/work"], env={"HOME": "/tmp"},
    )
    if rc == -1:
        result.stats = {"status": "skipped", "reason": "k8s klee job failed to run"}
        return result

    result.stats = dpe.parse_klee_output(stdout)
    result.stats["compile_failed"] = "__COMPILE_FAIL__" in stdout
    result.stats["status"] = ("failed" if result.stats["compile_failed"]
                              else "completed" if "__KLEE_DONE__" in stdout else "failed")
    if result.stats["compile_failed"]:
        result.stats["reason"] = "target did not compile to LLVM bitcode"
    result.stats["runtime"] = "k8s"
    dpe._emit_klee_findings(result, target_c_rel)
    return result
