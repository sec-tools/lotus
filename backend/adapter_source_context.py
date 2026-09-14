"""Bounded, source-only setup context for the native adapter planner.

Selection is an aid to interpretation, never evidence that a component can run.
The caller must bracket this function with the captured tree identity check.
Only the captured inventory is eligible; references never authorize another read.
No package manager, application, shell command, import, or template is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import tomllib
from types import MappingProxyType

from backend.proof_receipts import source_content_files

@dataclass(frozen=True, init=False)
class SourceContextInventory:
    """Invocation-local captured paths, never a cache or permission to read.

    Every content reader still checks its path at the time of use. The caller
    must retain fresh full-tree identity checks around context construction.
    Separate helper calls create fresh inventories unless the caller supplies
    this exact root-bound object for one context preparation.
    """
    root: Path
    paths: object

    def __init__(self, source):
        root = Path(source).resolve()
        paths = {}
        for path in source_content_files(root):
            try:
                paths[path.relative_to(root).as_posix()] = path
            except ValueError:
                continue
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "paths", MappingProxyType(paths))


def _context_paths(root, inventory):
    if inventory is None:
        inventory = SourceContextInventory(root)
    if type(inventory) is not SourceContextInventory or inventory.root != root:
        raise ValueError("Context inventory does not belong to this source root")
    return inventory.paths


MAX_FILES = 32
MAX_EXCERPT_BYTES = 6000
MAX_FILE_BYTES = 1024 * 1024
MAX_INSPECTED_FILES = 256
MAX_INSPECTED_BYTES = 8 * 1024 * 1024
MAX_MANIFESTS = 160
MAX_MANIFEST_INSPECTION_BYTES = 4 * 1024 * 1024
_MANIFESTS = {
    "package.json", "pyproject.toml", "setup.cfg", "requirements.txt", "go.mod",
    "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "gemfile",
    "composer.json", "cmakelists.txt", "configure.ac", "configure.in",
}
_TOOLCHAIN = {
    ".nvmrc", ".node-version", ".python-version", ".ruby-version", ".tool-versions",
    "rust-toolchain.toml", "rust-toolchain", "global.json", "pnpm-workspace.yaml",
    "pnpm-workspace.yml", "lerna.json", "nx.json", "makefile", "gnumakefile",
    "meson.build", "bootstrap", "bootstrap.sh", "autogen.sh",
}
_LOCKS = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "uv.lock", "poetry.lock",
          "cargo.lock", "gemfile.lock", "composer.lock"}
_SOURCE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".py", ".go", ".rs", ".rb", ".ru", ".php", ".cs", ".sh"}
_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".properties", ".py", ".js", ".ts"}
_SECRET = re.compile(r"(?:^|[._-])(?:secrets?|credentials?|passwords?)(?:[._-]|$)", re.I)
_DOC_NAMES = re.compile(r"(?:readme|install|getting.started|quickstart|development.setup|configuration|runtime.architecture)", re.I)


def _safe_name(name: str) -> bool:
    if not isinstance(name, str) or not name or len(name) > 1000 or "\\" in name:
        return False
    path = PurePosixPath(name)
    return (not path.is_absolute() and not any(part in {"", ".", ".."} for part in name.split("/"))
            and not any(ord(char) < 32 or ord(char) == 127 for char in name)
            and not any(part.lower() in {".git", ".lotus", ".lotus-local", "node_modules", "vendor", "secrets", "credentials"}
                        or part.lower().startswith(".env") or _SECRET.search(part) for part in path.parts)
            and path.name.lower() not in {"id_rsa", "id_ed25519", "id_ecdsa", ".npmrc", ".pypirc"}
            and path.suffix.lower() not in {".pem", ".key", ".p12", ".pfx", ".crt", ".sqlite", ".db"})


def _is_manifest(name: str) -> bool:
    path = PurePosixPath(name)
    return path.name.lower() in _MANIFESTS or path.suffix.lower() in {".csproj", ".fsproj"}


def _is_config(name: str) -> bool:
    path = PurePosixPath(name)
    if path.suffix.lower() not in _CONFIG_SUFFIXES:
        return False
    lower = path.name.lower()
    return (lower.startswith(("config.", "settings.", "application.", "appsettings.", "defaults."))
            or lower in {"defaults.json", "defaults.yaml", "defaults.yml", "defaults.toml",
                         "config.json", "config.yaml", "config.yml", "config.toml", "settings.py"})


def _is_doc(name: str) -> bool:
    path = PurePosixPath(name)
    return path.suffix.lower() in {".md", ".rst", ".txt", ""} and bool(_DOC_NAMES.search(path.name))


def _is_docker(name: str) -> bool:
    lower = PurePosixPath(name).name.lower()
    return lower.startswith("dockerfile") or lower in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}


def _excerpt(raw: bytes) -> dict:
    """Full-file hash, with UTF-8 head/tail byte ranges and explicit omissions."""
    if len(raw) <= MAX_EXCERPT_BYTES:
        return {"sha256": hashlib.sha256(raw).hexdigest(), "excerpt": raw.decode("utf-8"),
                "file_bytes": len(raw), "excerpt_ranges": [[0, len(raw)]], "omitted_bytes": 0}
    # Reserve marker bytes; UTF-8 decoding must not invent replacement characters.
    head = raw[:3900].decode("utf-8", errors="ignore").encode("utf-8")
    tail = raw[-1900:].decode("utf-8", errors="ignore").encode("utf-8")
    omitted = len(raw) - len(head) - len(tail)
    marker = f"\n[Lotus excerpt: {omitted} source bytes omitted between these ranges; full-file SHA256 supplied]\n".encode()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "excerpt": (head + marker + tail).decode("utf-8"),
            "file_bytes": len(raw), "excerpt_ranges": [[0, len(head)], [len(raw) - len(tail), len(raw)]],
            "omitted_bytes": omitted}


def _directory_owner(directory: tuple, manifest_dirs: set, owners: dict):
    """Memoize only literal path topology, never filesystem observations."""
    pending = []
    current = directory
    while current not in owners:
        pending.append(current)
        if current in manifest_dirs:
            owner = current
            break
        if not current:
            owner = None
            break
        current = current[:-1]
    else:
        owner = owners[current]
    for prefix in pending:
        owners[prefix] = owner
    return owner


def _component_neighborhoods(names: list[str], manifests: list[str]) -> dict:
    """Group files by their nearest captured manifest directory in O(N*depth).

    A strict descendant manifest excludes its files from a parent's context.
    This is the same rule as testing every other manifest for every file; the
    call-local index avoids those repeated comparisons and PurePath objects.
    """
    manifest_dirs = {PurePosixPath(name).parts[:-1] for name in manifests}
    owners = {}
    groups = {}
    for name in names:
        owner = _directory_owner(PurePosixPath(name).parts[:-1], manifest_dirs, owners)
        if owner is not None:
            groups.setdefault(owner, []).append(name)
    return {PurePosixPath(*owner): rows for owner, rows in groups.items()}


def bounded_build_context(source: Path, *, inventory=None) -> list[dict]:
    """Choose at most 32 setup files / 192,000 excerpt bytes deterministically.

    Root toolchain and workspace facts are reserved, then meaningful component
    manifests and their literal local runtime references/configuration. Library
    README floods cannot consume the runtime allocation. Selection is incomplete
    by design: unknown layouts and omitted middle regions still need review or
    the existing bounded captured-source retrieval pass. Filenames exclude common
    credential and key files; this is not a secret-content classifier. Ordinary
    checked-in production/local configuration remains eligible source context.
    """
    root = Path(source).resolve()
    captured = _context_paths(root, inventory)
    inventory = {}
    for name, path in captured.items():
        try:
            if not _safe_name(name) or any((root / Path(*PurePosixPath(name).parts[:i])).is_symlink()
                                          for i in range(1, len(PurePosixPath(name).parts) + 1)):
                continue
            if path.resolve() != root / name:
                continue
            inventory[name] = path
        except (OSError, ValueError, RuntimeError):
            continue
    order = lambda name: (name.count("/"), name.casefold(), name)
    names = sorted(inventory, key=order)
    cache = {}
    inspected = 0
    read_bytes = 0

    def read(name):
        nonlocal inspected, read_bytes
        if name in cache:
            return cache[name]
        if name not in inventory or inspected >= MAX_INSPECTED_FILES:
            return None
        inspected += 1
        cache[name] = None
        descriptor = None
        try:
            path = inventory[name]
            if (path.resolve() != root / name
                    or any(parent.is_symlink() for parent in path.parents if parent != root)):
                return None
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES
                    or read_bytes + before.st_size > MAX_INSPECTED_BYTES):
                return None
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = None
                raw = handle.read(MAX_FILE_BYTES + 1)
                after = os.fstat(handle.fileno())
            read_bytes += len(raw)
            if (len(raw) != before.st_size or len(raw) > MAX_FILE_BYTES
                    or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino)
                    or b"\0" in raw):
                return None
            raw.decode("utf-8", errors="strict")
            if any(value < 32 and value not in {9, 10, 13} for value in raw):
                return None
            cache[name] = raw
            return raw
        except (OSError, UnicodeError, ValueError, RuntimeError):
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def resolve(parent, reference):
        if not isinstance(reference, str) or len(reference) > 1000:
            return None
        while reference.startswith("./"):
            reference = reference[2:]
        if not _safe_name(reference) or any(char in reference for char in ":$*?{}[]#"):
            return None
        name = (PurePosixPath(parent) / reference).as_posix()
        if name in inventory:
            return name
        return None

    def manifest_info(name):
        if name not in cache and read_bytes >= MAX_MANIFEST_INSPECTION_BYTES:
            return (0, [])
        raw = read(name)
        if raw is None:
            return (0, [])
        refs = []
        score = 0
        parent = PurePosixPath(name).parent

        def add(reference, *, configuration=False):
            result = resolve(parent, reference)
            if result and (PurePosixPath(result).suffix.lower() in _SOURCE_SUFFIXES or _is_config(result)
                           or (configuration and PurePosixPath(result).suffix.lower() in _CONFIG_SUFFIXES)) and result not in refs:
                refs.append(result)

        try:
            if PurePosixPath(name).name == "package.json":
                data = json.loads(raw)
                if not isinstance(data, dict):
                    return (0, [])
                add(data.get("main"))
                score += 2 if refs else 0
                scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
                for key in ("start", "serve", "dev"):
                    command = scripts.get(key)
                    if not isinstance(command, str) or len(command) > 4000:
                        continue
                    old = len(refs)
                    tokens = shlex.split(command)[:64]
                    for index, token in enumerate(tokens):
                        add(token, configuration=index > 0 and tokens[index - 1] in {"--config", "--configuration", "-c"})
                    if len(refs) > old or any(re.search(r"(?:^|[ /])" + exe + r"(?: |$)", command)
                                              for exe in ("node", "nodemon", "tsx", "ts-node", "next", "nuxt")):
                        score += 6 if key == "start" else 4
                dependencies = data.get("dependencies")
                if isinstance(dependencies, dict) and set(dependencies) & {
                        "express", "fastify", "koa", "@hapi/hapi", "@nestjs/core", "next", "nuxt", "restify"}:
                    score += 3
                for key in ("config", "configuration"):
                    value = data.get(key)
                    if isinstance(value, str):
                        add(value, configuration=True)
                    elif isinstance(value, dict):
                        for reference in list(value.values())[:16]:
                            add(reference, configuration=True)
            elif PurePosixPath(name).name.lower() in {"pyproject.toml", "cargo.toml"}:
                data = tomllib.loads(raw.decode())
                if PurePosixPath(name).name.lower() == "pyproject.toml":
                    project = data.get("project", {})
                    scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
                    if isinstance(scripts, dict):
                        for reference in list(scripts.values())[:16]:
                            if isinstance(reference, str) and re.fullmatch(r"[A-Za-z_][\w.]*:[A-Za-z_][\w.]*", reference):
                                module = reference.split(":")[0].replace(".", "/") + ".py"
                                add(module)
                                add("src/" + module)
                else:
                    for binary in data.get("bin", [])[:16]:
                        if isinstance(binary, dict):
                            add(binary.get("path"))
                    add("src/main.rs")
                score += 8 if refs else 1
            else:
                # Conventional language entrypoints are setup candidates, not
                # proof of a usable application or a generated fallback.
                for reference in ("main.go", "Program.cs", "config.ru", "manage.py"):
                    add(reference)
                score += 6 if refs else 1
        except (ValueError, TypeError, RecursionError, AttributeError):
            pass
        if set(PurePosixPath(name).parts) & {"test", "tests", "fixtures", "examples", "demo", "demos"}:
            score -= 20
        return score, refs[:16]

    selected = []
    selected_names = set()

    def select(name, reason):
        if len(selected) >= MAX_FILES or name in selected_names:
            return False
        raw = read(name)
        if raw is None:
            return False
        selected.append({"file": name, **_excerpt(raw), "selection_reason": reason})
        selected_names.add(name)
        return True

    # Reserve top-level evidence before inspecting a large workspace.
    root_names = [name for name in names if "/" not in name]
    for group, reason, limit in (
        ([n for n in root_names if _is_manifest(n)], "root build manifest", 4),
        ([n for n in root_names if PurePosixPath(n).name.lower() in _TOOLCHAIN], "root toolchain/workspace declaration", 6),
        ([n for n in root_names if _is_doc(n)], "root setup documentation", 1),
        ([n for n in root_names if _is_docker(n)], "captured container setup (not a runtime privilege grant)", 2),
        ([n for n in root_names if PurePosixPath(n).name.lower() in _LOCKS], "captured lockfile excerpt", 1),
    ):
        for name in group[:limit]:
            select(name, reason)

    manifests = [name for name in names if _is_manifest(name)][:MAX_MANIFESTS]
    infos = {name: manifest_info(name) for name in manifests}
    components = sorted(manifests, key=lambda name: (-infos[name][0], *order(name)))
    roots = set()
    families = set()
    chosen = []
    for diverse in (True, False):
        for name in components:
            parent = PurePosixPath(name).parent.as_posix()
            family = PurePosixPath(name).parts[0] if "/" in name else "."
            if parent in roots or (diverse and family in families):
                continue
            roots.add(parent)
            families.add(family)
            chosen.append(name)
            if len(chosen) >= 3:
                break
        if len(chosen) >= 3:
            break

    neighborhoods = _component_neighborhoods(names, manifests)
    for name in chosen:
        select(name, "component build manifest; runtime support remains unverified")
        for reference in infos[name][1][:3]:
            select(reference, "literal local manifest runtime/configuration reference")
        parent = PurePosixPath(name).parent
        nearby = neighborhoods.get(parent, [])
        def config_order(item):
            basename = PurePosixPath(item).name.lower()
            # An exact mode declaration precedes a backend variant such as
            # config.development.docker.json. Generic defaults follow by
            # proximity; unrelated subsystem defaults must not crowd it out.
            stem = PurePosixPath(basename).stem
            native_development = stem in {"config.development", "defaults.development", "settings.development",
                                           "application.development", "appsettings.development"}
            mode = 0 if native_development else (1 if "default" in basename else 2)
            fixture = bool(set(PurePosixPath(item).parts) & {"test", "tests", "fixtures", "examples"})
            return fixture, mode, *order(item)
        configs = sorted((item for item in nearby if _is_config(item)), key=config_order)
        for item in configs[:4]:
            select(item, "captured component configuration; declared mode must be preserved")
        for item in [item for item in nearby if _is_doc(item)][:1]:
            select(item, "component setup documentation")

    # Fixed setup-document categories add diversity without a general code scan.
    docs = [name for name in names if _is_doc(name)]
    for name in sorted(docs, key=lambda n: (bool(re.match(r"readme", PurePosixPath(n).name, re.I)), *order(n)))[:6]:
        select(name, "setup/runtime documentation; interpretation only")
    # Follow only literal Markdown local links to setup docs/configs/manifests.
    for row in list(selected):
        if not _is_doc(row["file"]):
            continue
        for reference in re.findall(r"\]\(([^\s)]+)\)", row["excerpt"])[:16]:
            resolved = resolve(PurePosixPath(row["file"]).parent, reference)
            if resolved and (_is_doc(resolved) or _is_config(resolved) or _is_manifest(resolved)):
                select(resolved, "literal local setup-document link")
    return selected
