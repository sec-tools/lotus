"""Project-agnostic native build inference.

The platform repeatedly hit a class of blocker: a *compiled* target (C/C++/…)
whose lab image never produced a runnable binary — because the build needed
system ``-dev`` packages that weren't installed, or the project's default build
target was *self-bootstrapping* (it invokes the very binary it is supposed to
produce, e.g. microCI's ``make`` runs ``microCI | bash``). When the deterministic
lab build fails, the platform falls back to a serve-only container, so every
*native* PoC (CLI/config-DSL command injection, etc.) silently has no binary to
run and can never be proven.

This module derives, generically from the repository itself (never hardcoded to
any project):

* the apt ``-dev`` packages a C/C++ build needs (from ``-l`` link flags, CMake
  ``find_package``/``pkg_check_modules``, and system ``#include`` headers),
* a build command that avoids self-bootstrapping targets, and
* a last-resort *amalgamation compile* of the source tree (all TUs, inferred
  include dirs / defines / link flags, warnings disabled, non-static) that works
  even when the project's own build system is broken or unavailable.

It is consumed both by :mod:`backend.lab_builder` (primary: bake the build into
the lab image) and by native PoC harnesses such as
:mod:`backend.config_dsl_poc` (safety net: self-provision + build inside the
running lab before probing, while the lab still has network).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

# ``-l<name>`` link tokens whose apt package name is NOT simply ``lib<name>-dev``.
# Anything not listed falls back to the generic ``lib<name>-dev`` rule.
_LIB_TO_PKG = {
    "yaml-cpp": "libyaml-cpp-dev",
    "fmt": "libfmt-dev",
    "spdlog": "libspdlog-dev",
    "crypto": "libssl-dev",
    "ssl": "libssl-dev",
    "z": "zlib1g-dev",
    "zstd": "libzstd-dev",
    "lz4": "liblz4-dev",
    "bz2": "libbz2-dev",
    "lzma": "liblzma-dev",
    "curl": "libcurl4-openssl-dev",
    "pcre2-8": "libpcre2-dev",
    "pcre": "libpcre3-dev",
    "sqlite3": "libsqlite3-dev",
    "pq": "libpq-dev",
    "xml2": "libxml2-dev",
    "ssh2": "libssh2-1-dev",
    "ssh": "libssh-dev",
    "gmp": "libgmp-dev",
    "ncurses": "libncurses-dev",
    "readline": "libreadline-dev",
    "uv": "libuv1-dev",
    "event": "libevent-dev",
    "jsoncpp": "libjsoncpp-dev",
    "protobuf": "libprotobuf-dev",
    "crypto++": "libcrypto++-dev",
    "cryptopp": "libcrypto++-dev",
    "archive": "libarchive-dev",
    "boost_system": "libboost-system-dev",
    "boost_filesystem": "libboost-filesystem-dev",
    "boost_program_options": "libboost-program-options-dev",
    # Toolchain / libc components that need no package.
    "dl": None, "pthread": None, "m": None, "rt": None, "c": None,
    "stdc++": None, "gcc_s": None, "atomic": None,
}

# ``-l`` is also a common shell/ls option prefix (``-lt``, ``-le``, ``-lh``),
# especially in Makefile recipes.  Treat those tokens as non-library options;
# fabricating packages such as ``libh-dev`` makes an otherwise valid lab build
# fail before the target is compiled.
_NON_LIBRARY_OPTIONS = {"h", "t", "l", "e", "le", "lt", "gt", "ge", "eq", "ne"}

# Distinctive system headers -> apt package. Matched as substrings of the include
# path so ``<fmt/format.h>`` and ``<fmt/core.h>`` both map to libfmt-dev.
_HEADER_TO_PKG = {
    "yaml-cpp/": "libyaml-cpp-dev",
    "fmt/": "libfmt-dev",
    "spdlog/": "libspdlog-dev",
    "nlohmann/": "nlohmann-json3-dev",
    "boost/": "libboost-all-dev",
    "curl/curl.h": "libcurl4-openssl-dev",
    "openssl/": "libssl-dev",
    "zstd.h": "libzstd-dev",
    "zlib.h": "zlib1g-dev",
    "sqlite3.h": "libsqlite3-dev",
    "pcre2.h": "libpcre2-dev",
    "archive.h": "libarchive-dev",
    "gmp.h": "libgmp-dev",
}

_SRC_EXTS = (".c", ".cc", ".cpp", ".cxx", ".c++")
_HDR_EXTS = (".h", ".hpp", ".hh", ".hxx", ".h++")
_ALL_C_EXTS = _SRC_EXTS + _HDR_EXTS

_SKIP_DIRS = {".git", "build", "cmake-build-debug", "cmake-build-release",
              "node_modules", "vendor", "3rdparty", "third_party", "dist"}

# Directories that hold standalone example/test programs (each often with its own
# ``main()``). Sweeping these into an amalgamation compile guarantees duplicate
# symbols / multiple mains, so they are excluded from the last-resort compile.
_NON_LIB_DIRS = {"test", "tests", "testing", "example", "examples", "sample",
                 "samples", "demo", "demos", "docs", "doc", "dockerfiles",
                 "benchmark", "benchmarks", "bench"}

_LINK_RE = re.compile(r"(?<![\w-])-l([A-Za-z0-9_+\-.]+)")
_DEFINE_RE = re.compile(r"(?<![\w-])-D([A-Za-z0-9_]+(?:=[^\s]+)?)")
_INCLUDE_DIR_RE = re.compile(r"(?<![\w-])-I\s*([^\s]+)")
_STD_RE = re.compile(r"-std=([a-z0-9+]+)")
_SYS_INCLUDE_RE = re.compile(r'#\s*include\s*<([^>]+)>')
_CMAKE_FIND_RE = re.compile(r"find_package\s*\(\s*([A-Za-z0-9_+\-]+)", re.I)
_CMAKE_PKGCFG_RE = re.compile(r"pkg_check_modules\s*\([^)]*?\b([A-Za-z0-9_+\-]+)\)", re.I)


def _read(p: Path, limit: int = 200_000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _iter_files(dest: Path, names=None, exts=None, max_files: int = 4000):
    n = 0
    for p in dest.rglob("*"):
        if n >= max_files:
            return
        try:
            rel_parts = set(p.relative_to(dest).parts)
        except Exception:
            continue
        if rel_parts & _SKIP_DIRS:
            continue
        if not p.is_file():
            continue
        if names is not None and p.name not in names:
            continue
        if exts is not None and p.suffix.lower() not in exts:
            continue
        n += 1
        yield p


def _makefile_texts(dest: Path) -> List[Tuple[Path, str]]:
    out = []
    for p in _iter_files(dest, names={"Makefile", "makefile", "GNUmakefile"}):
        out.append((p, _read(p)))
    return out


def _cmake_texts(dest: Path) -> List[Tuple[Path, str]]:
    return [(p, _read(p)) for p in _iter_files(dest, names={"CMakeLists.txt"})]


def _lib_to_pkg(name: str) -> Optional[str]:
    if name.lower() in _NON_LIBRARY_OPTIONS:
        return None
    if name in _LIB_TO_PKG:
        return _LIB_TO_PKG[name]
    # Generic Debian convention: -lfoo -> libfoo-dev.
    return f"lib{name}-dev"


def infer_apt_packages(dest: Path) -> List[str]:
    """Best-effort ``-dev`` packages a native build of ``dest`` likely needs.

    Never raises; returns a deduped, sorted list. Callers subtract packages that
    are already present in their base image.
    """
    pkgs: set = set()

    # 1) Link flags in Makefiles / CMake.
    build_blobs = [t for _, t in _makefile_texts(dest)] + [t for _, t in _cmake_texts(dest)]
    for blob in build_blobs:
        for lib in _LINK_RE.findall(blob):
            pkg = _lib_to_pkg(lib)
            if pkg:
                pkgs.add(pkg)

    # 2) CMake find_package / pkg_check_modules names.
    for _, t in _cmake_texts(dest):
        for name in _CMAKE_FIND_RE.findall(t) + _CMAKE_PKGCFG_RE.findall(t):
            low = name.lower()
            if low in ("threads", "python", "python3", "git"):
                continue
            pkg = _LIB_TO_PKG.get(low) or f"lib{low}-dev"
            if pkg:
                pkgs.add(pkg)

    # 3) System headers in a sample of sources (angle-bracket includes only).
    scanned = 0
    for p in _iter_files(dest, exts=_ALL_C_EXTS):
        scanned += 1
        if scanned > 1500:
            break
        for inc in _SYS_INCLUDE_RE.findall(_read(p, limit=60_000)):
            for needle, pkg in _HEADER_TO_PKG.items():
                if needle in inc:
                    pkgs.add(pkg)

    # Build tooling projects commonly assume is present (asset embedding, etc.).
    if any(dest.rglob("*.header.cpp")) or _uses_xxd(dest):
        pkgs.add("xxd")

    return sorted(pkgs)


def _uses_xxd(dest: Path) -> bool:
    for _, t in _makefile_texts(dest):
        if re.search(r"\bxxd\b", t):
            return True
    return False


def _default_target_recipe(makefile_text: str) -> str:
    """Return the recipe body of the first real target (``all``/``build`` or the
    first non-special target), used to spot self-bootstrapping builds."""
    lines = makefile_text.splitlines()
    # Prefer 'all' then 'build', else first target.
    target_order = []
    targets = {}
    cur = None
    buf: List[str] = []
    for ln in lines:
        m = re.match(r"^([A-Za-z0-9_./%-]+)\s*:(?!=)", ln)
        if m and not ln.startswith("\t"):
            if cur is not None:
                targets[cur] = "\n".join(buf)
            cur = m.group(1)
            target_order.append(cur)
            buf = []
        elif ln.startswith("\t") and cur is not None:
            buf.append(ln.strip())
    if cur is not None:
        targets[cur] = "\n".join(buf)
    for pref in ("all", "build"):
        if pref in targets:
            # 'all: build' style indirection -> follow one hop.
            body = targets[pref].strip()
            if not body and pref == "all":
                continue
            return targets[pref]
    for t in target_order:
        if not t.startswith(".") and "%" not in t:
            return targets.get(t, "")
    return ""


def looks_self_bootstrapping(dest: Path, binary_names: List[str]) -> bool:
    """True when the root build's default target invokes the very binary it is
    supposed to produce (a chicken-and-egg build that cannot run from clean)."""
    root_mk = dest / "Makefile"
    if not root_mk.exists():
        root_mk = dest / "makefile"
    if not root_mk.exists():
        return False
    recipe = _default_target_recipe(_read(root_mk))
    if not recipe:
        return False
    for name in binary_names:
        if not name:
            continue
        if re.search(rf"(?<![\w./]){re.escape(name)}\b", recipe):
            return True
    return False


def _collect_flags(dest: Path) -> Tuple[List[str], List[str], List[str], str]:
    """(-D defines, -I include dirs (relative, existing), -l link flags, -std)."""
    defines: set = set()
    incs: List[str] = []
    links: List[str] = []
    std = "c++20"
    for mp, t in _makefile_texts(dest):
        for d in _DEFINE_RE.findall(t):
            defines.add(d)
        for inc in _INCLUDE_DIR_RE.findall(t):
            cand = inc.replace("../", "").strip()
            if cand and (dest / cand).exists() and cand not in incs:
                incs.append(cand)
        for lib in _LINK_RE.findall(t):
            flag = f"-l{lib}"
            if flag not in links:
                links.append(flag)
        m = _STD_RE.search(t)
        if m:
            std = m.group(1)
    # Sensible default include roots if the Makefile didn't spell them out.
    for cand in ("include", "include/3rd", "inc", "src"):
        if (dest / cand).is_dir() and cand not in incs:
            incs.append(cand)
    return sorted(defines), incs, links, std


def amalgamation_compile_command(dest: Path, binary_names: List[str]) -> Optional[str]:
    """A single, tolerant, *runtime-adaptive* g++ command that compiles the tree.

    Warnings disabled (``-w``) and **no** ``-static`` (dynamic linking avoids the
    missing-static-lib / jitterentropy-style link failures that break a project's
    own optimized build). Uses inferred defines/includes/link-flags.

    Crucially it handles two project shapes at runtime:

    * *Single-compilation-unit* projects (all ``*.cpp`` are ``#include``d into one
      generated ``single_compilation_unit.cpp`` and are **not** independently
      compilable): if such a file exists — typically produced by the project's own
      ``make`` step that ran just before this fallback — compile *only* that file.
    * Normal multi-TU projects: compile the inferred source list.

    Returns None only when there are no C/C++ sources at all.
    """
    srcs = []
    for p in _iter_files(dest, exts=_SRC_EXTS):
        rel_parts = p.relative_to(dest).parts
        # Skip standalone example/test programs (their own main() -> link clash).
        if any(part.lower() in _NON_LIB_DIRS for part in rel_parts[:-1]):
            continue
        rel = p.relative_to(dest).as_posix()
        base = p.name.lower()
        if "single_compilation_unit" in base or base.endswith(".header.cpp"):
            continue
        srcs.append(rel)
    # Prefer the library/app subtree (``src/``) when it holds sources, so a
    # top-level example .cpp with its own main() can't collide with the app's.
    src_only = [s for s in srcs if s.startswith("src/")]
    if src_only:
        srcs = src_only
    if not srcs:
        return None
    defines, incs, links, std = _collect_flags(dest)
    # Drop absolute include dirs (e.g. Homebrew) that won't exist in a Linux lab.
    incs = [i for i in incs if not i.startswith("/")]
    out_name = (binary_names or ["app"])[0]

    common = ["g++", f"-std={std}", "-O0", "-w"]
    common += [f"-D{d}" for d in defines]
    common += [f"-I{i}" for i in incs]
    common_str = " ".join(common)
    links_str = " ".join(links)
    srcs_str = " ".join(srcs)

    # $scu is discovered at runtime because it is generated during the build, not
    # committed. If present, the project is SCU-style -> compile the one unit.
    return (
        "mkdir -p bin && "
        '{ scu="$(find . -name single_compilation_unit.cpp 2>/dev/null | head -n1)"; '
        'if [ -n "$scu" ]; then '
        f'{common_str} -Isrc -o bin/{out_name} "$scu" {links_str}; '
        "else "
        f"{common_str} -o bin/{out_name} {srcs_str} {links_str}; "
        "fi; }"
    )


_MK_BIN_TARGET_RE = re.compile(r"(?m)^([A-Za-z0-9_./%-]*?bin/[A-Za-z0-9_.\-]+)\s*:(?!=)")
_CMAKE_ADD_EXE_RE = re.compile(r"add_executable\s*\(\s*([A-Za-z0-9_.\-]+)", re.I)


def guess_native_binary_names(dest: Path) -> List[str]:
    """Best-effort list of executable names a native build of ``dest`` produces.

    Derived generically from the project's own build system (never hardcoded):
    Makefile ``.../bin/<name>`` targets, CMake ``add_executable(<name> ...)``,
    committed ``bin/`` executables, and finally the project directory name.
    Ordered most-specific first, deduped.
    """
    names: List[str] = []

    def _add(n: str) -> None:
        n = (n or "").strip()
        # Ignore CMake generator expressions / variables.
        if not n or "$" in n or "{" in n:
            return
        if n not in names:
            names.append(n)

    # 1) Makefile targets that emit a binary under a bin/ directory.
    for _, t in _makefile_texts(dest):
        for target in _MK_BIN_TARGET_RE.findall(t):
            _add(target.rsplit("/", 1)[-1])

    # 2) CMake add_executable() names.
    for _, t in _cmake_texts(dest):
        for name in _CMAKE_ADD_EXE_RE.findall(t):
            _add(name)

    # 3) Anything already committed under bin/.
    bindir = dest / "bin"
    if bindir.is_dir():
        for p in bindir.iterdir():
            if p.is_file():
                _add(p.name)

    # 4) Fall back to project-name variants.
    proj = dest.name
    for n in (proj, proj.lower(), proj.replace("-", ""), proj.lower().replace("-", "")):
        _add(n)

    return names[:6]


def infer_build_steps(dest: Path, binary_names: Optional[List[str]] = None) -> List[str]:
    """Ordered, best-effort build commands. The caller runs them until a binary
    appears. Avoids self-bootstrapping targets and always ends with a generic
    amalgamation compile as a last resort."""
    binary_names = binary_names or []
    steps: List[str] = []
    has_cmake = (dest / "CMakeLists.txt").exists()
    has_root_mk = (dest / "Makefile").exists() or (dest / "makefile").exists()
    has_src_mk = (dest / "src" / "Makefile").exists()
    bootstrap = looks_self_bootstrapping(dest, binary_names)

    if has_cmake:
        steps.append("cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)")
    if has_src_mk and (bootstrap or not has_root_mk):
        steps.append("make -C src -j$(nproc)")
    elif has_root_mk and not bootstrap:
        steps.append("make -j$(nproc)")
    elif has_src_mk:
        steps.append("make -C src -j$(nproc)")

    amalg = amalgamation_compile_command(dest, binary_names)
    if amalg:
        steps.append(amalg)
    return steps


def build_setup_shell(dest: Path, binary_names: List[str], *, install_deps: bool = True) -> str:
    """A POSIX-sh snippet that self-provisions and builds ``dest`` in a running
    lab, for use by native PoC harnesses when the baked image lacks the binary.

    Each step is tolerant (``|| true``); success is decided by the caller
    re-locating the binary afterwards. apt usage is best-effort so an offline lab
    degrades gracefully instead of erroring.
    """
    lines: List[str] = []
    pkgs = infer_apt_packages(dest)
    if install_deps and pkgs:
        pkg_str = " ".join(pkgs)
        lines.append(
            "if command -v apt-get >/dev/null 2>&1; then "
            "apt-get update -qq >/dev/null 2>&1 || true; "
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg_str} "
            ">/dev/null 2>&1 || true; fi"
        )
    for step in infer_build_steps(dest, binary_names):
        lines.append(f"( {step} ) >/dev/null 2>&1 || true")
    return "\n".join(lines)
