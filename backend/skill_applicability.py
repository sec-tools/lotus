"""
Skill applicability: decide, for Phase 2 context, which skills apply to the repo.

Why this exists
---------------
Doctrine skills are rich (discovery vectors, cross-language examples). Injecting
all of them into every audit wastes the context budget and buries the few
skills that actually match the target. Substring-matching a language name inside
the skill body is not a selection signal either: a strong skill mentions many
languages by design. Applicability therefore comes from *declared metadata* in
each skill file, matched against a *repo profile* built once before the Phase 2 review.

Metadata contract (parsed from the ``## Metadata`` block of doctrine skills, or
from the YAML frontmatter of learned skills)::

    - **Category**: discovery | bug-classes | methodology | gating | learned
    - **Language**: python go java ...   (``any`` / ``multi-language`` = universal)
    - **Stacks**: fastapi, envoy, kafka   (frameworks / products / infra)
    - **Signals**: pyjwt, dockerfile, ... (dependency names or filename hints)
    - **Applies to**: all repositories    (explicit cross-cutting marker)

Selection rules
---------------
* ``methodology`` and ``gating`` skills are cross-cutting doctrine: always apply.
* ``learned`` skills are compounding memory: always retained, ranked by match.
* ``discovery`` / ``bug-classes`` skills apply when universal, or when any
  declared language, stack, or signal matches the repo profile. A skill that
  declares nothing is treated as unrestricted so BYOS / custom skills are never
  silently hidden.
* Every decision carries human-readable reasons so the audit log and recorded detail
  can show *why* a skill was (not) loaded.
"""
from __future__ import annotations

import json
import os
import re
import stat
from collections import deque
from itertools import islice
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Language normalisation (shared by skill metadata and repo profiling)
# ---------------------------------------------------------------------------

CANONICAL_LANGUAGES: Set[str] = {
    "python", "node", "go", "java", "kotlin", "scala", "ruby", "php", "c/cpp",
    "rust", "csharp", "elixir", "dart", "swift", "zig", "lua", "sql", "perl",
    "shell", "erlang", "haskell", "objective-c",
}

_LANG_ALIASES: Dict[str, str] = {
    "py": "python", "python3": "python",
    "js": "node", "javascript": "node", "ts": "node", "typescript": "node",
    "nodejs": "node", "node.js": "node", "deno": "node", "bun": "node",
    "golang": "go",
    "c": "c/cpp", "cpp": "c/cpp", "c++": "c/cpp", "cxx": "c/cpp", "cc": "c/cpp", "c/c++": "c/cpp",
    "ruby/rails": "ruby", "rb": "ruby",
    "c#": "csharp", "dotnet": "csharp", ".net": "csharp",
    "kt": "kotlin", "rs": "rust", "ex": "elixir", "sh": "shell", "bash": "shell",
    "objc": "objective-c", "pl": "perl", "hs": "haskell", "erl": "erlang",
}

# Tokens that mean "no language restriction".
_UNIVERSAL_TOKENS: Set[str] = {"any", "all", "multi", "multi-language", "multilanguage", "universal", "*"}

# Language tokens that also imply a stack (kept in both sets).
_LANG_IMPLIED_STACK: Dict[str, str] = {"ruby/rails": "rails", "rails": "rails"}

_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "node", ".jsx": "node", ".mjs": "node", ".cjs": "node", ".ts": "node", ".tsx": "node",
    ".go": "go", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".rb": "ruby", ".erb": "ruby", ".rake": "ruby",
    ".php": "php", ".rs": "rust", ".cs": "csharp",
    ".c": "c/cpp", ".cpp": "c/cpp", ".cc": "c/cpp", ".cxx": "c/cpp", ".h": "c/cpp", ".hpp": "c/cpp", ".hxx": "c/cpp",
    ".ex": "elixir", ".exs": "elixir", ".dart": "dart", ".swift": "swift", ".zig": "zig",
    ".lua": "lua", ".sql": "sql", ".pl": "perl", ".pm": "perl", ".sh": "shell", ".bash": "shell",
    ".erl": "erlang", ".hs": "haskell", ".m": "objective-c",
}

_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "vendor", ".bundle", "__pycache__", "target", "build", "dist",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".idea", ".vscode",
    "third_party", "thirdparty", "external", "deps", ".gradle", "bin", "obj",
}

# Dependency name -> framework/stack token(s) that skills declare.
_DEP_TO_STACK: Dict[str, Iterable[str]] = {
    "fastapi": ("fastapi",), "starlette": ("starlette",), "flask": ("flask",), "django": ("django",),
    "djangorestframework": ("django", "drf"), "werkzeug": ("werkzeug", "flask"),
    "rails": ("rails",), "railties": ("rails",), "sinatra": ("sinatra",), "rack": ("rack",),
    "react_on_rails": ("react_on_rails", "ssr"), "react-on-rails": ("react_on_rails", "ssr"),
    "express": ("express",), "@nestjs/core": ("nestjs",), "next": ("next", "ssr"), "nuxt": ("nuxt", "ssr"),
    "spring-boot": ("spring",), "spring-boot-starter": ("spring",), "spring-boot-starter-actuator": ("spring", "spring-actuator"),
    "spring-cloud-gateway": ("spring", "spring-cloud-gateway"), "spring-webmvc": ("spring",), "spring-web": ("spring",),
    "shenyu": ("shenyu", "gateway"), "struts2-core": ("struts",),
    "gin": ("gin",), "github.com/gin-gonic/gin": ("gin",), "echo": ("echo",), "fiber": ("fiber",),
    "torch": ("pytorch", "ml"), "pytorch": ("pytorch", "ml"), "tensorflow": ("ml",), "scikit-learn": ("sklearn", "ml"),
    "sklearn": ("sklearn", "ml"), "joblib": ("joblib", "ml"), "mlflow": ("mlflow", "ml"), "transformers": ("huggingface", "ml"),
    "huggingface-hub": ("huggingface", "ml"), "ray": ("ray", "ml"), "kfp": ("kubeflow", "ml"),
    "litellm": ("litellm", "llm", "proxy"), "openai": ("openai", "llm"), "anthropic": ("llm",), "langchain": ("llm",),
    "httpx": ("httpx",), "requests": ("requests",),
    "kafka-python": ("kafka", "broker"), "confluent-kafka": ("kafka", "broker"), "sarama": ("kafka", "broker"),
    "github.com/segmentio/kafka-go": ("kafka", "broker"), "pika": ("amqp", "rabbitmq", "broker"), "amqplib": ("amqp", "rabbitmq", "broker"),
    "nats": ("nats", "broker"), "paho-mqtt": ("mqtt", "broker"), "redis": ("redis",), "grpcio": ("grpc",), "grpc": ("grpc",),
    "google.golang.org/grpc": ("grpc",), "pymysql": ("mysql", "database"), "mysqlclient": ("mysql", "database"),
    "psycopg2": ("postgres", "database"), "psycopg": ("postgres", "database"), "pg": ("postgres", "database"),
    "pymongo": ("mongodb", "database"), "mongoose": ("mongodb", "database"), "sqlite3": ("sqlite", "database"),
    "pyjwt": ("jwt",), "jsonwebtoken": ("jwt",), "jose": ("jwt",), "python-jose": ("jwt",), "jjwt": ("jwt",),
    "io.jsonwebtoken": ("jwt",), "github.com/golang-jwt/jwt": ("jwt",), "golang-jwt": ("jwt",), "ruby-jwt": ("jwt",), "jwt": ("jwt",),
    "authlib": ("oauth", "oidc"), "oauthlib": ("oauth",), "omniauth": ("oauth",), "passport": ("oauth",),
    "pyyaml": ("yaml",), "psych": ("yaml",), "snakeyaml": ("yaml",), "js-yaml": ("yaml",),
    "pypdf": ("pdf", "parser"), "pdf-reader": ("pdf", "parser"), "prawn": ("pdf",), "pdfbox": ("pdf", "parser"),
    "nokogiri": ("xml", "parser"), "lxml": ("xml", "parser"), "pillow": ("image", "parser"),
    "jinja2": ("jinja2", "template"), "inja": ("inja", "template"), "freemarker": ("freemarker", "template"),
    "velocity": ("velocity", "template"), "thymeleaf": ("thymeleaf", "template"), "mustache": ("mustache", "template"),
    "handlebars": ("handlebars", "template"),
    "certbot": ("certbot", "acme"), "acme": ("acme",),
    "puppet": ("puppet", "config-management"), "chef": ("chef", "config-management"), "salt": ("salt", "config-management"),
    "ansible": ("ansible", "config-management"),
    "execjs": ("execjs", "ssr"), "mini_racer": ("execjs", "ssr"),
    "ctypes": ("native", "plugin"), "cffi": ("native", "plugin"), "jna": ("native", "plugin"),
    "tarfile": ("tar", "archive"), "zipfile": ("zip", "archive"), "adm-zip": ("zip", "archive"),
    "archive/tar": ("tar", "archive"), "archive/zip": ("zip", "archive"), "libarchive": ("archive",),
    "groovy": ("groovy",), "org.codehaus.groovy": ("groovy",), "spring-expression": ("spel",), "ognl": ("ognl",),
    "fastjson": ("fastjson",), "hessian": ("hessian",),
    "sidekiq": ("sidekiq",), "mailcatcher": ("mailcatcher",), "web-console": ("web-console",),
}

# Repo-layout hints -> (stack tokens, language)
_LAYOUT_HINTS: List[Tuple[str, Tuple[str, ...], Optional[str]]] = [
    ("config/routes.rb", ("rails",), "ruby"),
    ("app/controllers", ("rails",), "ruby"),
    ("manage.py", ("django",), "python"),
    ("Dockerfile", ("docker",), None),
    ("docker-compose.yml", ("docker", "compose"), None),
    ("docker-compose.yaml", ("docker", "compose"), None),
    ("compose.yaml", ("docker", "compose"), None),
    ("Chart.yaml", ("helm", "kubernetes"), None),
    ("values.yaml", ("helm", "kubernetes"), None),
    ("k8s", ("kubernetes",), None),
    ("kubernetes", ("kubernetes",), None),
    (".github/workflows", ("github-actions", "ci"), None),
    (".gitlab-ci.yml", ("gitlab-ci", "ci"), None),
    ("Jenkinsfile", ("jenkins", "ci"), None),
    (".drone.yml", ("drone", "ci"), None),
    (".circleci", ("circleci", "ci"), None),
    ("azure-pipelines.yml", ("ci",), None),
    ("envoy.yaml", ("envoy",), None),
    ("nginx.conf", ("nginx",), None),
    ("Puppetfile", ("puppet",), "ruby"),
    ("manifests", ("puppet",), None),
    ("plugins", ("plugin",), None),
    ("plugin", ("plugin",), None),
    ("sql", ("database",), None),
]

_MANIFESTS: Set[str] = {
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile",
    "package.json", "go.mod", "gemfile", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "cargo.toml",
    "cmakelists.txt", "makefile", "meson.build", "mix.exs", "pubspec.yaml", "package.swift",
}


def normalize_language(token: str) -> Optional[str]:
    """Return a canonical language for ``token`` or None when it is not a language."""
    t = (token or "").strip().lower().strip(",;")
    if not t:
        return None
    t = _LANG_ALIASES.get(t, t)
    return t if t in CANONICAL_LANGUAGES else None


def is_universal_token(token: str) -> bool:
    return (token or "").strip().lower().strip(",;") in _UNIVERSAL_TOKENS


def _split_tokens(value: str, *, on_space: bool) -> List[str]:
    if on_space:
        raw = re.split(r"[,\s]+", value)
    else:
        raw = value.split(",")
    return [x.strip().strip("`'\"").lower() for x in raw if x and x.strip()]


# ---------------------------------------------------------------------------
# Skill metadata
# ---------------------------------------------------------------------------

@dataclass
class SkillMeta:
    languages: Set[str] = field(default_factory=set)
    stacks: Set[str] = field(default_factory=set)
    signals: Set[str] = field(default_factory=set)
    universal: bool = False
    category: str = "general"
    cvss: Optional[float] = None
    declared: bool = False  # True when the file declared any applicability metadata

    def primary_hit(self, profile: "RepoProfile") -> bool:
        return bool(profile.primary_language and profile.primary_language in self.languages)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "languages": sorted(self.languages),
            "stacks": sorted(self.stacks),
            "signals": sorted(self.signals),
            "universal": self.universal,
            "category": self.category,
            "cvss": self.cvss,
            "declared": self.declared,
        }


_META_LINE = re.compile(r"^\s*[-*]\s*\*\*(?P<key>[A-Za-z][A-Za-z /]*?)\*\*\s*:\s*(?P<val>.*)$")
_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---", re.S)
_CVSS_RE = re.compile(r"(?:cvss|severity)[^0-9]{0,12}(\d{1,2}(?:\.\d)?)", re.I)


def _absorb_language_value(meta: SkillMeta, value: str) -> None:
    for tok in _split_tokens(value, on_space=True):
        if is_universal_token(tok):
            meta.universal = True
            continue
        if tok in ("unknown", "n/a", "none", "-"):
            continue
        lang = normalize_language(tok)
        if lang:
            meta.languages.add(lang)
            implied = _LANG_IMPLIED_STACK.get(tok)
            if implied:
                meta.stacks.add(implied)
        elif tok.startswith("multi-"):
            # multi-runtime / multi-protocol / ... describe breadth within a
            # domain; they are not a universal marker and not a stack.
            continue
        else:
            # Products / frameworks riding in the Language line (envoy, shenyu, puppet...)
            meta.stacks.add(tok)


def parse_skill_metadata(content: str, category: Optional[str] = None) -> SkillMeta:
    """Parse applicability metadata from a skill body (doctrine block or frontmatter)."""
    meta = SkillMeta(category=(category or "general"))
    text = content or ""

    # 1. Learned-skill YAML frontmatter (language:, stacks:, signals:, cvss:)
    fm = _FRONTMATTER.match(text)
    if fm:
        for line in fm.group(1).splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip().strip("\"'[]")
            if k in ("language", "languages"):
                _absorb_language_value(meta, v)
                meta.declared = True
            elif k in ("stacks", "stack", "frameworks"):
                meta.stacks.update(_split_tokens(v, on_space=False))
                meta.declared = True
            elif k in ("signals", "dependencies", "deps"):
                meta.signals.update(_split_tokens(v, on_space=False))
                meta.declared = True
            elif k == "cvss":
                try:
                    meta.cvss = float(v)
                except ValueError:
                    pass
            elif k == "category" and v:
                meta.category = v.lower()

    # 2. Doctrine ``## Metadata`` bullets (first 40 lines are enough)
    for line in text.splitlines()[:40]:
        m = _META_LINE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        val = m.group("val").strip()
        if key in ("language", "languages"):
            _absorb_language_value(meta, val)
            meta.declared = True
        elif key in ("stacks", "stack", "frameworks", "tech stacks"):
            meta.stacks.update(t for t in _split_tokens(val, on_space=False) if t not in _UNIVERSAL_TOKENS)
            meta.declared = True
        elif key in ("signals", "signal", "dependencies"):
            meta.signals.update(t for t in _split_tokens(val, on_space=False) if t not in _UNIVERSAL_TOKENS)
            meta.declared = True
        elif key in ("applies to", "applicability", "scope"):
            low = val.lower()
            if "all repositories" in low or low.startswith("all ") or low in _UNIVERSAL_TOKENS:
                meta.universal = True
                meta.declared = True
        elif key == "category" and val:
            meta.category = val.lower().split()[0]
        elif key in ("severity", "cvss") and meta.cvss is None:
            mm = _CVSS_RE.search(f"cvss {val}")
            if mm:
                try:
                    meta.cvss = float(mm.group(1))
                except ValueError:
                    pass

    if meta.category in ("methodology", "gating"):
        meta.universal = True
    return meta


# ---------------------------------------------------------------------------
# Repo profile
# ---------------------------------------------------------------------------

@dataclass
class RepoProfile:
    languages: Set[str] = field(default_factory=set)
    primary_language: Optional[str] = None
    frameworks: Set[str] = field(default_factory=set)
    dependencies: Set[str] = field(default_factory=set)
    files: Set[str] = field(default_factory=set)  # lowercase basenames + notable relative paths (exact-match only)
    manifests: List[str] = field(default_factory=list)
    file_count: int = 0
    source: str = "repo"
    limitations: List[str] = field(default_factory=list)

    def haystack(self) -> Set[str]:
        """Tokens eligible for substring matching: frameworks and dependency names.

        File names are deliberately excluded here and matched exactly (see
        ``_match_tokens``) so documentation or fixtures mentioning a product
        never count as evidence that the repo uses it.
        """
        return self.frameworks | self.dependencies

    def to_dict(self) -> Dict[str, Any]:
        return {
            "languages": sorted(self.languages),
            "primary_language": self.primary_language,
            "frameworks": sorted(self.frameworks),
            "dependencies": sorted(self.dependencies)[:200],
            "dependency_count": len(self.dependencies),
            "manifests": list(self.manifests),
            "file_count": self.file_count,
            "source": self.source,
            "limitations": list(self.limitations),
        }


def profile_from_language(language: Optional[str]) -> Optional[RepoProfile]:
    """Minimal profile when only a language string is known (legacy callers, tests)."""
    if not language:
        return None
    lang = normalize_language(language)
    if lang is None:
        if is_universal_token(language) or language.lower() == "unknown":
            return None
        lang = language.lower()
    prof = RepoProfile(languages={lang}, primary_language=lang, source="language")
    implied = _LANG_IMPLIED_STACK.get(language.lower())
    if implied:
        prof.frameworks.add(implied)
    return prof


def _dep_variants(name: str) -> Set[str]:
    n = name.strip().lower().strip("\"'")
    if not n:
        return set()
    out = {n, n.replace("_", "-"), n.replace("-", "_")}
    if "/" in n:
        # Module paths (github.com/golang-jwt/jwt/v5, @nestjs/core): drop a
        # trailing major-version segment, then expose the path, owner/name,
        # and bare package name so stack maps can key on any of them.
        parts = [p for p in n.split("/") if p]
        if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]):
            parts = parts[:-1]
        out.add("/".join(parts))
        out.add(parts[-1])
        if len(parts) >= 2:
            out.add("/".join(parts[-2:]))
            out.add(parts[-2])
    if ":" in n:  # maven coords group:artifact
        out.update(p for p in n.split(":")[:2] if p)
    return {x for x in out if x}


def _parse_requirements(text: str) -> Set[str]:
    deps: Set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", "file:")):
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if m:
            deps.add(m.group(1))
    return deps


def _parse_pyproject(text: str) -> Set[str]:
    deps: Set[str] = set()
    # PEP 621 / poetry: quoted requirement strings and `name = "^x"` keys inside dependency tables
    in_dep_table = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_dep_table = "dependencies" in s or s.startswith("[project.optional-dependencies")
            continue
        for m in re.finditer(r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[;]|[\"'])", s):
            deps.add(m.group(1))
        if in_dep_table:
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", s)
            if m and m.group(1).lower() != "python":
                deps.add(m.group(1))
    return deps


def _parse_package_json(text: str) -> Set[str]:
    deps: Set[str] = set()
    try:
        data = json.loads(text)
    except Exception:
        return deps
    if not isinstance(data, dict):
        return deps
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update(str(k) for k in block.keys())
    return deps


def _parse_go_mod(text: str) -> Set[str]:
    deps: Set[str] = set()
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s.startswith(")"):
            in_block = False
            continue
        if in_block or s.startswith("require "):
            parts = s.replace("require ", "").split()
            if parts:
                deps.add(parts[0])
    return deps


def _parse_gemfile(text: str) -> Set[str]:
    return set(re.findall(r"""^\s*gem\s+['"]([A-Za-z0-9_.-]+)['"]""", text, re.M)) | set(
        re.findall(r"""add(?:_runtime|_development)?_dependency\s*\(?\s*['"]([A-Za-z0-9_.-]+)['"]""", text)
    )


def _parse_pom(text: str) -> Set[str]:
    return set(re.findall(r"<artifactId>\s*([A-Za-z0-9_.-]+)\s*</artifactId>", text)) | set(
        re.findall(r"<groupId>\s*([A-Za-z0-9_.-]+)\s*</groupId>", text)
    )


def _parse_gradle(text: str) -> Set[str]:
    deps: Set[str] = set()
    for m in re.finditer(r"""['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::[^'"]*)?['"]""", text):
        deps.add(m.group(1))
        deps.add(m.group(2))
        deps.add(f"{m.group(1)}:{m.group(2)}")
    return deps


def _parse_composer(text: str) -> Set[str]:
    deps: Set[str] = set()
    try:
        data = json.loads(text)
    except Exception:
        return deps
    if not isinstance(data, dict):
        return deps
    for key in ("require", "require-dev"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update(str(k) for k in block.keys() if k != "php")
    return deps


def _parse_cargo(text: str) -> Set[str]:
    deps: Set[str] = set()
    in_dep = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_dep = "dependencies" in s
            continue
        if in_dep:
            m = re.match(r"([A-Za-z0-9_-]+)\s*=", s)
            if m:
                deps.add(m.group(1))
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements, "requirements-dev.txt": _parse_requirements,
    "requirements_dev.txt": _parse_requirements, "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json, "go.mod": _parse_go_mod, "gemfile": _parse_gemfile,
    "pom.xml": _parse_pom, "build.gradle": _parse_gradle, "build.gradle.kts": _parse_gradle,
    "composer.json": _parse_composer, "cargo.toml": _parse_cargo,
}


def _read_capped(path: Path, cap: int = 400_000, *, root: Optional[Path] = None) -> str:
    """Read a bounded regular manifest without following any path symlink."""
    directory_fd = None
    try:
        root = root if root is not None else path.parent
        parts = path.relative_to(root).parts
        if not parts or any(part in {".", ".."} for part in parts):
            return ""
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in parts[:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = following
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                return ""
            return source.read(cap).decode("utf-8", errors="ignore")
    except (OSError, ValueError):
        return ""
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def profile_repo(repo_path: Path | str, base_language: Optional[str] = None, max_files: int = 25000) -> RepoProfile:
    """Build a RepoProfile with one bounded breadth-first walk plus manifest parsing.

    ``base_language`` is the pipeline's ``detect_language`` result and is always
    kept as the primary language even when extension counts disagree. The walk
    is breadth-first so root / package-level manifests and a representative
    extension sample are captured even when ``max_files`` truncates a large
    tree; truncation is recorded in ``limitations`` and unmatched skills are
    then retained rather than hidden on partial evidence.
    """
    root = Path(repo_path)
    prof = RepoProfile(source="repo")
    base = normalize_language(base_language or "") if base_language else None
    if base:
        prof.languages.add(base)
        prof.primary_language = base
        implied = _LANG_IMPLIED_STACK.get((base_language or "").lower())
        if implied:
            prof.frameworks.add(implied)
    if root.is_symlink() or not root.is_dir():
        prof.limitations.append("repository root unavailable or symlinked")
        return prof

    ext_counts: Dict[str, int] = {}
    manifest_paths: List[Path] = []
    seen = 0
    queue: Deque[Path] = deque([root])
    remaining_entries = max(128, max_files * 4)
    while queue and seen < max_files and remaining_entries > 0:
        cur = queue.popleft()
        try:
            # Bound directory-only trees and the allocation for a single huge
            # directory as well as regular-file work. Never traverse symlinks.
            entries = list(islice(cur.iterdir(), remaining_entries + 1))
            if len(entries) > remaining_entries:
                prof.limitations.append("directory entry limit reached")
                entries = entries[:remaining_entries]
            entries.sort(key=lambda p: p.name)
        except OSError:
            if "unreadable directory" not in prof.limitations:
                prof.limitations.append("unreadable directory")
            continue
        for entry in entries:
            remaining_entries -= 1
            name = entry.name
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if name in _SKIP_DIRS or (name.startswith(".") and name not in (".github", ".gitlab", ".circleci")):
                    continue
                queue.append(entry)
                rel = str(entry.relative_to(root)).replace("\\", "/")
                prof.files.add(name.lower())
                prof.files.add(rel.lower())
                continue
            if not entry.is_file():
                continue
            seen += 1
            low = name.lower()
            prof.files.add(low)
            ext = entry.suffix.lower()
            lang = _EXT_TO_LANG.get(ext)
            if lang:
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
            # Manifests at the root or one level down (monorepo packages), bounded.
            near_root = cur == root or cur.parent == root
            if near_root and len(manifest_paths) < 40 and (low in _MANIFESTS or low.endswith(".gemspec")):
                manifest_paths.append(entry)
            if seen >= max_files:
                break
    prof.file_count = seen
    if seen >= max_files:
        prof.limitations.append("source file limit reached")
    if remaining_entries <= 0 and "directory entry limit reached" not in prof.limitations:
        prof.limitations.append("directory entry limit reached")

    # Languages: primary + any language with a meaningful share of source files
    total = sum(ext_counts.values()) or 1
    for lang, cnt in ext_counts.items():
        if cnt >= 3 and (cnt / total) >= 0.05:
            prof.languages.add(lang)
    if prof.primary_language is None and ext_counts:
        prof.primary_language = max(ext_counts, key=ext_counts.get)
        prof.languages.add(prof.primary_language)

    # Dependencies from manifests
    for mp in manifest_paths:
        low = mp.name.lower()
        parser = _MANIFEST_PARSERS.get(low)
        if low.endswith(".gemspec"):
            parser = _parse_gemfile
        if not parser:
            continue
        text = _read_capped(mp, root=root)
        found = parser(text)
        if found:
            prof.manifests.append(str(mp.relative_to(root)).replace("\\", "/"))
            for d in found:
                prof.dependencies.update(_dep_variants(d))
        if low in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "pyproject.toml", "setup.py", "pipfile"):
            prof.languages.add("python")
        elif low == "package.json":
            prof.languages.add("node")
        elif low == "go.mod":
            prof.languages.add("go")
        elif low in ("pom.xml", "build.gradle", "build.gradle.kts"):
            prof.languages.add("java")
        elif low == "gemfile" or low.endswith(".gemspec"):
            prof.languages.add("ruby")
            if "rails" in prof.dependencies:
                prof.frameworks.add("rails")
        elif low == "composer.json":
            prof.languages.add("php")
        elif low == "cargo.toml":
            prof.languages.add("rust")

    # Frameworks implied by dependencies
    for dep in list(prof.dependencies):
        for tok in _DEP_TO_STACK.get(dep, ()):  # exact key
            prof.frameworks.add(tok)
    # Layout hints
    for rel, stacks, lang in _LAYOUT_HINTS:
        candidate = root
        symlinked = False
        for component in Path(rel).parts:
            candidate = candidate / component
            if candidate.is_symlink():
                symlinked = True
                break
        if not symlinked and candidate.exists():
            prof.frameworks.update(stacks)
            prof.files.add(rel.lower())
            if lang:
                prof.languages.add(lang)
    return prof


# ---------------------------------------------------------------------------
# Matching / scoring
# ---------------------------------------------------------------------------

_MIN_SUBSTR_LEN = 4


def _match_tokens(tokens: Set[str], haystack: Set[str], files: Optional[Set[str]] = None) -> List[str]:
    """Return declared tokens that match the profile.

    ``haystack`` holds frameworks and dependency names: short tokens (< 4 chars)
    must match exactly to avoid `ci`/`ml`-style noise; longer tokens match as
    substrings in either direction so `spring` finds `spring-boot-starter-web`.

    ``files`` holds repository file / directory names and is matched *exactly*
    only (``dockerfile``, ``docker-compose.yml``, ``.github/workflows``). A
    substring match on arbitrary basenames would let a repo that merely ships
    a document named ``envoy-notes.md`` "prove" it runs Envoy.
    """
    hits: List[str] = []
    if not tokens or not (haystack or files):
        return hits
    files = files or set()
    for tok in tokens:
        t = tok.lower()
        if not t or t in _UNIVERSAL_TOKENS:
            continue
        if t in haystack or t in files:
            hits.append(tok)
            continue
        if len(t) < _MIN_SUBSTR_LEN:
            continue
        for h in haystack:
            if len(h) >= _MIN_SUBSTR_LEN and (t in h or h in t):
                hits.append(tok)
                break
    return hits


def skill_applies(meta: SkillMeta, profile: Optional[RepoProfile]) -> Tuple[bool, List[str]]:
    """Decide whether a skill applies to the profiled repo, with reasons."""
    if profile is None:
        return True, ["no-profile"]
    cat = (meta.category or "").lower()
    if cat in ("methodology", "gating"):
        return True, ["cross-cutting:" + cat]
    if cat == "learned":
        reasons = ["learned-memory"]
        if meta.languages & profile.languages:
            reasons.append("language:" + ",".join(sorted(meta.languages & profile.languages)))
        return True, reasons
    if meta.universal:
        return True, ["universal"]
    reasons: List[str] = []
    lang_hits = sorted(meta.languages & profile.languages)
    if lang_hits:
        reasons.append("language:" + ",".join(lang_hits))
    hay = profile.haystack()
    stack_hits = _match_tokens(meta.stacks, hay, profile.files)
    if stack_hits:
        reasons.append("stack:" + ",".join(sorted(set(stack_hits))))
    sig_hits = _match_tokens(meta.signals, hay, profile.files)
    if sig_hits:
        reasons.append("signal:" + ",".join(sorted(set(sig_hits))))
    if reasons:
        return True, reasons
    if not meta.declared:
        return True, ["undeclared-metadata"]
    if profile.limitations:
        return True, ["incomplete-profile: retained for review"]
    return False, ["no-match"]


_CATEGORY_BASE = {"learned": 2.5, "discovery": 2.0, "bug-classes": 2.0, "gating": 1.5, "methodology": 1.0}


def score_skill(meta: SkillMeta, profile: Optional[RepoProfile]) -> float:
    """Relevance score used to rank applicable skills inside the context budget."""
    cat = (meta.category or "").lower()
    score = _CATEGORY_BASE.get(cat, 1.0)
    if meta.cvss:
        score += min(max(meta.cvss, 0.0), 10.0) / 10.0
    if profile is None:
        return score
    lang_hits = meta.languages & profile.languages
    if lang_hits:
        score += 3.0
        if meta.primary_hit(profile):
            score += 0.5
    hay = profile.haystack()
    stack_hits = _match_tokens(meta.stacks, hay, profile.files)
    sig_hits = _match_tokens(meta.signals, hay, profile.files)
    score += 2.0 * min(len(set(stack_hits)), 3)
    score += 2.5 * min(len(set(sig_hits)), 3)
    if meta.universal and not (lang_hits or stack_hits or sig_hits):
        score += 0.5
    return score


# ---------------------------------------------------------------------------
# Phase 2 eligibility report
# ---------------------------------------------------------------------------

def applicability_report(profile: Optional[RepoProfile], items: Iterable[Tuple[str, str, str]]) -> Dict[str, Any]:
    """Evaluate ``(filename, content, category)`` items against ``profile``.

    Returns a JSON-safe report listing applicable and skipped skills with reasons
    and scores, sorted by score. Used by the Phase 2 audit log; eligibility is not proof of context injection.
    """
    applicable: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for name, content, category in items:
        meta = parse_skill_metadata(content, category)
        ok, reasons = skill_applies(meta, profile)
        entry = {
            "filename": name,
            "category": category,
            "reasons": reasons,
            "score": round(score_skill(meta, profile), 2),
            "languages": sorted(meta.languages),
            "stacks": sorted(meta.stacks)[:12],
            "universal": meta.universal,
        }
        (applicable if ok else skipped).append(entry)
    applicable.sort(key=lambda e: (-e["score"], e["category"], e["filename"]))
    skipped.sort(key=lambda e: (e["category"], e["filename"]))
    return {
        "profile": profile.to_dict() if profile else None,
        "applicable": applicable,
        "skipped": skipped,
        "applicable_count": len(applicable),
        "skipped_count": len(skipped),
    }


def summarize_report(report: Dict[str, Any], limit: int = 6) -> str:
    """One-line human summary for the audit stream."""
    prof = report.get("profile") or {}
    langs = ",".join(prof.get("languages") or []) or "unknown"
    fws = ",".join((prof.get("frameworks") or [])[:limit])
    top = ", ".join(e["filename"].replace(".md", "") for e in (report.get("applicable") or [])[:limit])
    skipped = report.get("skipped_count", 0)
    parts = [f"Skill eligibility: {report.get('applicable_count', 0)} eligible, {skipped} unmatched for languages={langs}"]
    if fws:
        parts.append(f"stacks={fws}")
    if top:
        parts.append(f"top: {top}")
    return "; ".join(parts)
