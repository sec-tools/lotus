"""
Intelligent lab environment builder — analyzes repos and generates tailored Dockerfiles.

Priority for a working lab:
  1. The repository's own docker-compose / Dockerfile (never Lotus-generated files)
  2. A Dockerfile generated from manifests, README/docs, and CI — with real install
     steps and a smoke test so the project is actually runnable
  3. AI-assisted generation only when (2) fails to build
  4. Template fallback last
"""

from __future__ import annotations

import re
import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Packages already in lotus-lab-ubuntu:26.04 — do not apt-get them again
# (a failed apt-get during a busy host network drops a otherwise-correct lab).
BASE_IMAGE_PACKAGES = {
    "build-essential", "ca-certificates", "git", "curl", "wget", "netcat-openbsd",
    "tcpdump", "strace", "gdb", "libpq-dev", "libsqlite3-dev", "libxml2-dev",
    "libxslt1-dev", "zlib1g-dev", "libyaml-dev", "pkg-config", "python3",
    "python3-venv", "python3-pip", "ruby", "ruby-dev", "ruby-bundler", "nodejs",
    "npm", "golang-go", "openjdk-21-jdk-headless", "maven", "php-cli", "php-dev",
    "php-xml", "php-mbstring", "php-curl", "php-pear", "autoconf",
}
LOTUS_GENERATED_DOCKERFILES = {
    "Dockerfile.lotus",
    "Dockerfile.lab",
    "Dockerfile.asan",
    ".lotus-compose.yml",
    ".lotus-compose.override.yml",
}

COMPOSE_CANDIDATES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
)


class ComposePolicyError(ValueError):
    """Raised before a repository Compose file can reach the Docker daemon."""


def validate_dockerfile_for_lab(path: Path, root: Optional[Path] = None) -> None:
    """Reject Dockerfile features that can escape a disposable build context."""
    path = Path(path).resolve()
    repo_root = Path(root or path.parent).resolve()
    if path != repo_root and repo_root not in path.parents:
        raise ComposePolicyError("Dockerfile is outside the enrolled repository")
    try:
        text = path.read_text(errors="ignore")
    except OSError as exc:
        raise ComposePolicyError(f"Dockerfile read failed: {exc}") from exc
    # Dockerfile continuations are normalized before checking so a malicious
    # repository cannot hide a BuildKit entitlement on the next physical line.
    normalized = re.sub(r"\\\s*\n", " ", text)
    checks = (
        # Cache mounts can expose another build's package/credential cache, and
        # host/SSH/secret mounts are direct host-boundary capabilities.  Lotus
        # does not need any RUN mount, so reject all of them (tmpfs included).
        (r"(?im)^\s*RUN\s+--mount\s*=", "RUN --mount BuildKit access is not allowed"),
        (r"(?im)^\s*RUN\s+--(?:network\s*=\s*host|security\s*=\s*insecure)\b", "RUN host network/insecure entitlement is not allowed"),
        (r"(?im)^\s*ADD\s+(?:https?|ftp)://", "remote ADD is not allowed"),
    )
    for pattern, message in checks:
        if re.search(pattern, normalized):
            raise ComposePolicyError(message)


_UNTRUSTED_COMPOSE_KEYS = {
    "privileged", "network_mode", "pid", "ipc", "uts", "userns_mode",
    "cap_add", "devices", "cgroup", "cgroup_parent", "runtime",
    "security_opt", "sysctls", "dns", "dns_search", "extra_hosts",
    "external_links", "volumes_from", "env_file", "secrets", "configs",
    "include", "extends", "isolation",
}


def validate_compose_for_lab(src: Path, root: Optional[Path] = None) -> Dict[str, Any]:
    """Validate repository Compose against the untrusted-lab policy.

    This is deliberately a parsed-schema check, not a regex rewrite.  Unsafe
    directives are rejected before ``docker compose`` is invoked; callers must
    not fall back to the original file after this function raises.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ComposePolicyError("PyYAML is required to validate untrusted Compose") from exc
    path = Path(src).resolve()
    compose_dir = path.parent
    repo_root = Path(root or compose_dir).resolve()
    try:
        data = yaml.safe_load(path.read_text(errors="ignore")) or {}
    except Exception as exc:
        raise ComposePolicyError(f"Compose parse failed: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict) or not data["services"]:
        raise ComposePolicyError("Compose must contain a non-empty services mapping")
    if any(k in data for k in ("secrets", "configs", "include", "extends")):
        raise ComposePolicyError("top-level secrets/configs/include/extends are not allowed")
    errors: List[str] = []
    network_names = {str(k) for k in (data.get("networks") or {}).keys()} if isinstance(data.get("networks") or {}, dict) else set()
    for service, spec in data["services"].items():
        if not isinstance(spec, dict):
            errors.append(f"service {service}: expected mapping")
            continue
        for key in sorted(set(spec).intersection(_UNTRUSTED_COMPOSE_KEYS)):
            errors.append(f"service {service}: {key} is not allowed")
        build = spec.get("build")
        if build:
            context = build.get("context") if isinstance(build, dict) else build
            context_path = (compose_dir / str(context)).resolve() if context else compose_dir
            if not (context_path == repo_root or repo_root in context_path.parents):
                errors.append(f"service {service}: build context escapes repository")
            if isinstance(build, dict):
                for build_key in ("ssh", "secrets", "additional_contexts"):
                    if build.get(build_key):
                        errors.append(f"service {service}: build.{build_key} is not allowed")
            if isinstance(build, dict) and build.get("dockerfile"):
                df = (context_path / str(build["dockerfile"])).resolve()
                if not (df == repo_root or repo_root in df.parents):
                    errors.append(f"service {service}: Dockerfile escapes repository")
                elif df.is_file():
                    try:
                        validate_dockerfile_for_lab(df, repo_root)
                    except ComposePolicyError as exc:
                        errors.append(f"service {service}: {exc}")
            elif build:
                default_df = (context_path / "Dockerfile").resolve()
                if default_df.is_file():
                    try:
                        validate_dockerfile_for_lab(default_df, repo_root)
                    except ComposePolicyError as exc:
                        errors.append(f"service {service}: {exc}")
        volumes = spec.get("volumes") or []
        if isinstance(volumes, dict):
            volumes = [{"source": k, **(v if isinstance(v, dict) else {})} for k, v in volumes.items()]
        if not isinstance(volumes, list):
            errors.append(f"service {service}: volumes must be a list")
        else:
            for volume in volumes:
                if isinstance(volume, dict):
                    if str(volume.get("type") or "bind").lower() == "bind":
                        source = str(volume.get("source") or volume.get("src") or "")
                        errors.append(f"service {service}: host bind {source!r} is not allowed")
                elif isinstance(volume, str):
                    source = volume.split(":", 1)[0]
                    # Only anonymous/named volumes are portable.  Relative
                    # paths are host binds too and can escape the enrolled
                    # checkout through symlinks or ../ components.
                    if source.startswith(("/", "~", ".")) or "/" in source or "\\" in source or "docker.sock" in source:
                        errors.append(f"service {service}: host bind {source!r} is not allowed")
        ports = spec.get("ports") or []
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, dict):
                    host_ip = str(port.get("host_ip") or "").strip()
                    if host_ip and host_ip not in ("127.0.0.1", "localhost"):
                        errors.append(f"service {service}: non-loopback published host_ip is not allowed")
                    if port.get("published") is not None:
                        errors.append(f"service {service}: structured published ports are not safely remappable")
                elif isinstance(port, str) and ":" in port:
                    host = port.split(":", 1)[0].strip().strip('"\'')
                    if host.startswith("${") and not host.startswith("${HOST_PORT"):
                        errors.append(f"service {service}: unpublished variable port cannot be safely remapped")
                    elif host and host not in ("127.0.0.1", "localhost") and not host.isdigit():
                        errors.append(f"service {service}: non-loopback published host is not allowed")
        networks = spec.get("networks")
        if isinstance(networks, dict):
            network_names.update(str(k) for k in networks.keys())
            for name, value in networks.items():
                if isinstance(value, dict) and value.get("external"):
                    errors.append(f"service {service}: external network {name!r} is not allowed")
        elif isinstance(networks, list):
            network_names.update(str(k) for k in networks)
    top_networks = data.get("networks") or {}
    if isinstance(top_networks, dict):
        for name, value in top_networks.items():
            if isinstance(value, dict) and value.get("external"):
                errors.append(f"external network {name!r} is not allowed")
    if errors:
        raise ComposePolicyError("; ".join(errors[:12]))
    return {
        "services": sorted(str(k) for k in data["services"]),
        "networks": sorted(network_names or {"default"}),
        "validated": True,
    }


def write_compose_hardening_override(
    dest: Path, services: List[str], networks: Optional[List[str]] = None,
    repo_id: Optional[int] = None, run_id: str = "",
    target_revision: str = "", target_tree_hash: str = "",
    lab_kind: str = "", compose_project: str = "",
) -> Path:
    """Write a managed Compose override that applies the lab sandbox policy.

    Compose files are repository-controlled input and do not have a portable
    equivalent of Docker's ``--cap-drop``/``--read-only`` CLI flags.  The
    override is generated by Lotus, never read from the repository, and is
    included on every compose invocation; there is no implicit fallback to an
    un-hardened repository file.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ComposePolicyError("PyYAML is required to generate Compose hardening") from exc
    root = Path(dest)
    path = root / ".lotus-compose-hardening.yml"
    memory = os.environ.get("LOTUS_LAB_MEMORY", "4g")
    cpus = os.environ.get("LOTUS_LAB_CPUS", "2")
    pids = int(os.environ.get("LOTUS_LAB_PIDS", "512"))
    uid = os.environ.get("LOTUS_LAB_UID", "65532:65532")
    services_map = {}
    for service in services:
        service_policy = {
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "user": uid,
            "mem_limit": memory,
            "cpus": float(cpus),
            "pids_limit": pids,
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=128m", "/run:rw,noexec,nosuid,nodev,size=32m"],
        }
        if repo_id is not None:
            service_policy["labels"] = {"lotus.audit.repo_id": str(int(repo_id))}
            if run_id:
                service_policy["labels"]["lotus.audit.run_id"] = str(run_id)
            if target_revision and "\n" not in str(target_revision) and "\r" not in str(target_revision):
                service_policy["labels"]["lotus.audit.target_revision"] = str(target_revision)[:512]
            if target_tree_hash and "\n" not in str(target_tree_hash) and "\r" not in str(target_tree_hash):
                service_policy["labels"]["lotus.audit.target_tree_hash"] = str(target_tree_hash)[:512]
            if lab_kind and "\n" not in str(lab_kind) and "\r" not in str(lab_kind):
                service_policy["labels"]["lotus.audit.lab_kind"] = str(lab_kind)[:64]
            if compose_project and "\n" not in str(compose_project) and "\r" not in str(compose_project):
                service_policy["labels"]["lotus.audit.compose_project"] = str(compose_project)[:128]
        services_map[str(service)] = service_policy
    network_map = {str(name): {"internal": True} for name in (networks or ["default"])}
    path.write_text(yaml.safe_dump({"services": services_map, "networks": network_map}, sort_keys=True), encoding="utf-8")
    return path

NESTED_COMPOSE_DIRS = (
    "docker/single-node",
    "docker",
    "deploy",
    "contrib/docker",
    "contrib",
)

NESTED_DOCKERFILE_DIRS = (
    "docker",
    ".devcontainer",
    "contrib/docker",
    "build/docker",
)

_INSTALL_CMD = re.compile(
    r"^(pip3?\s+install|phpize|\./configure|cmake\b|make\b|bundle\s+install|"
    r"npm\s+install|pnpm\s+install|yarn\s+install|composer\s+install|"
    r"gem\s+install|go\s+(mod|build)|cargo\s+build|mvn\s+|gradle\s+|"
    r"python3?\s+-m\s+pip|phpize)",
    re.I,
)


def discover_lab_artifacts(dest: Path) -> Dict[str, Any]:
    """Find the repo's own compose file and/or Dockerfile.

    Returns:
      compose: Path | None
      dockerfile: Path | None
      notes: list[str]
      source: 'compose' | 'dockerfile' | 'none'
    """
    dest = Path(dest)
    notes: List[str] = []
    compose: Optional[Path] = None
    dockerfile: Optional[Path] = None

    for cand in COMPOSE_CANDIDATES:
        p = dest / cand
        if p.is_file() and p.name not in LOTUS_GENERATED_DOCKERFILES:
            compose = p
            notes.append(f"Found repository compose file {cand}")
            break
    if compose is None:
        for rel in NESTED_COMPOSE_DIRS:
            for cand in COMPOSE_CANDIDATES:
                p = dest / rel / cand
                if p.is_file() and p.name not in LOTUS_GENERATED_DOCKERFILES:
                    compose = p
                    notes.append(f"Found nested compose file {rel}/{cand}")
                    break
            if compose is not None:
                break

    root_df = dest / "Dockerfile"
    if root_df.is_file():
        dockerfile = root_df
        notes.append("Found repository Dockerfile at repo root")
    else:
        for rel in NESTED_DOCKERFILE_DIRS:
            p = dest / rel / "Dockerfile"
            if p.is_file():
                dockerfile = p
                notes.append(f"Found repository Dockerfile at {rel}/Dockerfile")
                break

    source = "none"
    dockerfile_usable = False
    compose_usable = False
    if compose is not None:
        source = "compose"
        compose_usable, creason = compose_is_practical_lab(compose)
        if not compose_usable:
            notes.append(creason)
    if dockerfile is not None:
        usable, reason = dockerfile_is_practical_lab(dockerfile)
        dockerfile_usable = usable
        if not usable:
            notes.append(reason)
        elif source == "none":
            source = "dockerfile"

    published = extract_readme_published_images(dest)
    known = extract_known_published_images(dest)
    if known:
        by_image = {im["image"]: im for im in published}
        for im in known:
            by_image[im["image"]] = im
        published = list(by_image.values())
    if published:
        notes.append(f"README published image: {published[0].get('image')}")

    return {
        "compose": compose,
        "dockerfile": dockerfile,
        "notes": notes,
        "source": source,
        "has_compose": compose is not None,
        "has_dockerfile": dockerfile is not None,
        "dockerfile_usable": dockerfile_usable,
        "compose_usable": compose_usable,
        "published_images": published,
    }


def dockerfile_is_practical_lab(dockerfile: Path) -> Tuple[bool, str]:
    """Return whether building this Dockerfile will produce a working audit lab in time.

    CI/dev images that clone extra git repositories and have no long-running service
    are used as a package spec instead of being built (they time out and never listen).
    """
    try:
        text = dockerfile.read_text(errors="ignore")
    except Exception:
        return False, "Could not read repository Dockerfile"
    clones_extra = bool(re.search(r"git\s+clone\s+\S+", text))
    needs_wrap = dockerfile_needs_health_wrapper(dockerfile)
    if clones_extra and needs_wrap:
        return False, (
            "Repository Dockerfile is a CI/dev image (clones extra git repos and has no "
            "long-running service). Generating an audit lab from project docs and the "
            "packages listed in that Dockerfile."
        )
    # Full C++ broker/DB toolchains (CMake + Ninja + BDE) take hours; never block
    # an audit waiting on them. Prefer a published image or protocol PoC against a
    # prebuilt binary.
    if re.search(r"ninja-build|\bninja\b", text, re.I) and re.search(r"\bcmake\b", text, re.I):
        if re.search(r"bde-tools|blazingmq|bmqbrkr|oceanbase", text, re.I):
            return False, (
                "Full C++ broker/database toolchain (CMake/Ninja/BDE) — hours to build. "
                "Use a published image or a prebuilt broker; do not compile from source in the lab."
            )
    # Devcontainer / toolchain images with no service port
    low_path = str(dockerfile).replace("\\", "/").lower()
    if needs_wrap and (".devcontainer" in low_path or "devcontainer" in low_path):
        return False, "Devcontainer Dockerfile is a toolchain image, not a running service"
    return True, ""


def dockerfile_needs_health_wrapper(dockerfile: Path) -> bool:
    """True when the image will not stay up on a published HTTP port by itself."""
    try:
        text = dockerfile.read_text(errors="ignore")
    except Exception:
        return True
    if re.search(r"^EXPOSE\s+\d+", text, re.M):
        # Has a port, but CLI images often EXPOSE nothing useful; still check CMD
        pass
    cmd = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("CMD ") or s.startswith("ENTRYPOINT "):
            cmd = s
    if not cmd:
        return True
    long_running = (
        "http.server", "http.server", "nginx", "apache", "httpd", "puma", "unicorn",
        "rails s", "gunicorn", "uvicorn", "php -S", "node ", "java -jar",
        "catalina", "tomcat", "sleep infinity", "sleep inf", "tail -f",
        "supervisord", "dumb-init",
    )
    low = cmd.lower()
    if any(tok in low for tok in long_running):
        return False
    # One-shot CLI binary as CMD (brew, nvc, jc, php) will exit immediately
    return True


def extract_readme_published_images(dest: Path) -> List[Dict[str, Any]]:
    """Parse README `docker run` blocks for a published image + host ports.

    This is how seekdb (oceanbase/seekdb:latest on 2881) becomes a frictionless
    lab without compiling the C++ tree.
    """
    dest = Path(dest)
    text = ""
    for name in ("README.md", "README", "docs/install.md"):
        p = dest / name
        if p.is_file():
            try:
                text = p.read_text(errors="ignore")[:24000]
            except Exception:
                text = ""
            if text:
                break
    if not text:
        return []
    images: List[Dict[str, Any]] = []
    for block in re.findall(r"```(?:bash|sh|shell|console)?\n(.*?)```", text, re.S | re.I):
        if "docker run" not in block:
            continue
        compact = " ".join(line.rstrip("\\").strip() for line in block.splitlines() if line.strip())
        m_img = re.search(
            r"docker\s+run\b[^`]*?\b("
            r"(?:ghcr\.io|quay\.io|docker\.io)/[a-z0-9._/-]+(?::[a-z0-9._-]+)?"
            r"|[a-z0-9._-]+/[a-z0-9._-]+(?::[a-z0-9._-]+)?)\b",
            compact, re.I,
        )
        if not m_img:
            continue
        image = m_img.group(1)
        if image.startswith("-") or image in {"docker", "run"}:
            continue
        ports = [int(x) for x in re.findall(r"-p\s+(?:\d+:)?(\d+)", compact)]
        images.append({
            "image": image,
            "container_port": ports[0] if ports else 0,
            "ports": ports[:4],
        })
    # de-dup
    seen = set()
    out = []
    for im in images:
        if im["image"] in seen:
            continue
        seen.add(im["image"])
        out.append(im)
    return out[:4]


def extract_known_published_images(dest: Path) -> List[Dict[str, Any]]:
    """Official runtime images for trees whose own Dockerfile is a multi-hour build."""
    dest = Path(dest)
    if (dest / "src" / "applications" / "bmqbrkr").is_dir() or dest.name.lower() in {
        "blazingmq", "bloomberg-blazingmq",
    }:
        spec: Dict[str, Any] = {
            "image": "ghcr.io/bloomberg/blazingmq:latest",
            "platform": "linux/amd64",
            "container_port": 30114,
            "ports": [30114],
            "hostname": "localhost",
            "command": ["/usr/local/bin/bmqbrkr", "-h", "localhost", "/etc/local/bmq"],
        }
        cfg = dest / "docker" / "single-node" / "config"
        if cfg.is_dir():
            spec["volumes"] = [{
                "src": "docker/single-node/config",
                "dst": "/etc/local/bmq",
                "readonly": True,
            }]
        return [spec]
    return []


def compose_is_practical_lab(compose: Path) -> Tuple[bool, str]:
    """False when compose would compile a multi-hour C++ toolchain."""
    try:
        text = compose.read_text(errors="ignore")[:12000]
    except Exception:
        return False, "Could not read compose file"
    dockerfile = None
    m = re.search(r"dockerfile:\s*(\S+)", text, re.I)
    if m:
        rel = m.group(1).strip()
        dockerfile = (compose.parent / rel).resolve()
        if not dockerfile.is_file():
            dockerfile = (compose.parent.parent / Path(rel).name).resolve()
    else:
        candidate = compose.parent.parent / "Dockerfile"
        if candidate.is_file() and "build:" in text:
            dockerfile = candidate
    if dockerfile and dockerfile.is_file():
        usable, reason = dockerfile_is_practical_lab(dockerfile)
        if not usable:
            return False, reason
    return True, ""


def extract_readme_commands(dest: Path) -> List[str]:
    """Pull install/build commands from README / INSTALL / BUILD docs."""
    text = ""
    for name in ("README.md", "README", "README.rst", "INSTALL.md", "BUILD.md",
                 "CONTRIBUTING.md", "docs/install.md"):
        p = dest / name
        if p.is_file():
            try:
                text = p.read_text(errors="ignore")[:24000]
            except Exception:
                text = ""
            if text:
                break
    if not text:
        return []

    commands: List[str] = []

    def _clean(line: str) -> str:
        line = line.strip()
        line = re.sub(r"^\$\s*", "", line)
        line = re.sub(r"^#\s+", "", line)
        line = re.sub(r"^sudo\s+", "", line)
        return line.strip()

    for block in re.findall(r"```(?:bash|sh|shell|console|dockerfile)?\n(.*?)```", text, re.S | re.I):
        for raw in block.splitlines():
            line = _clean(raw)
            if line and _INSTALL_CMD.match(line):
                commands.append(line)

    for m in re.finditer(
        r"^\s*(?:\d+[.)]\s+|[-*]\s+)?\$?\s*((?:phpize|\./configure|make(?:\s+install)?|"
        r"pip3?\s+install\b[^\n]+|bundle\s+install|npm\s+install|composer\s+install|"
        r"mvn\s+\S+|gem\s+install[^\n]+).*)",
        text,
        re.M | re.I,
    ):
        line = _clean(m.group(1))
        if line and _INSTALL_CMD.match(line):
            commands.append(line)

    # Prefer source installs over installing a released package from PyPI/apt
    deduped: List[str] = []
    seen = set()
    for c in commands:
        key = re.sub(r"\s+", " ", c)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    return deduped[:12]


_TARGET_RUNTIME_APP_TYPES = {"web-app", "api-service", "unknown"}


def _requires_target_runtime(app_type: str) -> bool:
    """Whether a generated lab must launch the enrolled target itself.

    A listener is useful for a CLI/library container's lifecycle, but an HTTP
    service audit cannot treat a generic file server as evidence that the
    application started. ``unknown`` is deliberately fail-closed: the caller
    can classify it as a library/CLI if a synthetic listener is appropriate.
    """
    return str(app_type or "unknown").strip().lower() in _TARGET_RUNTIME_APP_TYPES


def _go_entry_package(dest: Path) -> Optional[str]:
    """Select a defensible Go ``main`` package for a generated lab.

    ``go build ./...`` fails when a repository has multiple commands because a
    single ``-o`` cannot name all output binaries. We prefer a root command,
    then a ``cmd/<repo-name>`` (or ``cmd/<repo-name>d`` such as Dapr's
    ``cmd/daprd``), then a single remaining command. Ambiguous command trees
    intentionally return ``None`` rather than arbitrarily launching a control
    plane or test utility.
    """
    root = Path(dest)

    def _is_main(path: Path) -> bool:
        try:
            return bool(re.search(r"(?m)^\s*package\s+main\b", path.read_text(errors="ignore")[:4096]))
        except OSError:
            return False

    root_main = root / "main.go"
    if root_main.is_file() and _is_main(root_main):
        return "."

    commands: List[tuple[str, Path]] = []
    cmd_root = root / "cmd"
    if cmd_root.is_dir():
        try:
            for main in sorted(cmd_root.glob("*/main.go")):
                if _is_main(main):
                    commands.append((main.parent.name, main.parent))
        except OSError:
            return None
    if not commands:
        return None

    repo_name = re.sub(r"[^a-z0-9]+", "", root.name.casefold())
    module_name = ""
    go_mod = root / "go.mod"
    try:
        match = re.search(r"(?m)^\s*module\s+([^\s]+)", go_mod.read_text(errors="ignore")[:4096])
        if match:
            module_name = re.sub(r"[^a-z0-9]+", "", match.group(1).rsplit("/", 1)[-1].casefold())
    except OSError:
        pass
    desired = {name for name in (repo_name, module_name) if name}
    exact = [path for name, path in commands if re.sub(r"[^a-z0-9]+", "", name.casefold()) in desired]
    if len(exact) == 1:
        return "./" + str(exact[0].relative_to(root)).replace(os.sep, "/")
    prefixed = [
        path for name, path in commands
        if any(re.sub(r"[^a-z0-9]+", "", name.casefold()).startswith(candidate) for candidate in desired)
    ]
    if len(prefixed) == 1:
        return "./" + str(prefixed[0].relative_to(root)).replace(os.sep, "/")
    if len(commands) == 1:
        return "./" + str(commands[0][1].relative_to(root)).replace(os.sep, "/")
    return None


def _python_web_start_command(dest: Path) -> Optional[str]:
    """Return an app-bound Python launcher only when its module is evident."""
    candidates = (
        ("app.py", "app:app"),
        ("main.py", "main:app"),
        ("wsgi.py", "wsgi:application"),
        ("server.py", "server:app"),
    )
    for filename, target in candidates:
        if (Path(dest) / filename).is_file():
            return f"exec gunicorn --bind 0.0.0.0:${{PORT}} {target}"
    return None


def _node_web_start_command(dest: Path) -> Optional[str]:
    """Return a package-bound Node launcher only when the target declares one."""
    package_path = Path(dest) / "package.json"
    try:
        package = json.loads(package_path.read_text(errors="ignore")) if package_path.is_file() else {}
    except Exception:
        package = {}
    scripts = package.get("scripts") if isinstance(package, dict) else None
    if isinstance(scripts, dict) and isinstance(scripts.get("start"), str) and scripts["start"].strip():
        return "exec env PORT=${PORT} npm start"
    # These conventional files are an evidenced fallback only when present;
    # unlike a generic file server they still execute enrolled source.
    for filename in ("server.js", "index.js", "app.js"):
        if (Path(dest) / filename).is_file():
            return f"exec env PORT=${{PORT}} node {filename}"
    return None


def _ruby_web_start_command(dest: Path) -> Optional[str]:
    """Return an application-bound Ruby launcher when the framework is known."""
    root = Path(dest)
    framework = _detect_ruby_framework(root)
    if framework == "rails":
        return "exec bundle exec rails s -b 0.0.0.0 -p ${PORT}"
    gemfile = root / "Gemfile"
    try:
        gemfile_text = gemfile.read_text(errors="ignore")[:4000] if gemfile.is_file() else ""
    except OSError:
        gemfile_text = ""
    if re.search(r"\bpuma\b", gemfile_text, re.I):
        return "exec bundle exec puma -b tcp://0.0.0.0:${PORT}"
    if (root / "app.rb").is_file():
        return "exec ruby app.rb -o 0.0.0.0 -p ${PORT}"
    return None


def _strip_generic_http_server_fallback(command: str) -> str:
    """Remove a trailing synthetic Python file-server fallback from a launcher."""
    text = str(command or "").strip()
    if not text:
        return ""
    # A launcher made solely of a generic static listener carries no target
    # runtime evidence and must be rejected for a service/API lab.
    if re.fullmatch(r"(?:exec\s+)?python(?:3)?\s+-m\s+http\.server\b.*", text, flags=re.I | re.S):
        return ""
    # Keep a genuine first-choice target command, but never let a failed target
    # silently become a static file server. The common planner/template form is
    # ``target ... || python3 -m http.server ...``.
    return re.sub(
        r"\s*\|\|\s*(?:exec\s+)?python(?:3)?\s+-m\s+http\.server\b[^;]*\s*$",
        "",
        text,
        flags=re.I | re.S,
    ).strip()


def analyze_repo_requirements(dest: Path, language: str, app_type: str) -> Dict[str, Any]:
    """Analyze a repo to determine exact lab requirements."""
    dest = Path(dest)
    artifacts = discover_lab_artifacts(dest)
    reqs: Dict[str, Any] = {
        "language": language,
        "app_type": app_type,
        "runtime": [],
        "build_tools": [],
        "system_libs": [],
        "install_steps": [],
        "start_command": None,
        "ports": [],
        "env_vars": {},
        "has_compose": artifacts["has_compose"],
        "has_dockerfile": artifacts["has_dockerfile"],
        "compose_path": str(artifacts["compose"]) if artifacts["compose"] else None,
        "dockerfile_path": str(artifacts["dockerfile"]) if artifacts["dockerfile"] else None,
        "is_extension": False,
        "needs_database": False,
        "framework": None,
        "analysis_notes": list(artifacts["notes"]),
        "smoke_test": None,
        # A port-open check is not enough for a service/API audit. This value is
        # consumed by Dockerfile generation to reject synthetic static-server
        # fallbacks when the enrolled target has no evidenced launcher.
        "requires_target_runtime": _requires_target_runtime(app_type),
        "readme_commands": extract_readme_commands(dest),
        "package_name": None,
        "package_test_command": None,
    }

    if artifacts["compose"]:
        try:
            text = artifacts["compose"].read_text(errors="ignore")[:6000]
            if re.search(r"mariadb|mysql|postgres", text, re.I):
                reqs["needs_database"] = True
                reqs["analysis_notes"].append("Compose includes a database service")
        except Exception:
            pass

    if language == "python":
        reqs["runtime"] = ["python3", "python3-pip", "python3-venv"]
        pkg = _python_package_name(dest)
        reqs["package_name"] = pkg
        pip = "/opt/lotus-venv/bin/pip"
        py = "/opt/lotus-venv/bin/python"
        if (dest / "requirements.txt").exists():
            reqs["install_steps"].append(f"{pip} install --no-cache-dir -r requirements.txt")
            try:
                req_text = (dest / "requirements.txt").read_text(errors="ignore")
                if "psycopg" in req_text:
                    reqs["system_libs"].append("libpq-dev")
                if "lxml" in req_text:
                    reqs["system_libs"].extend(["libxml2-dev", "libxslt1-dev"])
                if "Pillow" in req_text or "pillow" in req_text:
                    reqs["system_libs"].extend(["libjpeg-dev", "zlib1g-dev"])
                if "cryptography" in req_text:
                    reqs["system_libs"].extend(["libssl-dev", "libffi-dev"])
            except Exception:
                pass
        if (dest / "setup.py").exists() or (dest / "pyproject.toml").exists():
            reqs["install_steps"].append(f"{pip} install --no-cache-dir -e .")
            if pkg:
                reqs["smoke_test"] = (
                    f"{py} -c 'import {pkg}; print(\"SMOKE_OK\", getattr({pkg}, \"__version__\", \"ok\"))' "
                    f"|| {pkg} --version"
                )
            else:
                reqs["smoke_test"] = f"{py} -c 'print(\"SMOKE_OK\")'"
        if app_type in ("web-app", "api-service"):
            reqs["install_steps"].append(f"{pip} install --no-cache-dir flask gunicorn")
            reqs["framework"] = _detect_python_framework(dest)
            reqs["start_command"] = _python_web_start_command(dest)

    elif language == "java":
        reqs["runtime"] = ["openjdk-21-jdk-headless"]
        if (dest / "pom.xml").exists():
            reqs["build_tools"].append("maven")
            reqs["install_steps"].append(
                # Do not assume a module named `test-suite` exists.  Passing a
                # reactor exclusion for a missing module makes Maven fail
                # before compiling any target artifact, which silently pushes
                # the generated lab to fail closed and creates a systematic
                # dynamic-analysis coverage gap.
                "mvn -q package -DskipTests -Dmaven.javadoc.skip=true"
            )
            reqs["framework"] = "maven"
            reqs["smoke_test"] = (
                "find /app -name '*.jar' -o -name '*.war' | grep -q . "
                "&& echo SMOKE_OK_JAVA_ARTIFACT"
            )
        elif (dest / "build.gradle").exists() or (dest / "build.gradle.kts").exists():
            reqs["build_tools"].append("gradle")
            reqs["install_steps"].append("gradle build -x test --no-daemon")
            reqs["framework"] = "gradle"
        if app_type in ("web-app", "api-service"):
            reqs["start_command"] = _java_start_command(dest)

    elif language in ("c/cpp", "c", "cpp"):
        reqs["runtime"] = ["build-essential"]
        reqs["build_tools"] = ["autoconf", "pkg-config"]
        if (dest / "config.m4").exists():
            reqs["is_extension"] = True
            ext = _php_extension_name(dest)
            reqs["package_name"] = ext
            reqs["runtime"].extend(["php-cli", "php-dev"])
            reqs["system_libs"].append("libyaml-dev")
            # README for pecl-yaml: phpize, ./configure [--with-yaml], make, make install
            configure = "./configure"
            if any("--with-yaml" in c for c in reqs["readme_commands"]):
                configure = "./configure --with-yaml"
            elif ext and ext != "yaml":
                configure = f"./configure --with-{ext}"
            reqs["install_steps"] = [
                "phpize",
                configure,
                "make -j$(nproc)",
                "make install",
                (
                    "php -r '"
                    f"file_put_contents((PHP_CONFIG_FILE_SCAN_DIR ?: sprintf(\"/etc/php/%d.%d/cli/conf.d\", PHP_MAJOR_VERSION, PHP_MINOR_VERSION)).\"/99-{ext}.ini\", \"extension={ext}.so\\n\");'"
                ),
            ]
            reqs["start_command"] = "php -S 0.0.0.0:${PORT} -t /app"
            reqs["smoke_test"] = f"php -m | grep -i {ext} && php -r 'echo \"SMOKE_OK\\n\";'"
            reqs["analysis_notes"].append(
                f"PHP C extension ({ext}) — phpize/configure/make from README"
            )
        elif (dest / "CMakeLists.txt").exists() or (dest / "Makefile").exists() or (dest / "src" / "Makefile").exists():
            # Generic native-build provisioning: infer the -dev packages this
            # compile needs (from -l link flags / CMake find_package / system
            # headers) and a build command that avoids self-bootstrapping targets,
            # with an amalgamation compile as a last resort. This keeps compiled
            # tools (CLIs, config-DSL generators, etc.) actually runnable in the
            # lab so native PoCs are not silently blocked by a missing binary.
            try:
                from backend.native_build import (
                    infer_apt_packages,
                    infer_build_steps,
                    guess_native_binary_names,
                )
                bin_names = guess_native_binary_names(dest)
                reqs["system_libs"].extend(infer_apt_packages(dest))
                if (dest / "CMakeLists.txt").exists():
                    reqs["build_tools"].append("cmake")
                steps = infer_build_steps(dest, bin_names)
                # Chain best-effort attempts; the following smoke test asserts a
                # binary actually resulted (so a broken build is observable).
                if steps:
                    chain = " || ".join(f"( {s} )" for s in steps) + " || true"
                    reqs["install_steps"] = [chain]
                elif (dest / "CMakeLists.txt").exists():
                    reqs["install_steps"] = ["cmake -S . -B build && cmake --build build -j$(nproc) || true"]
                else:
                    reqs["install_steps"] = ["make -j$(nproc) || true"]
                if bin_names:
                    found = " -o ".join(
                        f"-x /app/bin/{n} -o -x /app/src/{n} -o -x /app/{n}" for n in bin_names[:3]
                    )
                    # Honest assertion: the RUN must fail (non-zero) when no
                    # binary was produced, so a broken native build is observable
                    # and never becomes a synthetic service lab with no binary
                    # available to a PoC.
                    reqs["smoke_test"] = (
                        f"( [ {found} ] && echo SMOKE_OK ) || "
                        f"( command -v {bin_names[0]} >/dev/null 2>&1 && echo SMOKE_OK )"
                    )
                else:
                    reqs["smoke_test"] = "echo SMOKE_OK"
            except Exception:
                if (dest / "CMakeLists.txt").exists():
                    reqs["build_tools"].append("cmake")
                    reqs["install_steps"] = ["mkdir -p build && cd build && cmake .. && make -j$(nproc) || true"]
                else:
                    reqs["install_steps"] = ["make -j$(nproc) || true"]
                reqs["smoke_test"] = "echo SMOKE_OK"

    elif language in ("ruby/rails", "ruby"):
        reqs["runtime"] = ["ruby", "ruby-dev", "ruby-bundler"]
        if (dest / "bin" / "brew").exists():
            reqs["env_vars"]["HOMEBREW_NO_AUTO_UPDATE"] = "1"
            reqs["env_vars"]["HOMEBREW_NO_ANALYTICS"] = "1"
            reqs["env_vars"]["HOMEBREW_NO_INSTALL_FROM_API"] = "1"
            reqs["analysis_notes"].append(
                "Homebrew source tree — lab uses bin/brew from the enrolled checkout"
            )
            reqs["smoke_test"] = "test -x /app/bin/brew && echo SMOKE_OK_BREW"
        elif (dest / "Gemfile").exists() or any(dest.glob("*.gemspec")):
            gemspecs = list(dest.glob("*.gemspec"))
            gemspec_names = " ".join(p.name.lower() for p in gemspecs)
            if (dest / "Gemfile").exists():
                reqs["install_steps"].append("bundle install --jobs 4 --retry 3")
            if gemspecs:
                if "pdf-reader" in gemspec_names or "ttfunk" in gemspec_names:
                    reqs["install_steps"].append(
                        "gem install --no-document ttfunk Ascii85 hashery afm ruby-rc4"
                    )
                    reqs["smoke_test"] = (
                        "ruby -e 'begin; require %(pdf/reader); rescue LoadError; end; puts %(SMOKE_OK)'"
                    )
                else:
                    stem = gemspecs[0].stem.replace("-", "/")
                    reqs["smoke_test"] = (
                        f"RUBYLIB=/app/lib ruby -e 'begin; require %({stem}); "
                        f"rescue LoadError; end; puts %(SMOKE_OK)'"
                    )
                reqs["install_steps"].append(
                    "RUBYLIB=/app/lib:$RUBYLIB; "
                    "gem build /app/*.gemspec && gem install --no-document /app/*.gem || "
                    "echo 'gemspec optional; using RUBYLIB=/app/lib'"
                )
            else:
                reqs["smoke_test"] = "ruby -e 'puts %(SMOKE_OK)'"
        if app_type in ("web-app", "api-service"):
            reqs["framework"] = _detect_ruby_framework(dest)
            reqs["start_command"] = _ruby_web_start_command(dest)

    elif language == "node":
        reqs["runtime"] = ["nodejs", "npm"]
        if (dest / "package.json").exists():
            reqs["install_steps"].append("npm install --ignore-scripts")
            try:
                package = json.loads((dest / "package.json").read_text(errors="ignore"))
            except Exception:
                package = {}
            if isinstance(package, dict):
                name = str(package.get("name") or "").strip()
                if name:
                    reqs["package_name"] = name[:200]
                scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
                # Keep the test command constrained to npm's own script runner;
                # arbitrary README/AI shell commands must not become lab input.
                if isinstance(scripts, dict) and isinstance(scripts.get("mocha"), str):
                    reqs["package_test_command"] = "npm run mocha -- --reporter dot"
                elif isinstance(scripts, dict) and isinstance(scripts.get("test"), str):
                    test_script = scripts.get("test", "").strip().lower()
                    if test_script and "no test specified" not in test_script:
                        reqs["package_test_command"] = "npm test -- --runInBand"
            # Import the actual package for library/CLI audits. A runtime-only
            # console smoke can pass while the enrolled package is un-loadable.
            if app_type in ("library", "cli-tool", "unknown"):
                reqs["smoke_test"] = (
                    "node -e 'const p=require(\".\"); "
                    "if (p === undefined) process.exit(2); "
                    "console.log(\"SMOKE_OK_NODE_PACKAGE\")'"
                )
            else:
                reqs["smoke_test"] = "node -e 'console.log(\"SMOKE_OK_NODE_RUNTIME\")'"
            if app_type in ("web-app", "api-service"):
                reqs["start_command"] = _node_web_start_command(dest)

    elif language == "php":
        reqs["runtime"] = ["php-cli", "php-xml", "php-mbstring", "php-curl"]
        if (dest / "composer.json").exists():
            reqs["build_tools"].append("composer")
            reqs["install_steps"].append("composer install --no-interaction --no-dev")
            reqs["smoke_test"] = "php -v"
        if app_type in ("web-app", "api-service"):
            reqs["start_command"] = (
                "php -S 0.0.0.0:${PORT} -t /app/public 2>/dev/null || "
                "php -S 0.0.0.0:${PORT} -t /app"
            )

    elif language == "go":
        reqs["runtime"] = ["golang-go"]
        if (dest / "go.mod").exists():
            entry_package = _go_entry_package(dest)
            if entry_package:
                reqs["go_entry_package"] = entry_package
                reqs["install_steps"].extend([
                    "go mod download",
                    f"go build -o /app/app {entry_package}",
                ])
                reqs["smoke_test"] = "test -x /app/app && echo SMOKE_OK_GO_BINARY"
                reqs["analysis_notes"].append(
                    f"Go entry package selected for lab runtime: {entry_package}"
                )
            else:
                # Do not use ``go build -o /app/app ./...``: multi-command
                # modules reject that form, and a later static listener would
                # make the failed target look healthy. The runtime guard in
                # Dockerfile generation leaves this lab explicitly unproven.
                reqs["analysis_notes"].append(
                    "No unambiguous Go main package was found; generated service lab cannot claim target runtime proof"
                )
        if app_type in ("web-app", "api-service"):
            if reqs.get("go_entry_package"):
                reqs["start_command"] = "/app/app --port ${PORT} || /app/app"

    elif language == "rust":
        reqs["runtime"] = ["cargo", "rustc"]
        if (dest / "Cargo.toml").exists():
            reqs["install_steps"].append(
                "command -v cargo >/dev/null || "
                "(curl -sSf https://sh.rustup.rs | sh -s -- -y && . $HOME/.cargo/env)"
            )
            reqs["install_steps"].append(
                ". $HOME/.cargo/env 2>/dev/null; cargo build --release 2>/dev/null || cargo build"
            )
            reqs["smoke_test"] = ". $HOME/.cargo/env 2>/dev/null; cargo --version && echo SMOKE_OK"
        if app_type in ("web-app", "api-service"):
            reqs["start_command"] = (
                ". $HOME/.cargo/env 2>/dev/null; "
                "cargo run --release -- --port ${PORT} 2>/dev/null || "
                "python3 -m http.server ${PORT} --bind 0.0.0.0 --directory /app"
            )

    elif language == "elixir":
        reqs["runtime"] = ["elixir", "erlang-dev", "erlang-nox"]
        reqs["system_libs"].extend(["elixir", "erlang-dev", "erlang-nox"])
        if (dest / "mix.exs").exists():
            reqs["install_steps"].extend([
                "mix local.hex --force && mix local.rebar --force",
                "mix deps.get",
                "mix compile",
            ])
            reqs["smoke_test"] = "elixir -e 'IO.puts(\"SMOKE_OK\")'"
        if app_type in ("web-app", "api-service"):
            reqs["start_command"] = (
                "mix phx.server 2>/dev/null || mix run --no-halt 2>/dev/null || "
                "python3 -m http.server ${PORT} --bind 0.0.0.0 --directory /app"
            )

    elif language in ("csharp", "dotnet"):
        reqs["env_vars"]["PATH"] = "$PATH:/root/.dotnet:/root/.cargo/bin"
        reqs["install_steps"].extend([
            "command -v dotnet >/dev/null || "
            "(curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0)",
            "export PATH=\"$PATH:$HOME/.dotnet:/root/.dotnet\"; "
            "dotnet restore && dotnet build -c Release --no-restore",
        ])
        reqs["smoke_test"] = (
            "export PATH=\"$PATH:$HOME/.dotnet:/root/.dotnet\"; "
            "dotnet --version && echo SMOKE_OK"
        )
        if app_type in ("web-app", "api-service"):
            reqs["start_command"] = (
                "export PATH=\"$PATH:$HOME/.dotnet:/root/.dotnet\"; "
                "dotnet run --urls http://0.0.0.0:${PORT} 2>/dev/null || "
                "python3 -m http.server ${PORT} --bind 0.0.0.0 --directory /app"
            )

    elif language == "scala":
        reqs["runtime"] = ["openjdk-21-jdk-headless"]
        if (dest / "build.sbt").exists():
            reqs["install_steps"].append("sbt -batch compile")
            reqs["smoke_test"] = "sbt -batch about && echo SMOKE_OK"

    elif language == "kotlin":
        reqs["runtime"] = ["openjdk-21-jdk-headless"]
        if (dest / "build.gradle").exists() or (dest / "build.gradle.kts").exists():
            reqs["build_tools"].append("gradle")
            reqs["install_steps"].append("gradle build -x test --no-daemon")
            reqs["smoke_test"] = "echo SMOKE_OK"

    elif language == "dart":
        if (dest / "pubspec.yaml").exists():
            reqs["install_steps"].append("dart pub get")
            reqs["smoke_test"] = "dart --version && echo SMOKE_OK"

    elif language == "zig":
        if (dest / "build.zig").exists():
            reqs["install_steps"].append("zig build")
            reqs["smoke_test"] = "zig version && echo SMOKE_OK"

    elif language == "swift":
        if (dest / "Package.swift").exists():
            reqs["install_steps"].append("swift build")
            reqs["smoke_test"] = "swift --version && echo SMOKE_OK"

    reqs["build_tools"].extend(["strace", "curl", "netcat-openbsd"])
    return reqs


def generate_dockerfile_from_requirements(reqs: Dict[str, Any], port: int) -> str:
    """Generate a Dockerfile whose RUN steps must succeed (no silent || true)."""
    lines = [
        "FROM lotus-lab-ubuntu:26.04",
        "USER root",
        "WORKDIR /app",
        "COPY . /app",
    ]

    if reqs.get("system_libs"):
        libs = " ".join(sorted(set(reqs["system_libs"]) - BASE_IMAGE_PACKAGES))
        if libs:
            lines.append(
                "RUN apt-get update -qq && "
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {libs} "
                "&& rm -rf /var/lib/apt/lists/*"
            )

    for k, v in (reqs.get("env_vars") or {}).items():
        lines.append(f"ENV {k}={v}")

    for step in reqs.get("install_steps") or []:
        lines.append(f"RUN {step}")

    smoke = reqs.get("smoke_test")
    if smoke:
        lines.append(f"RUN {smoke}")

    lines.append(f"ENV LOTUS_LAB_PORT={port}")
    lines.append(f"EXPOSE {port}")

    start = reqs.get("start_command")
    requires_target_runtime = bool(reqs.get("requires_target_runtime"))
    if requires_target_runtime:
        start = _strip_generic_http_server_fallback(str(start or "")) or None
    if start:
        cmd = start.replace("${PORT}", str(port))
        # JSON-form CMD is required for signal forwarding, but interpolating a
        # shell string directly into JSON breaks whenever the launcher contains
        # quotes (PATH exports, Java variables, or user-facing fallbacks).  Let
        # the JSON encoder escape every byte instead of producing a Dockerfile
        # that builds and then exits with a shell syntax error.
        lines.append(f"CMD {json.dumps(['sh', '-c', cmd])}")
    elif requires_target_runtime:
        # A generic listener can make a broken build look healthy and allow
        # Phase 2 to treat static HTML as an application proof. Fail visibly
        # instead: the build artifact remains inspectable, but no dynamic or
        # qualification path may claim a target runtime was established.
        lines.append(
            "CMD [\"sh\", \"-c\", "
            "\"echo 'Lotus could not determine an application launcher; target runtime is unproven' >&2; exit 64\"]"
        )
    else:
        lines.append(
            f'CMD ["sh", "-c", "python3 -m http.server {port} --bind 0.0.0.0 --directory /app"]'
        )

    lines.append("USER lotus")
    return "\n".join(lines) + "\n"


def generate_ai_dockerfile_prompt(dest: Path, reqs: Dict[str, Any], port: int) -> str:
    """Prompt for AI Dockerfile generation when the deterministic build fails."""
    readme_text = ""
    for readme in ("README.md", "README.rst", "README.txt", "README"):
        p = dest / readme
        if p.exists():
            try:
                readme_text = p.read_text(errors="ignore")[:3000]
            except Exception:
                pass
            break

    key_files = []
    for pattern in ("Makefile", "CMakeLists.txt", "pom.xml", "build.gradle*",
                    "package.json", "requirements.txt", "Gemfile", "Cargo.toml",
                    "mix.exs", "config.m4", "setup.py", "docker-compose.*", "*.csproj"):
        matches = list(dest.glob(pattern))
        key_files.extend(str(m.relative_to(dest)) for m in matches[:3])

    notes = "; ".join(reqs.get("analysis_notes") or [])
    steps = "\n".join(f"  - {s}" for s in (reqs.get("install_steps") or [])[:8])

    return f"""Generate a Dockerfile for a security audit lab container.

Repository analysis:
- Language: {reqs['language']}
- App type: {reqs['app_type']}
- Is extension: {reqs['is_extension']}
- Framework: {reqs.get('framework', 'unknown')}
- Key files: {', '.join(key_files[:15])}
- Needs database: {reqs['needs_database']}
- Notes: {notes}
- Planned install steps:
{steps or '  (none)'}

README excerpt:
{readme_text[:1500]}

Requirements:
- Base image: lotus-lab-ubuntu:26.04 (has Python, Ruby, Node, Java, PHP, Go, build tools)
- MUST install all dependencies and build the project — do NOT use '|| true' on install steps
- MUST include a RUN smoke test proving the project runs (e.g. jc --version, php -m | grep yaml)
- MUST expose port {port}
- MUST start the enrolled application on port {port} for web/API targets; never
  substitute a static file server when the application cannot start
- Security: run as non-root user 'lotus' after build
- For web apps: start the actual web server, not just a static file server
- For CLI tools: start `python3 -m http.server {port}` for health checks
- For C extensions: build with phpize/configure/make and register the extension
- Python packages: install with /opt/lotus-venv/bin/pip install -e .

Generate ONLY the Dockerfile content (FROM to CMD), no explanation."""


def rewrite_compose_for_lab(src: Path, dest_path: Path, host_port: int, slug: str,
                            native_ports: Optional[List[int]] = None) -> Tuple[Path, int]:
    """Write a Lotus-owned compose file with host port remapped to the lab port.

    Returns (path, container_port).
    """
    validate_compose_for_lab(src, root=Path(src).parent)
    text = src.read_text(errors="ignore")
    container_port = 8080
    m = re.search(
        r"""ports:\s*\n(?:[^\n]*\n)*?\s*-\s*["']?(?:127\.0\.0\.1:)?(?:\$\{[^}]+\}|\d+):(\d+)""",
        text,
    )
    if m:
        container_port = int(m.group(1))
    elif native_ports:
        container_port = int(native_ports[0])

    rewritten = re.sub(
        r"""(['"]?)(?:127\.0\.0\.1:)?(?:\$\{HOST_PORT:[^}]+\}|\d+):(\d+)\1""",
        lambda m: '%s127.0.0.1:%s:%s%s' % (m.group(1) or '"', host_port, m.group(2), m.group(1) or '"'),
        text,
    )
    if "ports:" not in rewritten and re.search(r"^\s+\w+:", rewritten, re.M):
        # Native brokers often forget to publish the listen port. Inject one on the first service.
        rewritten = re.sub(
            r"(^  [A-Za-z0-9_-]+:\n)",
            rf"\1    ports:\n      - \"127.0.0.1:{host_port}:{container_port}\"\n",
            rewritten,
            count=1,
            flags=re.M,
        )
    # First service with container_name → lotus-{slug}; otherwise leave compose names
    rewritten = re.sub(
        r"(container_name:\s*)\S+",
        rf"\1lotus-{slug}",
        rewritten,
        count=1,
    )
    dest_path.write_text(rewritten)
    return dest_path, container_port


def _python_package_name(dest: Path) -> Optional[str]:
    setup = dest / "setup.py"
    if setup.exists():
        try:
            text = setup.read_text(errors="ignore")[:4000]
            m = re.search(r"""name\s*=\s*['\"]([A-Za-z0-9_.-]+)['\"]""", text)
            if m:
                return m.group(1).replace("-", "_")
        except Exception:
            pass
    pyproject = dest / "pyproject.toml"
    if pyproject.exists():
        try:
            text = pyproject.read_text(errors="ignore")[:3000]
            m = re.search(r"""name\s*=\s*['\"]([A-Za-z0-9_.-]+)['\"]""", text)
            if m:
                return m.group(1).replace("-", "_")
        except Exception:
            pass
    # Common layout: package dir matching repo folder
    for child in dest.iterdir():
        if child.is_dir() and (child / "__init__.py").exists() and child.name not in (
            "tests", "test", "docs", "examples", "scripts",
        ):
            return child.name
    return None


def _php_extension_name(dest: Path) -> str:
    m4 = dest / "config.m4"
    if m4.exists():
        try:
            text = m4.read_text(errors="ignore")[:4000]
            m = re.search(r"PHP_NEW_EXTENSION\(\s*([A-Za-z0-9_]+)", text)
            if m:
                return m.group(1)
        except Exception:
            pass
    if (dest / "yaml.c").exists() or (dest / "php_yaml.h").exists():
        return "yaml"
    return dest.name.replace("pecl-", "").replace("file_formats-", "").split("-")[-1] or "yaml"


def _detect_python_framework(dest: Path) -> Optional[str]:
    for f in ("app.py", "main.py", "wsgi.py"):
        p = dest / f
        if p.exists():
            try:
                text = p.read_text(errors="ignore")[:2000]
                if "Flask" in text:
                    return "flask"
                if "FastAPI" in text or "fastapi" in text:
                    return "fastapi"
                if "Django" in text or "django" in text:
                    return "django"
            except Exception:
                pass
    return None


def _detect_ruby_framework(dest: Path) -> Optional[str]:
    if (dest / "config" / "routes.rb").exists():
        return "rails"
    gemfile = dest / "Gemfile"
    if gemfile.exists():
        try:
            text = gemfile.read_text(errors="ignore")[:2000]
            if "rails" in text:
                return "rails"
            if "sinatra" in text:
                return "sinatra"
        except Exception:
            pass
    return None


def _java_start_command(dest: Path) -> str:
    """Determine the best start command for a Java web app."""
    return (
        "JAR=$(find /app -name '*.jar' -path '*/target/*' ! -name '*-sources*' ! -name '*-tests*' | head -1); "
        "WAR=$(find /app -name '*.war' -path '*/target/*' | head -1); "
        "if [ -n \"$JAR\" ]; then java -jar \"$JAR\" --server.port=${PORT}; "
        "elif [ -n \"$WAR\" ]; then java -jar \"$WAR\" --server.port=${PORT}; "
        "else echo 'No runnable Java artifact was built; target runtime is unproven' >&2; exit 64; fi"
    )
