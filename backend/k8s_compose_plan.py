"""Finite, source-only Compose admission for a restricted Kubernetes service.

This is not a general Compose implementation. Every operational field must be
translated or rejected before build work; no host environment, daemon or shell
is consulted. Runtime command semantics follow the Compose services reference:
https://docs.docker.com/reference/compose-file/services/#command
https://docs.docker.com/reference/compose-file/services/#entrypoint
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import shlex

import yaml


class ComposeAdmissionError(ValueError):
    """The target's declared deployment needs a capability we cannot preserve."""


def _fail(reason):
    raise ComposeAdmissionError("Kubernetes Compose admission: " + reason)


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or len(key) > 256 or key in mapping:
            _fail("mapping keys must be unique strings; ambiguous YAML was not applied")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _literal(value, field):
    if not isinstance(value, str) or "\x00" in value or len(value) > 32768:
        _fail(field + " must be a bounded literal string")
    # $$ is Compose's literal dollar escape. Unresolved interpolation must not
    # read the controller's process environment or silently become empty.
    escaped = value.replace("$$", "\x00")
    if "$" in escaped:
        _fail(field + " has unresolved interpolation; provide literal values (use $$ for a literal dollar)")
    return escaped.replace("\x00", "$")


def _argv(value, field):
    if value is None:
        return None
    if isinstance(value, str):
        literal = _literal(value, field)
        try:
            return shlex.split(literal)
        except ValueError as exc:
            raise ComposeAdmissionError("Kubernetes Compose admission: " + field + " has invalid quoting") from exc
    if not isinstance(value, list) or len(value) > 256:
        _fail(field + " must be an argument list, string, or null")
    return [_literal(item, field) for item in value]


def _port(value, field):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)) or not 1 <= int(value) <= 65535:
        _fail(field + " must be one numeric TCP port from 1 to 65535")
    return int(value)


def _ports(service):
    targets, published = set(), []
    for field in ("ports", "expose"):
        values = service.get(field)
        if values is None:
            values = []
        if not isinstance(values, list) or len(values) > 32:
            _fail(field + " must be a bounded list")
        for value in values:
            if isinstance(value, dict):
                if field != "ports" or set(value) - {"target", "published", "host_ip", "protocol"}:
                    _fail("structured ports contain unsupported fields")
                if value.get("protocol", "tcp") != "tcp":
                    _fail("only TCP service ports are supported")
                host = value.get("host_ip", "")
                target, host_port = _port(value.get("target"), "ports.target"), value.get("published")
                if host_port is not None:
                    host_port = _port(host_port, "ports.published")
            else:
                text = _literal(str(value), field)
                if "/" in text:
                    text, protocol = text.rsplit("/", 1)
                    if protocol != "tcp":
                        _fail("only TCP service ports are supported")
                parts = text.split(":")
                if field == "expose" and len(parts) != 1 or len(parts) > 3:
                    _fail("port ranges, IPv6 host binding, and multiple mappings require an explicit Kubernetes topology")
                host = parts[0] if len(parts) == 3 else ""
                host_port = _port(parts[-2], "published port") if len(parts) >= 2 else None
                target = _port(parts[-1], "target port")
            if host not in ("", "127.0.0.1", "localhost"):
                _fail("non-loopback host publication is not allowed")
            targets.add(target)
            if host_port is not None:
                published.append({"host_ip": host or "127.0.0.1", "published": host_port, "target": target})
    if len(targets) > 1:
        _fail("multiple target ports require an explicit Kubernetes topology; none were silently omitted")
    return next(iter(targets), None), published


def _environment(value):
    if value is None:
        return {}
    if isinstance(value, list):
        pairs = []
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                _fail("environment entries must include explicit values; host inheritance is unsupported")
            pairs.append(item.split("=", 1))
    elif isinstance(value, dict):
        pairs = list(value.items())
    else:
        _fail("environment must be a mapping or KEY=value list")
    result = {}
    for key, item in pairs:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in result:
            _fail("environment names must be unique portable variable names")
        if item is None or isinstance(item, bool) or not isinstance(item, (str, int, float)):
            _fail("environment values must be explicit strings or numbers; quote booleans")
        result[key] = _literal(str(item), "environment." + key)
    if len(result) > 256 or len(json.dumps(result).encode()) > 65536:
        _fail("environment exceeds the bounded service configuration budget")
    return result


def read_compose_document(source: Path, compose: Path) -> tuple[dict, str]:
    """Parse bounded captured YAML without environment expansion or execution.

    Shared by runtime admission and the diagnostic planner so the latter never
    invents a different Compose interpretation. This alone is not admission.
    """
    source, compose = Path(source).resolve(), Path(compose).resolve()
    if not compose.is_relative_to(source) or not compose.is_file():
        _fail("Compose file must be inside the captured source tree")
    if compose.stat().st_size > 1024 * 1024:
        _fail("Compose file exceeds the 1 MiB admission budget")
    with compose.open("rb") as handle:
        payload = handle.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        _fail("Compose file exceeds the 1 MiB admission budget")
    try:
        raw = payload.decode("utf-8")
    except UnicodeError:
        _fail("Compose file must be UTF-8 text")
    try:
        depth = 0
        for index, token in enumerate(yaml.scan(raw)):
            if index > 10000 or isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                _fail("YAML aliases/anchors or oversized structures need an explicit flattened Compose contract")
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                                  yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
                if depth > 32:
                    _fail("Compose nesting exceeds the diagnostic and admission budget")
            elif isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken,
                                    yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
        data = yaml.load(raw, Loader=_UniqueLoader)
    except yaml.YAMLError as exc:
        # Do not echo source lines (which can contain credentials) in task logs.
        raise ComposeAdmissionError("Kubernetes Compose admission: invalid YAML; check the captured Compose syntax") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict) or not data["services"]:
        _fail("a non-empty services mapping is required")
    pending = [data]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif (type(value) not in (str, int, float, bool, type(None))
              or type(value) is float and not math.isfinite(value)):
            _fail("Compose scalars must be finite JSON-compatible values; quote dates and binary-looking text")
    return data, raw


def plan_compose(source: Path, compose: Path, request: dict) -> dict:
    """Read one captured Compose file and return a fully admitted source plan."""
    source, compose = Path(source).resolve(), Path(compose).resolve()
    companions = ("compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml")
    if any((compose.parent / name).exists() for name in companions):
        _fail("companion Compose override files require one explicitly flattened contract; overrides were not ignored")
    data, raw = read_compose_document(source, compose)
    services = data["services"]
    # Diagnose known daemon requirements before the broader field/topology
    # refusal, so the user gets the actual missing capability immediately.
    for service in services.values():
        if not isinstance(service, dict):
            _fail("each service must be a mapping")
        mounts = json.dumps(service.get("volumes", []))
        environment = service.get("environment") or {}
        has_daemon_env = "DOCKER_HOST" in environment if isinstance(environment, dict) else any(str(item).startswith("DOCKER_HOST=") for item in environment) if isinstance(environment, list) else False
        if any(socket in mounts for socket in ("docker.sock", "containerd.sock", "podman.sock")) or service.get("use_api_socket") or has_daemon_env:
            _fail("target requires a host container-daemon API/socket. Restricted Kubernetes labs do not expose Docker, containerd, or Podman sockets. Provide a daemon-independent target contract; no socket or elevated privileges were granted")
    if set(data) - {"services", "name", "version"}:
        _fail("top-level networks, volumes, extensions, or external resources require an explicit Kubernetes topology")
    if len(services) != 1:
        _fail("multiple services require an explicit Kubernetes topology; dependencies were not omitted")
    name, service = next(iter(services.items()))
    allowed = {"build", "image", "environment", "ports", "expose", "command", "entrypoint", "working_dir", "user"}
    unsupported = sorted(set(service) - allowed)
    if unsupported:
        _fail("service " + name + " needs unsupported fields: " + ", ".join(unsupported) + "; no declared topology or host capability was ignored")
    if "image" in service:
        _literal(service["image"], "image")
    build = service.get("build")
    if build is None:
        _fail("the single service must build captured source; an image-only service is not source-bound")
    if isinstance(build, str):
        build = {"context": build}
    if not isinstance(build, dict) or set(build) - {"context", "dockerfile"}:
        _fail("build supports only a root context and repository Dockerfile; args, stages, secrets, and external contexts require an explicit build contract")
    context = (compose.parent / _literal(build.get("context", "."), "build.context")).resolve()
    if context != source:
        _fail("build.context must resolve to the captured repository root")
    dockerfile = (context / _literal(build.get("dockerfile", "Dockerfile"), "build.dockerfile")).resolve()
    if not dockerfile.is_relative_to(source) or not dockerfile.is_file():
        _fail("build.dockerfile must be a file inside the captured source root")
    target_port, published = _ports(service)
    current_port = request.get("port")
    if target_port and current_port and request.get("port_source") != "default" and int(current_port) != target_port:
        _fail("the explicit requested port conflicts with the Compose target port; choose one consistent source contract")
    port = target_port or _port(current_port or 3000, "service port")
    environment = _environment(service.get("environment"))
    workdir = service.get("working_dir")
    if workdir is not None:
        workdir = _literal(workdir, "working_dir")
        if not re.fullmatch(r"/[A-Za-z0-9_./-]*", workdir):
            _fail("working_dir must be a literal absolute POSIX path without whitespace")
    user = service.get("user")
    if user is not None:
        user = _literal(str(user), "user")
        if not re.fullmatch(r"[1-9][0-9]*(?::[1-9][0-9]*)?", user):
            _fail("service user must be a literal non-root numeric UID[:GID]")
    return {"schema_version": 1, "file": compose.relative_to(source).as_posix(), "service": name,
            "compose_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "dockerfile": dockerfile.relative_to(source).as_posix(), "port": port, "port_declared": target_port is not None,
            "published_ports": published, "environment": environment,
            "command": _argv(service.get("command"), "command"),
            "entrypoint": _argv(service.get("entrypoint"), "entrypoint"),
            "working_dir": workdir, "user": user}


def apply_image_config(recipe: str, plan: dict) -> str:
    """Bake OCI startup overrides so null and empty arrays keep Compose meaning.

    Kubernetes treats empty command arrays as inheritance, so they cannot
    faithfully clear an image ENTRYPOINT/CMD. A recipe overlay can.
    """
    additions = ["", "# Captured single-service Compose startup configuration"]
    if plan["entrypoint"] is not None:
        additions.append("ENTRYPOINT " + json.dumps(plan["entrypoint"]))
    if plan["command"] is not None:
        additions.append("CMD " + json.dumps(plan["command"]))
    elif plan["entrypoint"] is not None:
        additions.append("CMD []")
    if plan["working_dir"] is not None:
        additions.append("WORKDIR " + plan["working_dir"])
    if plan["user"] is not None:
        additions.append("USER " + plan["user"])
    return recipe.rstrip() + "\n" + "\n".join(additions) + "\n"
