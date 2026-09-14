"""Bounded, source-supported GET plans for deployment identity observations.

The catalog is deliberately smaller than route discovery. A conventional name
is not evidence of a harmless handler. Only captured literal Python responses
and explicitly mapped static metadata files qualify here. Middleware, reverse
proxies and an unknown remote implementation remain outside this static check.
The hashes bind saved selections; they are not signatures or vulnerability proof.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from pathlib import PurePosixPath

from backend import source_index


POLICY = "source-reviewed-identity-plan-v1"
MAX_CATALOG = 32
MAX_REQUESTS = 9
MAX_PURPOSE = 300
SAFE_PATHS = frozenset({"/", "/health", "/healthz", "/status", "/version",
                        "/robots.txt", "/favicon.ico", "/openapi.json", "/swagger.json"})
_RESOURCES = frozenset({"/robots.txt", "/favicon.ico", "/openapi.json", "/swagger.json"})
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_FILES, _MAX_FILE_BYTES, _MAX_LINES = 32, 65536, 1000
_HEALTH_LIMITATIONS = [
    "The controller observed this response in the selected audit's local lab; a successful GET does not prove an unknown remote handler is side-effect-free.",
    "Review the captured source and request purpose before explicitly selecting this endpoint. This is not vulnerability or remote revision proof.",
]
_LIMITATIONS = [
    "Selection checks captured response code or static resource mappings, not middleware, proxies or unknown remote behavior.",
    "Only nine conventional metadata paths are eligible; observed local-health entries require explicit selection and do not establish remote safety.",
    "A response match identifies a possible deployment; it proves neither the remote revision nor a vulnerability.",
]


def _hash(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest()


def _scope(static):
    return {key: static.get(key) for key in ("repo_id", "scan_job_id", "target_revision", "target_tree_hash")}


def _canonical_file(value):
    return (isinstance(value, str) and 0 < len(value) <= 500 and not value.startswith("/")
            and "\\" not in value and not any(ord(c) < 32 for c in value)
            and all(part not in {"", ".", ".."} for part in value.split("/")))


def _purpose(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > MAX_PURPOSE
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("Request purpose must be plain text between 1 and 300 characters")
    return value.strip()


def _seal(plan):
    plan["catalog_hash"] = _hash({"policy": POLICY, "scope": plan["scope"], "catalog": plan["catalog"]})
    plan["plan_hash"] = _hash({key: value for key, value in plan.items() if key != "plan_hash"})
    return plan


def _candidate(path, refs, kind):
    return {"id": _hash({"method": "GET", "path": path, "source_refs": refs, "kind": kind}),
            "method": "GET", "path": path,
            "purpose": ("Compare the captured static metadata resource." if kind == "static-resource"
                        else "Compare the captured literal service response."),
            "source_refs": refs,
            "screening": {"kind": kind, "source_verified": True,
                          "limitations": [_LIMITATIONS[0]]}}


def _source_hints(output):
    """Inspect only current-audit route inventory, never finding/PoC payloads."""
    surface = output.get("attack_surface")
    if not isinstance(surface, dict):
        return [], []
    hints, resources = {}, []
    for key in ("controllers", "routes", "entry_points", "static_resources"):
        values = surface.get(key)
        if not isinstance(values, list):
            continue
        for index, value in enumerate(values[:256]):
            pointer = f"/attack_surface/{key}/{index}"
            file = value if isinstance(value, str) else value.get("file") if isinstance(value, dict) else None
            if _canonical_file(file) and len(hints) < _MAX_FILES:
                hints.setdefault(file, pointer)
            if key == "static_resources" and isinstance(value, dict) and len(resources) < MAX_CATALOG:
                resources.append((value, pointer))
                declaration = value.get("declaration_file")
                if _canonical_file(declaration) and len(hints) < _MAX_FILES:
                    hints.setdefault(declaration, pointer)
    return list(hints.items()), resources


def _observed_row(path, refs, candidate_hash, observation_hash):
    row = _candidate(path, refs, "observed-local-health")
    row["purpose"] = "Compare the application response observed in this audit's local lab; review its purpose before selecting."
    row["screening"] = {"kind": "observed-local-health", "source_verified": True,
                        "local_observation_verified": True, "candidate_sha256": candidate_hash,
                        "observation_sha256": observation_hash, "limitations": list(_HEALTH_LIMITATIONS)}
    row["id"] = _hash({key: row[key] for key in ("method", "path", "source_refs", "screening")})
    return row


def _observed_local_health(scope, output, meta, index):
    """Offer one signed local observation, not a guessed route or network action."""
    from backend.proof_receipts import _canonical, verify_blob
    try:
        adapter = output.get("local_lab_adapter")
        if (not isinstance(adapter, dict) or adapter.get("status") != "component-ready"
                or adapter.get("runtime_verified") is not True):
            return None
        candidate = adapter["candidate"]
        encoded_candidate = _canonical(candidate)
        if len(encoded_candidate) > 65536 or candidate.get("profile") != "native-service":
            return None
        candidate_hash = hashlib.sha256(encoded_candidate).hexdigest()
        smoke = candidate["smoke_test"]
        if (adapter.get("candidate_sha256") != candidate_hash or not isinstance(smoke, dict)
                or set(smoke) != {"path", "status_code", "body_contains"}
                or smoke["path"] not in SAFE_PATHS or type(smoke["status_code"]) is not int
                or not 200 <= smoke["status_code"] < 300 or not isinstance(smoke["body_contains"], str)
                or not 8 <= len(smoke["body_contains"]) <= 256):
            return None
        runtime = adapter["runtime"]
        result = runtime["smoke"]
        if (result.get("ran") is not True or result.get("ok") is not True
                or type(result.get("exit_code")) is not int or result["exit_code"] != 0):
            return None
        observation = result["observation"]
        unsigned = {k: v for k, v in observation.items() if k != "catalog_signature"}
        payload = _canonical(unsigned)
        if len(payload) > 65536 or not verify_blob(payload, observation.get("catalog_signature"),
                                                purpose="lotus-observed-local-health-v1"):
            return None
        bound = observation["runtime"]
        if (observation.get("observer") != "lotus-controller-http-v1"
                or observation.get("schema_version") != 1 or observation.get("ok") is not True
                or observation.get("candidate_sha256") != candidate_hash
                or type(observation.get("scan_job_id")) is not int
                or observation["scan_job_id"] != scope["scan_job_id"]
                or any(bound.get(k) != scope[k] for k in ("repo_id", "target_revision", "target_tree_hash"))
                or any(not isinstance(bound.get(k), str) or not bound[k] for k in ("pod_uid", "container_id", "lab_run_id", "image_digest"))
                or any(runtime.get(k) != bound[k] for k in ("pod_uid", "image_digest", "target_tree_hash"))
                or observation.get("request") != {"method": "GET", "path": smoke["path"], "port": candidate["port"]}
                or observation.get("status_code") != smoke["status_code"]
                or observation.get("source_marker_matched") is not True
                or observation.get("source_marker_sha256") != hashlib.sha256(smoke["body_contains"].encode()).hexdigest()
                or observation.get("evidence_role") != "component-observation"
                or observation.get("full_deployment_verified") is not False):
            return None
        cited, signed = candidate["source_evidence"], observation["source_evidence"]
        if (not isinstance(cited, list) or not 1 <= len(cited) <= 64 or len(set(cited)) != len(cited)
                or not isinstance(signed, list) or len(signed) != len(cited)):
            return None
        refs, found_marker, total_bytes = [], False, 0
        for number, (name, declared) in enumerate(zip(cited, signed)):
            if (not _canonical_file(name) or not isinstance(declared, dict)
                    or set(declared) != {"file", "sha256"} or declared["file"] != name):
                return None
            actual, entry = source_index.resolve_source_entry(meta, index, name)
            size = entry.get("bytes")
            if type(size) is not int or not 0 <= size <= 1024 * 1024:
                return None
            total_bytes += size
            if total_bytes > 8 * 1024 * 1024 or entry["sha256"] != "sha256:" + declared["sha256"]:
                return None
            window = source_index.indexed_source_window(meta, actual, entry, line_count=_MAX_LINES,
                                                        expected_sha256=entry["sha256"])
            marker_line = next((i + 1 for i, line in enumerate(window["lines"]) if smoke["body_contains"] in line), None)
            found_marker |= marker_line is not None
            refs.append({"artifact": "local_lab_adapter", "pointer": f"/local_lab_adapter/candidate/source_evidence/{number}",
                         "file": name, "line": marker_line or 1, "sha256": entry["sha256"]})
        if not found_marker:
            return None
        return _observed_row(smoke["path"], refs, candidate_hash, hashlib.sha256(payload).hexdigest())
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def _literal_python_routes(text):
    """Accept only explicit GET, zero-argument handlers returning one literal.

    A route with extra decorators, dependencies, calls or statements is not
    approved, including a mutating handler named /health. Duplicate declarations
    invalidate the path. No repository code is imported or executed.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return {}, {}
    def bindings(name):
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == name:
                count += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
                count += 1
            elif isinstance(node, (ast.ImportFrom, ast.Import)):
                count += sum((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)
        return count

    factories = {alias.asname or alias.name: alias.name
                 for node in tree.body if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in {"fastapi", "flask"}
                 for alias in node.names if alias.name == ("FastAPI" if node.module == "fastapi" else "Flask")
                 and bindings(alias.asname or alias.name) == 1}
    apps = set()
    route_decorators = {id(decorator) for node in tree.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        for decorator in node.decorator_list}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                and node.value.func.id in factories):
            name, call = node.targets[0].id, node.value
            constructor_safe = not call.keywords and (
                factories[call.func.id] == "FastAPI" and not call.args
                or factories[call.func.id] == "Flask" and len(call.args) == 1
                and (isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
                     or isinstance(call.args[0], ast.Name) and call.args[0].id == "__name__"))
            # Visible middleware/dependency registration can run on every GET.
            # Extra app calls and app-attribute mutation are outside this subset.
            configured = any(
                isinstance(other, ast.Call) and isinstance(other.func, ast.Attribute)
                and isinstance(other.func.value, ast.Name) and other.func.value.id == name
                and (other.func.attr not in {"get", "route", "post", "put", "patch", "delete", "head", "options"}
                     or other.func.attr in {"get", "route"} and id(other) not in route_decorators)
                or isinstance(other, ast.Attribute) and isinstance(other.ctx, (ast.Store, ast.Del))
                and isinstance(other.value, ast.Name) and other.value.id in {name, call.func.id}
                for other in ast.walk(tree))
            if bindings(name) == 1 and constructor_safe and not configured:
                apps.add(name)
    routes, counts = {}, {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute)
                    or not isinstance(decorator.func.value, ast.Name) or decorator.func.value.id not in apps
                    or decorator.func.attr not in {"get", "route"}):
                continue
            path_node = decorator.args[0] if decorator.args else next(
                (keyword.value for keyword in decorator.keywords if keyword.arg in {"path", "rule"}), None)
            if not isinstance(path_node, ast.Constant) or not isinstance(path_node.value, str):
                # A dynamic registration can shadow any selected conventional path.
                for path in SAFE_PATHS:
                    counts[path] = counts.get(path, 0) + 2
                continue
            path = path_node.value
            if path not in SAFE_PATHS:
                continue
            counts[path] = counts.get(path, 0) + 1
            keywords = {keyword.arg: keyword.value for keyword in decorator.keywords}
            if decorator.func.attr == "get":
                explicit_get = len(decorator.args) == 1 and not keywords
            else:
                try:
                    explicit_get = len(decorator.args) == 1 and set(keywords) == {"methods"} and ast.literal_eval(keywords["methods"]) == ["GET"]
                except (ValueError, TypeError, RecursionError):
                    explicit_get = False
            args = node.args
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            if (not explicit_get or len(node.decorator_list) != 1 or args.posonlyargs or args.args or args.kwonlyargs
                    or args.vararg or args.kwarg or len(body) != 1 or not isinstance(body[0], ast.Return)):
                continue
            try:
                # literal_eval cannot invoke handlers, functions, properties or imports.
                value = ast.literal_eval(body[0].value)
                json.dumps(value, allow_nan=False)
            except (ValueError, TypeError, RecursionError, OverflowError):
                continue
            routes[path] = decorator.lineno
    return {path: line for path, line in routes.items() if counts[path] == 1}, counts


def _static_mapping(text, path, file):
    """Recognize one exact Nginx static alias with no location-level actions.

    This deployment-format check is language independent. Absolute deployment
    paths and guessed document roots are intentionally not mapped to repo files.
    """
    blocks = list(re.finditer(r"\blocation\s*=\s*" + re.escape(path) + r"\s*\{([^{}]*)\}", text))
    if len(blocks) != 1:
        return None
    match = blocks[0]
    if not re.fullmatch(r"\s*alias\s+" + re.escape(file) + r"\s*;\s*", match.group(1)):
        return None
    # Commented declarations are not evidence. More complex quoting is excluded.
    prefix = text[:match.start()].rsplit("\n", 1)[-1]
    if "#" in prefix or "\"" in prefix or "'" in prefix:
        return None
    return text.count("\n", 0, match.start()) + 1


def make_plan(static: dict, output: dict) -> dict:
    """Build a small catalog using an existing authenticated source index.

    This read never starts indexing, scans the working checkout or executes code.
    Missing/unready/integrity-conflicted evidence yields no candidate for that file.
    """
    plan = {"schema_version": 1, "policy": POLICY, "scope": _scope(static), "catalog": [],
            "requests": [], "limitations": list(_LIMITATIONS), "reason": ""}
    scope = plan["scope"]
    if (any(type(scope[k]) is not int or scope[k] < 1 for k in ("repo_id", "scan_job_id"))
            or not isinstance(scope["target_revision"], str)
            or not _HASH.fullmatch(str(scope["target_tree_hash"] or ""))):
        plan["reason"] = "The selected audit has no complete immutable source identity."
        return _seal(plan)
    snapshot = output.get("target_snapshot")
    if snapshot is None:
        checkpoint = output.get("phase1_checkpoint")
        snapshot = checkpoint.get("target_snapshot") if isinstance(checkpoint, dict) else None
    try:
        if not isinstance(snapshot, dict):
            raise ValueError("missing snapshot")
        meta = source_index.snapshot_metadata(snapshot.get("path", ""), expected_tree=scope["target_tree_hash"],
                                              expected_manifest=snapshot.get("manifest_hash", ""))
        # Deliberately use the authenticated cached-index reader, not _source_index:
        # that public workflow can schedule a complete snapshot rebuild on a GET.
        index = source_index._load_index(meta, source_index._identity(meta))
        if index is None:
            plan["reason"] = "The captured source index is not ready; prepare the audit source index before reviewing requests."
            return _seal(plan)
    except (OSError, ValueError, TypeError, KeyError):
        plan["reason"] = "The selected audit source snapshot is unavailable or failed its identity check."
        return _seal(plan)
    hints, resources = _source_hints(output)
    texts, candidates, duplicates, declarations = {}, {}, set(), {}
    for file, pointer in hints:
        try:
            actual, entry = source_index.resolve_source_entry(meta, index, file)
            if type(entry.get("bytes")) is not int or not 0 <= entry["bytes"] <= _MAX_FILE_BYTES:
                continue
            window = source_index.indexed_source_window(meta, actual, entry, line_count=_MAX_LINES)
            if window["total_lines"] > _MAX_LINES:
                continue
            text = "\n".join(window["lines"])
            texts[file] = (text, entry["sha256"])
            if PurePosixPath(file).suffix != ".py":
                continue
            routes, observed = _literal_python_routes(text)
            for path, count in observed.items():
                declarations[path] = declarations.get(path, 0) + count
                if declarations[path] > 1:
                    duplicates.add(path)
            for path, line in routes.items():
                refs = [{"artifact": "attack_surface", "pointer": pointer, "file": file, "line": line,
                         "sha256": entry["sha256"]}]
                if path in candidates:
                    duplicates.add(path)
                candidates[path] = _candidate(path, refs, "literal-python-get")
        except (OSError, ValueError, TypeError, KeyError):
            continue
    for resource, pointer in resources:
        path, file, declaration = resource.get("path"), resource.get("file"), resource.get("declaration_file")
        if (resource.get("method") != "GET" or not isinstance(path, str) or path not in _RESOURCES
                or not _canonical_file(file) or not _canonical_file(declaration)
                or PurePosixPath(declaration).suffix != ".conf"
                or PurePosixPath(file).name != path[1:] or file not in texts or declaration not in texts):
            continue
        line = _static_mapping(texts[declaration][0], path, file)
        if line is None:
            continue
        refs = [{"artifact": "attack_surface", "pointer": pointer, "file": name, "line": number,
                 "sha256": texts[name][1]} for name, number in ((declaration, line), (file, 1))]
        if path in candidates:
            duplicates.add(path)
        candidates[path] = _candidate(path, refs, "static-resource")
    observed = _observed_local_health(scope, output, meta, index)
    if observed and observed["path"] not in candidates and observed["path"] not in declarations:
        candidates[observed["path"]] = observed
    plan["catalog"] = [candidate for path, candidate in sorted(candidates.items()) if path not in duplicates][:MAX_CATALOG]
    plan["requests"] = [{"method": "GET", "path": row["path"], "purpose": row["purpose"]}
                        for row in plan["catalog"][:MAX_REQUESTS] if row["screening"]["kind"] != "observed-local-health"]
    plan["reason"] = ("Only source-supported requests are offered; review them before making network requests." if plan["catalog"]
                      else "No supported literal GET handler or explicitly mapped static metadata resource was verified in the bounded captured-source review.")
    return _seal(plan)


def validate_plan(plan: dict, static: dict) -> dict:
    """Check stored-plan consistency. API callers also compare a fresh catalog hash."""
    keys = {"schema_version", "policy", "scope", "catalog", "requests", "limitations", "reason", "catalog_hash", "plan_hash"}
    if (not isinstance(plan, dict) or set(plan) != keys or type(plan.get("schema_version")) is not int
            or plan["schema_version"] != 1 or plan["policy"] != POLICY or plan["scope"] != _scope(static)):
        raise ValueError("Request plan does not match the selected audit or supported policy")
    catalog = plan["catalog"]
    if (not isinstance(catalog, list) or len(catalog) > MAX_CATALOG or not isinstance(plan["reason"], str)
            or len(plan["reason"]) > 1000 or plan["limitations"] != _LIMITATIONS):
        raise ValueError("Request catalog is malformed")
    paths = set()
    for row in catalog:
        observed = (isinstance(row, dict) and isinstance(row.get("screening"), dict)
                    and row["screening"].get("kind") == "observed-local-health")
        if (not isinstance(row, dict) or set(row) != {"id", "method", "path", "purpose", "source_refs", "screening"}
                or row["method"] != "GET" or not isinstance(row["path"], str)
                or row["path"] not in SAFE_PATHS or row["path"] in paths
                or not isinstance(row["source_refs"], list) or not 1 <= len(row["source_refs"]) <= (64 if observed else 2)):
            raise ValueError("Request catalog contains an unsupported request")
        _purpose(row["purpose"])
        screening = row["screening"]
        if observed:
            if (set(screening) != {"kind", "source_verified", "local_observation_verified", "candidate_sha256", "observation_sha256", "limitations"}
                    or screening.get("source_verified") is not True or screening.get("local_observation_verified") is not True
                    or screening.get("limitations") != _HEALTH_LIMITATIONS
                    or any(not isinstance(screening.get(k), str) or not re.fullmatch(r"[0-9a-f]{64}", screening[k])
                           for k in ("candidate_sha256", "observation_sha256"))):
                raise ValueError("Observed local health screening is malformed")
        elif (not isinstance(screening, dict) or not isinstance(screening.get("kind"), str)
                or screening.get("kind") not in {"literal-python-get", "static-resource"}
                or screening.get("source_verified") is not True
                or screening != {"kind": screening["kind"], "source_verified": True, "limitations": [_LIMITATIONS[0]]}):
            raise ValueError("Request source screening is missing")
        for number, ref in enumerate(row["source_refs"]):
            if (not isinstance(ref, dict) or set(ref) != {"artifact", "pointer", "file", "line", "sha256"}
                    or ref["artifact"] != ("local_lab_adapter" if observed else "attack_surface")
                    or not isinstance(ref["pointer"], str)
                    or (ref["pointer"] != f"/local_lab_adapter/candidate/source_evidence/{number}" if observed else
                        not re.fullmatch(r"/attack_surface/(controllers|routes|entry_points|static_resources)/[0-9]{1,3}", ref["pointer"]))
                    or not _canonical_file(ref["file"]) or type(ref["line"]) is not int or not 1 <= ref["line"] <= _MAX_LINES
                    or not isinstance(ref["sha256"], str) or not _HASH.fullmatch(ref["sha256"])):
                raise ValueError("Request source provenance is malformed")
        expected = (_observed_row(row["path"], row["source_refs"], screening["candidate_sha256"], screening["observation_sha256"])
                    if observed else _candidate(row["path"], row["source_refs"], screening["kind"]))
        if row["id"] != expected["id"]:
            raise ValueError("Request candidate identity is inconsistent")
        paths.add(row["path"])
    result = copy.deepcopy(plan)
    result["requests"] = _selection(catalog, plan["requests"])
    if result["requests"] != plan["requests"]:
        raise ValueError("Stored requests are not canonical")
    _seal(result)
    if result["catalog_hash"] != plan["catalog_hash"] or result["plan_hash"] != plan["plan_hash"]:
        raise ValueError("Request plan hash is inconsistent")
    return result


def _selection(catalog, submitted):
    if not isinstance(submitted, list) or len(submitted) > MAX_REQUESTS:
        raise ValueError("Select at most nine source-supported requests")
    by_path, result, seen = {row["path"]: row for row in catalog}, [], set()
    for row in submitted:
        if (not isinstance(row, dict) or not {"method", "path", "purpose"} <= set(row)
                or set(row) - {"method", "path", "purpose", "candidate_id"} or row["method"] != "GET"
                or not isinstance(row["path"], str) or row["path"] not in by_path or row["path"] in seen):
            raise ValueError("Requests must select distinct exact GET paths from the source-supported catalog")
        if "candidate_id" in row and row["candidate_id"] != by_path[row["path"]]["id"]:
            raise ValueError("Request candidate identity does not match its path")
        result.append({"method": "GET", "path": row["path"], "purpose": _purpose(row["purpose"])})
        seen.add(row["path"])
    return result


def select_requests(plan: dict, submitted: list[dict]) -> dict:
    if not isinstance(plan, dict):
        raise ValueError("Request plan must be an object")
    current = validate_plan(plan, plan.get("scope", {}))
    current["requests"] = _selection(current["catalog"], submitted)
    return _seal(current)


def get_request_paths(plan: dict, static: dict) -> list[str]:
    return [row["path"] for row in validate_plan(plan, static)["requests"]]
