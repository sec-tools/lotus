"""One source-bound primary correction after an owned, cleaned compiler failure.

No resource operation happens here. Callers must obtain evidence from the
builder's private single-use capsule, never from artifact JSON or exception attrs.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
import re

from backend.proof_receipts import content_tree_digest

# Logs can deny repair, but never authorize it without the producer capsule and
# positive API termination/cleanup state. Unknown failures remain unrepaired.
_DENY = re.compile(r"out.of.memory|oomkilled|\boom\b|\bkilled\b|memory.limit|cannot allocate memory|"
    r"no space left|disk quota|evict|node.?pressure|deadline|timed?\s*out|timeout|"
    r"network.(?:error|unreachable|isolation|policy)|failed to fetch|could not resolve|econn\w*|enotfound|etimedout|eai_again|dns failure|certificate|tls handshake|"
    r"unauthorized|forbidden|permission denied|connection refused|rate.limit|"
    r"unexpected status.*(?:401|403|429|50[0-9])", re.I)
_REFERENCE = r"([A-Za-z0-9_@./+~-]{1,160})"
_RULES = (
    ("missing-node-module", re.compile(r"Cannot find module ['\"]" + _REFERENCE + r"['\"]", re.I)),
    ("missing-header", re.compile(r"fatal error:\s*" + _REFERENCE + r": No such file", re.I)),
    ("missing-command", re.compile(_REFERENCE + r": (?:command )?not found(?:\s|$)", re.I)),
    ("missing-python-module", re.compile(r"No module named ['\"]" + _REFERENCE + r"['\"]", re.I)),
    ("missing-node-package", re.compile(r"Cannot find package ['\"]" + _REFERENCE + r"['\"]", re.I)),
)


_KANIKO_COMMAND = re.compile(r"(?m)^INFO\[[0-9]{4,}\][ \t]+(RUN |Unpacking rootfs as cmd RUN |Args: |Running: )")


def _plain_log(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _deny_output(text):
    """Remove only the exact trusted installer portion of command records.

    Kaniko logs one command as JSON and as decoded argv, with optional SGR
    color. Parse those record forms through one fixed argv contract; preserve
    remaining args and every subsequent output byte for denial classification.
    Unknown/truncated/modified scripts and ordinary RUN records stay intact.
    The original retained log is never modified.
    """
    from backend.native_toolchains import install_script
    text = _plain_log(text)
    argv = ["/usr/bin/env", "-i", "PATH=/opt/lotus-venv/bin:/usr/local/bin:/usr/bin:/bin",
            "/opt/lotus-venv/bin/python3", "-I", "-c", install_script()]
    decoder = json.JSONDecoder()
    parts = []; cursor = 0
    for record in _KANIKO_COMMAND.finditer(text):
        if record.start() < cursor: continue
        start = record.end(); end = None
        if record[1] in ("RUN ", "Unpacking rootfs as cmd RUN "):
            # JSON argv: decode each fixed argument, stopping before the
            # model-independent version/checksum payload at the end.
            if text.startswith('[', start):
                position = start + 1
                try:
                    for number, expected in enumerate(argv):
                        while position < len(text) and text[position] in ' \t': position += 1
                        if number:
                            if text[position] != ',': raise ValueError('argv separator')
                            position += 1
                            while position < len(text) and text[position] in ' \t': position += 1
                        value, position = decoder.raw_decode(text, position)
                        if value != expected: raise ValueError('different command')
                    end = position
                except (ValueError, IndexError): pass
            else:
                prefix = ' '.join(argv)
                if text.startswith(prefix, start): end = start + len(prefix)
        else:
            prefix = '[' + ' '.join(argv[1:] if record[1] == 'Args: ' else argv)
            if text.startswith(prefix, start): end = start + len(prefix)
        if end is not None:
            parts.append(text[cursor:record.start()]); cursor = end
    parts.append(text[cursor:])
    return ''.join(parts)


def compiler_diagnostics(evidence):
    """Project only fixed diagnostic kinds/codes, never arbitrary log lines."""
    if not isinstance(evidence, dict) or evidence.get("cleanup_verified") is not True:
        return []
    failure = evidence.get("failure") or {}
    if failure.get("stage") != "image-build" or failure.get("code") != "executor-failed" or failure.get("cleanup_errors"):
        return []
    log = evidence.get("log") or {}; termination = log.get("termination") or {}
    if (log.get("status") != "captured" or termination.get("phase") != "Failed"
            or termination.get("reason") != "Error" or termination.get("pod_reason") not in (None, "")
            or type(termination.get("exitCode")) is not int or termination["exitCode"] not in {1, 2, 126, 127}
            or termination.get("signal") not in (None, 0)):
        return []
    text = log.get("text")
    if not isinstance(text, str) or len(text.encode()) > 3 * 128 * 1024 or _DENY.search(_deny_output(text)):
        return []
    text = _plain_log(text)
    found = []
    # Standalone checker output only: Kaniko may also echo the entire RUN
    # script containing every marker, which is not an observed check failure.
    for code in re.findall(r"(?m)^LOTUS_ENTRYPOINT_(MISSING|ARCHITECTURE|FORMAT): [^\r\n]*$", text):
        found.append({"kind": "entrypoint-" + code.lower()})
    for kind, pattern in _RULES:
        for match in list(pattern.finditer(text))[:4]:
            found.append({"kind": kind, "reference": match[1]})
    from backend.adapter_build_inputs import literal_pattern
    for match in list(re.finditer(r"(?m)^([A-Za-z0-9_./-]{1,160}\.go):[1-9][0-9]*:[1-9][0-9]*: pattern ([^\r\n ]{1,164}): no matching files found$", text))[:4]:
        if literal_pattern(match[1]) and literal_pattern(match[2]):
            found.append({"kind": "missing-go-embed", "reference": match[1], "pattern": match[2]})
    for code in re.findall(r"\berror (TS[0-9]{3,5})\b", text, re.I)[:4]:
        found.append({"kind": "typescript-error", "code": code.upper()})
    if "ERR_PNPM_NO_OFFLINE_TARBALL" in text or "ERR_PNPM_NO_OFFLINE_META" in text:
        found.append({"kind": "unpopulated-offline-store"})
    if "ERR_PNPM_OUTDATED_LOCKFILE" in text:
        found.append({"kind": "package-lock-mismatch"})
    if re.search(r"undefined reference to|undefined: [A-Za-z_]", text):
        found.append({"kind": "unresolved-compiled-symbol"})
    return found[:8]


def prompt_diagnostics(rows, context, candidate):
    # References from negative-control/error output are not sent to providers
    # unless already present in this source/candidate input. Fixed kinds remain
    # useful when a missing module name itself is not yet known from source.
    known = json.dumps({"context": context, "candidate": candidate}, ensure_ascii=True)
    result = []
    for row in rows[:8]:
        value = {key: row[key] for key in ("kind", "code") if key in row}
        ref = row.get("reference", "")
        if ref and ref in known and not re.search(r"secret|token|password|credential|api.?key|[A-Za-z0-9_-]{40}", ref, re.I):
            value["reference"] = ref
            if row.get("kind") == "missing-go-embed":
                value["pattern"] = row["pattern"]
        result.append(value)
    return result


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


async def correct_candidate(source, repo_id, expected, deployment, artifact, evidence, send, *, invoke=None):
    """One primary response, unchanged source/component/proof contract, no fallback."""
    from backend import lab_adapters as adapters
    from backend.ai_gateway import AIStatus, extract_json
    from backend.ai_runtime import request_model
    if artifact.get("build_repair") is not None:
        return None
    if evidence.get("source_tree_hash") != expected or evidence.get("recipe_sha256") != artifact.get("recipe_sha256"):
        return None
    rows = compiler_diagnostics(evidence)
    if not rows:
        text = (evidence.get("log") or {}).get("text")
        denied = isinstance(text, str) and bool(_DENY.search(_deny_output(text)))
        artifact["build_repair"] = {"status": "not-attempted", "primary_calls": 0, "max_primary_calls": 1,
            "source_tree_hash": expected, "failed_recipe_sha256": artifact["recipe_sha256"],
            "code": "resource-or-transport-diagnostic" if denied else "no-eligible-compiler-diagnostic",
            "reason": ("Compiler correction was not attempted because the retained build output contains a resource, timeout, permission or transport failure"
                       if denied else "The owned build did not contain an eligible compiler diagnostic with the required termination and cleanup state")}
        return None
    repair = {"status": "checking-source", "primary_calls": 0, "max_primary_calls": 1,
              "source_tree_hash": expected, "failed_recipe_sha256": artifact["recipe_sha256"]}
    artifact["build_repair"] = repair
    refusal = "source-validation"
    original_candidate = deepcopy(artifact.get("candidate"))
    original_hash = artifact.get("candidate_sha256")
    try:
        context = await asyncio.to_thread(adapters.source_context, source, expected)
        previous = deepcopy(artifact["candidate"])
        await asyncio.to_thread(adapters.extend_source_context, source, expected, context, previous.get("source_evidence") or [])
        context["prepared_toolchain"] = deepcopy(artifact.get("toolchain"))
        previous = adapters.validate_candidate(previous, context)
        from backend.adapter_build_inputs import supports_embed_diagnostic
        rows = [row for row in rows if supports_embed_diagnostic(context, row)]
        if not rows:
            raise adapters.AdapterUnavailable("Compiler embed diagnostic does not match the captured source directive")
        repair.update(status="requesting-correction", previous_candidate_sha256=fingerprint(previous))
        adapters.persist_adapter(source, artifact)
        await send(repo_id, "Build failed; making one source-bound compiler correction",
                   detail_id=f"{repo_id}-local-lab-adapter", detail=artifact)
        if await asyncio.to_thread(content_tree_digest, source) != expected:
            raise adapters.AdapterUnavailable("Captured source changed before compiler correction")
        repair["primary_calls"] = 1
        refusal = "primary-unavailable"
        response = await (invoke or request_model)(adapters.repair_prompt_for(context, deployment, previous,
            {"kind": "compiler-failure", "diagnostics": prompt_diagnostics(rows, context, previous)}), role="primary")
        if await asyncio.to_thread(content_tree_digest, source) != expected:
            refusal = "source-validation"
            raise adapters.AdapterUnavailable("Captured source changed during compiler correction")
        if (response is None or response.status != AIStatus.OK or (response.meta or {}).get("mock")
                or (response.meta or {}).get("simulated")):
            raise adapters.AdapterUnavailable("Compiler correction requires a verified primary response")
        refusal = "response-validation"
        repair["response_sha256"] = hashlib.sha256(response.text.encode()).hexdigest()
        adapters.require_complete_response(response)
        if len(response.text.encode()) > adapters.MAX_RESPONSE_BYTES:
            raise adapters.AdapterUnavailable("Compiler correction exceeds its schema budget")
        candidate = adapters.validate_candidate(extract_json(response.text), context)
        refusal = "component-contract-changed"
        for key in ("profile", "component_scope", "omitted_behaviors", "unavailable_capabilities", "port", "smoke_test"):
            if candidate[key] != previous[key]:
                raise adapters.AdapterUnavailable("Compiler correction changed the original component or proof contract")
        execution = ("build_steps", "entrypoint", "environment", "system_packages")
        refusal = "unchanged-execution-plan"
        if all(candidate[key] == previous[key] for key in execution):
            raise adapters.AdapterUnavailable("Compiler correction did not change the failed execution plan")
        refusal = "record-persistence"
        repair.update(status="accepted", candidate_sha256=fingerprint(candidate))
        artifact.setdefault("candidate_history", []).append({"repair_kind": "compiler-failure",
            "candidate_sha256": repair["candidate_sha256"], "candidate": deepcopy(candidate)})
        artifact.setdefault("attempts", []).append({"repair_kind": "compiler-failure", "status": "schema-valid",
            "response_sha256": repair["response_sha256"], "candidate_sha256": repair["candidate_sha256"]})
        artifact["candidate"] = deepcopy(candidate)
        artifact["candidate_sha256"] = repair["candidate_sha256"]
        adapters.persist_adapter(source, artifact)
        await send(repo_id, "Compiler correction validated; rebuilding once",
                   detail_id=f"{repo_id}-local-lab-adapter", detail=artifact)
        return candidate
    except asyncio.CancelledError:
        artifact["candidate"] = original_candidate
        if original_hash is None: artifact.pop("candidate_sha256", None)
        else: artifact["candidate_sha256"] = original_hash
        repair["status"] = "cancelled"
        raise
    except Exception as error:
        artifact["candidate"] = original_candidate
        if original_hash is None: artifact.pop("candidate_sha256", None)
        else: artifact["candidate_sha256"] = original_hash
        # Keep the original build error authoritative; no arbitrary provider or
        # source text becomes a public failure or another repair instruction.
        reasons = {
            "source-validation": "Captured source could not be revalidated for compiler correction",
            "primary-unavailable": "The primary model was unavailable for the single compiler correction",
            "response-validation": "The compiler correction failed its required response or source schema",
            "component-contract-changed": "The compiler correction changed the original component or proof contract",
            "unchanged-execution-plan": "The compiler correction did not change the failed execution plan",
            "record-persistence": "Compiler correction evidence could not be persisted",
        }
        repair.update(status="refused", code=refusal, error_type=type(error).__name__[:80], reason=reasons[refusal])
        return None
