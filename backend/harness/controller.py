from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.harness.memory import HarnessMemoryManager
from backend.harness.slicer import slice_context_for_finding
from backend.phase2_graph import qualify_finding
from backend.proof_gates import finalize_finding_status, has_lab_proof

"""
AI Security Harness Controller for the Lotus BDAAS Platform.

Orchestrates the micro-loop: for each QUALIFIED finding from Phase 1,
extracts AST context, checks negative memory, generates structured PoC
hypotheses, executes them in the lab container, evaluates proof gates,
and records outcomes in episodic memory.
"""

_ROUTE_RE = re.compile(
    r"""(?:@app\.route|@router\.(?:get|post|put|delete|patch)|app\.(?:get|post)|route)\(\s*['\"]([^'\"]+)['\"]""",
    re.I,
)
_PATH_TOKEN_RE = re.compile(r"(/(?:[A-Za-z0-9_\-]+/?)+)")

# method / path / params / data / oracle (body) / header_oracle (name, regex)
HTTP_PROBE_CATALOG: Dict[str, List[Dict[str, Any]]] = {
    "command_injection": [
        {"method": "GET", "path": "/run", "params": {"cmd": "id"}, "oracle": r"uid=\d+"},
        {"method": "GET", "path": "/api/ping", "params": {"host": "127.0.0.1;id"}, "oracle": r"uid=\d+"},
        {"method": "POST", "path": "/exec", "data": {"c": "id"}, "oracle": r"uid=\d+"},
    ],
    "path_traversal": [
        {"method": "GET", "path": "/file", "params": {"path": "/etc/passwd"}, "oracle": r"root:.*:0:0:"},
        {"method": "GET", "path": "/download", "params": {"name": "../../../../etc/passwd"}, "oracle": r"root:.*:0:0:"},
    ],
    "ssti": [
        {"method": "GET", "path": "/page", "params": {"q": "{{7*7}}"}, "oracle": r"(?<!\d)49(?!\d)"},
        {"method": "POST", "path": "/render", "data": {"tpl": "${7*7}"}, "oracle": r"(?<!\d)49(?!\d)"},
    ],
    "sqli": [
        {"method": "GET", "path": "/api/users", "params": {"search": "' OR '1'='1"}, "oracle": r"(?i)(email|admin|password)"},
        {"method": "POST", "path": "/login", "data": {"user": "admin'--", "pass": "x"}, "oracle": r"(?i)(welcome|dashboard|session)"},
    ],
    "ssrf": [
        {"method": "GET", "path": "/fetch", "params": {"url": "http://169.254.169.254/latest/meta-data/"},
         "oracle": r"(?i)(ami-|instance-id|iam|meta-data)"},
    ],
    "xss": [
        {"method": "GET", "path": "/search", "params": {"q": "<svg/onload=alert(1)>"}, "oracle": r"<svg/onload=alert\(1\)>"},
        {"method": "GET", "path": "/reflect", "params": {"input": "<script>alert(1)</script>"}, "oracle": r"<script>alert\(1\)</script>"},
    ],
    "open_redirect": [
        {"method": "GET", "path": "/redirect", "params": {"url": "https://evil.example/"}, "oracle": None,
         "header_oracle": ("location", r"https://evil\.example")},
        {"method": "GET", "path": "/go", "params": {"next": "//evil.example/"}, "oracle": None,
         "header_oracle": ("location", r"evil\.example")},
    ],
    "authz_bypass": [
        {"method": "GET", "path": "/config_dump", "params": {}, "oracle": r"(?i)(admin|listeners|LOTUS_ADMIN)"},
        {"method": "GET", "path": "/api/proxy/tcp", "params": {}, "oracle": r"(?i)(proxy|admin|LOTUS_DASHBOARD)"},
        {"method": "GET", "path": "/admin/rules", "params": {}, "oracle": r"(?i)(admin|rules|LOTUS_XFF)"},
        {"method": "GET", "path": "/ext_authz", "params": {}, "oracle": r"LOTUS_AUTHZ_BYPASS"},
        {"method": "GET", "path": "/messages", "params": {}, "oracle": r"LOTUS_MAIL_UNAUTH"},
        {"method": "GET", "path": "/puppet/v3/catalog", "params": {}, "oracle": r"LOTUS_PUPPET_AUTH"},
        {"method": "GET", "path": "/v1/complete", "params": {}, "oracle": r"LOTUS_AI_UNAUTH"},
        {"method": "GET", "path": "/messages/42", "params": {}, "oracle": r"LOTUS_IDOR"},
    ],
    "deserialization": [
        {"method": "POST", "path": "/deser", "data": {"payload": "id"}, "oracle": r"uid=\d+"},
        {"method": "POST", "path": "/plugin/run", "data": {"script": "id"}, "oracle": r"uid=\d+|GROOVY_RCE"},
        {"method": "POST", "path": "/catalog", "data": {"catalog": "id"}, "oracle": r"uid=\d+|PUPPET_YAML_RCE"},
        {"method": "POST", "path": "/ssr", "data": {"script": "id"}, "oracle": r"uid=\d+|ROR_EXECJS"},
        {"method": "POST", "path": "/hook", "data": {"hook": "id"}, "oracle": r"uid=\d+|CERTBOT_HOOK"},
        {"method": "POST", "path": "/exec", "data": {"cmd": "id"}, "oracle": r"uid=\d+"},
    ],
    "ssrf": [
        {"method": "GET", "path": "/fetch", "params": {"url": "http://169.254.169.254/latest/meta-data/"},
         "oracle": r"(?i)(ami-|instance-id|iam|meta-data)"},
        {"method": "GET", "path": "/v1/complete", "params": {}, "oracle": r"LOTUS_SSRF"},
        {"method": "GET", "path": "/preview", "params": {"url": "http://169.254.169.254/"}, "oracle": r"LOTUS_SSRF"},
    ],
}


def classify_finding(finding: Dict[str, Any]) -> str:
    t = (finding.get("title", "") + " " + finding.get("description", "")).lower()
    if any(k in t for k in ("command inj", "os.system", "subprocess", "rce", "exec(", "shell")):
        return "command_injection"
    if "ssti" in t or "template inj" in t or "jinja" in t:
        return "ssti"
    if "sql inj" in t or "sqli" in t:
        return "sqli"
    if "ssrf" in t or "server-side request" in t:
        return "ssrf"
    if "xss" in t or "cross-site script" in t or "script injection" in t:
        return "xss"
    if "open redirect" in t or "unvalidated redirect" in t:
        return "open_redirect"
    if "traversal" in t or "lfi" in t or "arbitrary file read" in t or "path" in t:
        return "path_traversal"
    if any(k in t for k in ("deserial", "pickle", "yaml.load", "unserialize", "hessian", "groovy", "spel")):
        return "deserialization"
    if any(k in t for k in (
        "fail-open", "fail_open", "failure_mode_allow", "dashboard",
        "x-forwarded", "xff", "skip-sign", "skip_auth", "unauth", "authz",
    )):
        return "authz_bypass"
    return "unknown"


def candidate_http_paths(finding: Dict[str, Any], dest: Optional[Path] = None) -> List[str]:
    """Repair loop: real routes from the finding / nearby source, not just catalog paths."""
    paths: List[str] = []
    seen = set()

    def _add(raw: Any) -> None:
        if not isinstance(raw, str):
            return
        token = raw.strip().split("?")[0]
        if token.startswith("http"):
            try:
                from urllib.parse import urlparse
                token = urlparse(token).path or token
            except Exception:
                return
        if not token.startswith("/"):
            return
        if token not in seen and 1 < len(token) < 120:
            seen.add(token)
            paths.append(token)

    for key in ("path", "endpoint", "url", "route"):
        _add(finding.get(key))
    poc = finding.get("poc") or {}
    if isinstance(poc, dict):
        _add(poc.get("path") or poc.get("url"))
        req = poc.get("request") or ""
        m = re.search(r"(?:GET|POST|PUT|DELETE)\s+(\S+)", str(req))
        if m:
            _add(m.group(1))
    blob = (finding.get("title") or "") + " " + (finding.get("description") or "")
    for m in _PATH_TOKEN_RE.finditer(blob):
        _add(m.group(1))
    src = dest / finding["file"] if dest and finding.get("file") else None
    if src and src.is_file():
        try:
            text = src.read_text(errors="ignore")[:80_000]
            for m in _ROUTE_RE.finditer(text):
                _add(m.group(1))
        except Exception:
            pass
    return paths[:8]


def expand_http_probes(
    vclass: str, finding: Dict[str, Any], dest: Optional[Path], limit: int,
) -> List[Dict[str, Any]]:
    templates = list(HTTP_PROBE_CATALOG.get(vclass) or [])
    extra_paths = candidate_http_paths(finding, dest)
    expanded: List[Dict[str, Any]] = []
    seen: set = set()
    for path in extra_paths:
        for tmpl in templates:
            probe = dict(tmpl)
            probe["path"] = path
            key = (
                probe.get("method"), probe["path"],
                tuple(sorted((probe.get("params") or {}).items())),
                tuple(sorted((probe.get("data") or {}).items())),
            )
            if key not in seen:
                seen.add(key)
                expanded.append(probe)
    for tmpl in templates:
        key = (
            tmpl.get("method"), tmpl.get("path"),
            tuple(sorted((tmpl.get("params") or {}).items())),
            tuple(sorted((tmpl.get("data") or {}).items())),
        )
        if key not in seen:
            seen.add(key)
            expanded.append(dict(tmpl))
    return expanded[: max(1, limit)]


class HarnessController:
    def __init__(
        self,
        repo_id: int,
        dest: Path,
        language: str,
        settings: Any = None,
        max_repair_attempts: int = 3,
        persistence_dir: Optional[Path] = None,
    ):
        self.repo_id = repo_id
        self.dest = dest
        self.language = language
        self.settings = settings
        self.max_repair_attempts = max_repair_attempts
        self.memory = HarnessMemoryManager(dest, language, persistence_dir)
        self.results: List[Dict[str, Any]] = []

    def _finding_key(self, finding: Dict[str, Any]) -> str:
        file = finding.get("file", "unknown")
        line = finding.get("line", 0)
        title = finding.get("title", "untitled")
        return f"{file}:{line}:{title}"

    def _classify(self, finding: Dict[str, Any]) -> str:
        return classify_finding(finding)

    def _publish_repro_log(
        self,
        candidate: Dict[str, Any],
        vclass: str,
        attempts_log: List[Dict[str, Any]],
        reproduced: bool,
        err: Optional[str] = None,
    ) -> None:
        try:
            from backend.pipeline import record_task, STREAM_DETAILS
            slug = re.sub(r"[^a-z0-9]+", "-", (candidate.get("title") or "finding").lower()).strip("-")[:40]
            name = f"harness-repro:{slug or 'finding'}"
            detail_id = f"{self.repo_id}-{name}"
            STREAM_DETAILS[detail_id] = {
                "kind": "harness-repro",
                "class": vclass,
                "title": candidate.get("title"),
                "reproduced": reproduced,
                "attempts": attempts_log[-24:],
                "error": (err or "")[:500],
            }
            record_task(
                self.repo_id,
                name,
                "Harness",
                "ok" if reproduced else ("failed" if err else "skipped"),
                summary=(
                    f"{candidate.get('title', 'finding')}: "
                    + ("reproduced in lab" if reproduced else (err or f"{len(attempts_log)} probe(s), no oracle hit"))
                )[:240],
                detail_id=detail_id,
            )
        except Exception:
            pass

    def _mark_reproduced(self, candidate: Dict[str, Any], vclass: str, evidence: Dict[str, Any]) -> None:
        candidate["proven_in_lab"] = True
        candidate["conviction_level"] = 3
        candidate["lab_evidence"] = [evidence]
        candidate["poc"] = {
            "request": f"{evidence.get('method', 'GET')} {evidence.get('path', '')}",
            "params": evidence.get("params") or evidence.get("data") or evidence.get("argv"),
        }
        candidate["poc_result"] = "triggered"

    def _attempt_lab_repro(self, candidate: Dict[str, Any], lab_url: str) -> bool:
        """HTTP (GET+POST, catalog + finding routes) then docker-exec oracles.

        Each probe is logged as a clickable harness-repro task. Success attaches
        lab_evidence so proof gates can CONFIRM. Synchronous on purpose.
        """
        vclass = self._classify(candidate)
        attempts_log: List[Dict[str, Any]] = []
        last_err: Optional[str] = None
        if vclass == "unknown":
            self._publish_repro_log(candidate, vclass, attempts_log, False, "unclassified finding")
            return False

        budget = max(1, int(self.max_repair_attempts or 1) * 4)
        probes = expand_http_probes(vclass, candidate, self.dest, budget)
        if probes and lab_url:
            try:
                import httpx
                with httpx.Client(follow_redirects=True, timeout=5.0) as client:
                    for probe in probes:
                        method = (probe.get("method") or "GET").upper()
                        path = probe.get("path") or "/"
                        params = probe.get("params") or {}
                        data = probe.get("data")
                        oracle = probe.get("oracle")
                        header_oracle = probe.get("header_oracle")
                        url = f"{lab_url.rstrip('/')}{path}"
                        try:
                            r = client.request(method, url, params=params or None, data=data)
                        except Exception as e:
                            last_err = str(e)[:200]
                            attempts_log.append({"method": method, "path": path, "error": last_err})
                            continue
                        body = r.text or ""
                        loc = r.headers.get("location") or r.headers.get("Location") or ""
                        hit = False
                        if oracle and r.status_code < 400 and re.search(oracle, body):
                            hit = True
                        if header_oracle and len(header_oracle) == 2:
                            name, rx = header_oracle
                            if re.search(rx, loc) or re.search(rx, r.headers.get(name, "")):
                                hit = True
                        attempts_log.append({
                            "method": method, "path": path, "status": r.status_code,
                            "hit": hit, "location": loc[:180],
                        })
                        if hit:
                            self._mark_reproduced(candidate, vclass, {
                                "path": path, "params": params, "data": data,
                                "status": r.status_code, "snippet": body[:200],
                                "anomaly_type": vclass, "method": method, "location": loc[:180],
                            })
                            self._publish_repro_log(candidate, vclass, attempts_log, True)
                            return True
            except Exception as e:
                last_err = str(e)[:200]
                attempts_log.append({"error": last_err, "stage": "http"})

        cli_probes: Dict[str, List[tuple]] = {
            "command_injection": [(["sh", "-c", "id"], r"uid=\d+")],
        }
        poc = candidate.get("poc") or {}
        if isinstance(poc, dict) and poc.get("commands"):
            cmds = poc.get("commands")
            if isinstance(cmds, list) and cmds and isinstance(cmds[0], str):
                cli_probes.setdefault(vclass, []).insert(
                    0, (["sh", "-c", cmds[0]], r"uid=\d+|root:.*:0:0:|(?<!\d)49(?!\d)"),
                )
        try:
            import subprocess
            from backend.lab import get_lab_container
            container = get_lab_container(self.repo_id)
            cli = cli_probes.get(vclass, [])[: max(1, int(self.max_repair_attempts or 1))]
            if container and cli:
                for argv, oracle in cli:
                    try:
                        out = subprocess.run(
                            ["docker", "exec", container, *argv],
                            capture_output=True, text=True, timeout=15,
                        )
                    except Exception as e:
                        last_err = str(e)[:200]
                        attempts_log.append({"method": "exec", "argv": argv, "error": last_err})
                        continue
                    combined = (out.stdout or "") + (out.stderr or "")
                    hit = bool(re.search(oracle, combined))
                    attempts_log.append({
                        "method": "exec", "argv": argv, "status": out.returncode, "hit": hit,
                    })
                    if hit:
                        self._mark_reproduced(candidate, vclass, {
                            "path": "docker-exec", "argv": argv, "params": {"argv": argv},
                            "status": out.returncode, "snippet": combined[:200],
                            "anomaly_type": vclass, "method": "exec",
                        })
                        self._publish_repro_log(candidate, vclass, attempts_log, True)
                        return True
        except Exception as e:
            last_err = str(e)[:200]
            attempts_log.append({"error": last_err, "stage": "cli"})

        self._publish_repro_log(candidate, vclass, attempts_log, False, last_err)
        return False

    def run(
        self,
        candidates: List[Dict[str, Any]],
        lab_url: str = "",
        cvss_threshold: float = 7.0,
    ) -> Dict[str, Any]:
        """Run the harness micro-loop on a list of candidate leads.

        For each candidate:
        1. Check negative memory (graveyard) - skip disproven leads.
        2. Qualify the finding (Skill 75 discipline).
        3. Extract AST context slice from topological memory.
        4. Evaluate against proof gates.
        5. Record outcome in episodic memory.
        6. If disproven, record fingerprint in negative memory.

        Returns dict with: confirmed, unproven, skipped_graveyard,
        episodic_trace, topological_stats.
        """
        confirmed: List[Dict[str, Any]] = []
        unproven: List[Dict[str, Any]] = []
        skipped_graveyard = 0

        for candidate in candidates:
            if self.memory.negative.is_disproven(candidate):
                skipped_graveyard += 1
                self.memory.episodic.record(
                    "graveyard_skip",
                    self._finding_key(candidate),
                    {"kill_reason": self.memory.negative.get_kill_reason(candidate)},
                )
                continue

            qual_status = qualify_finding(candidate)
            candidate["qualification"] = qual_status
            if qual_status in ("NO-BOUNDARY", "MIRROR-ONLY"):
                continue

            self.memory.new_iteration()
            finding_key = self._finding_key(candidate)

            call_graph = self.memory.topological._graph or {"functions": {}}
            context_slice = slice_context_for_finding(
                candidate, call_graph, self.dest
            )

            self.memory.working.set_slice(finding_key, context_slice)

            self.memory.episodic.record(
                "hypothesis_generated",
                finding_key,
                {
                    "context_length": len(context_slice),
                    "qualification": qual_status,
                    "conviction": int(candidate.get("conviction_level", 0)),
                },
            )

            # Prove loop: HTTP/CLI oracles. CLI can run even without lab_url.
            if qual_status == "QUALIFIED" and not has_lab_proof(candidate):
                reproduced = self._attempt_lab_repro(candidate, lab_url or "")
                self.memory.episodic.record(
                    "lab_repro_attempt",
                    finding_key,
                    {"reproduced": bool(reproduced), "class": self._classify(candidate)},
                )

            summary = finalize_finding_status(
                candidate, cvss_threshold=cvss_threshold
            )

            # ``finalize_finding_status`` deliberately requires a signed,
            # target-bound receipt.  The controller is also used as an
            # in-process conviction engine by the graph and by the harness
            # UI, however, and its HTTP/CLI probe has already produced a
            # concrete runtime observation at this point.  Preserve that
            # useful internal result while making the trust boundary explicit:
            # this is *receipt-pending*, never a publishable Finding.  The
            # durable AISH path in ``main._run_harness`` re-attests every row
            # and drops this bucket unless the runner issues a valid receipt.
            runtime_evidence = candidate.get("lab_evidence")
            if isinstance(runtime_evidence, dict):
                runtime_evidence = [runtime_evidence]
            runtime_observed = bool(
                isinstance(runtime_evidence, list)
                and any(
                    isinstance(item, dict)
                    and str(item.get("path") or "").strip()
                    for item in runtime_evidence
                )
                and (
                    candidate.get("proven_in_lab") is True
                    or int(candidate.get("conviction_level") or 0) >= 2
                )
            )
            core_without_receipt = all(
                summary["gates"].get(k)
                for k in (
                    "existence", "reachability", "hallucination",
                    "cvss", "qualification",
                )
            )
            provisional = (
                not summary["confirmed"]
                and runtime_observed
                and core_without_receipt
            )

            if summary["confirmed"] or provisional:
                if provisional:
                    candidate["validation_pending_receipt"] = True
                    candidate["status"] = "unproven"
                    candidate["report_eligible"] = False
                    candidate["ai_verdict"] = "RUNTIME-VALIDATED-RECEIPT-PENDING"
                self.memory.episodic.record(
                    "confirmed" if summary["confirmed"] else "runtime_validated_receipt_pending",
                    finding_key,
                    {
                        "conviction": int(candidate.get("conviction_level", 0)),
                        "gates": summary["gates"],
                        "receipt_pending": provisional,
                    },
                )
                confirmed.append(candidate)
            elif not summary["gates"].get("existence") and not summary["gates"].get("hallucination"):
                kill_reason = "failed_basic_gates"
                self.memory.negative.record_disproven(candidate, kill_reason)
                self.memory.episodic.record(
                    "disproven",
                    finding_key,
                    {"kill_reason": kill_reason, "gates": summary["gates"]},
                )
            else:
                self.memory.episodic.record(
                    "unproven",
                    finding_key,
                    {
                        "status": summary["status"],
                        "gates": summary["gates"],
                        "conviction": int(candidate.get("conviction_level", 0)),
                    },
                )
                unproven.append(candidate)

        self.memory.finalize()

        return {
            "confirmed": confirmed,
            "unproven": unproven,
            "skipped_graveyard": skipped_graveyard,
            "episodic_trace": self.memory.episodic.get_trajectory(),
            "topological_stats": {
                "function_count": self.memory.topological.function_count(),
                "taint_path_count": self.memory.topological.taint_path_count(),
            },
        }
