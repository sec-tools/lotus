"""Tool Registry & Capabilities Manager.

Tracks all Phase 1 reconnaissance tools, analyzers, and scanners.
Provides persistence of enabled/disabled states so users can customize
which tools run during audits from the Capabilities page.
"""

from __future__ import annotations
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Any, Optional

try:  # POSIX deployments (including macOS/Linux) support advisory file locks.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback remains thread-safe.
    fcntl = None

STATE_FILE = Path(os.environ.get("LOTUS_DATA_DIR", "./data")) / "tool_state.json"
_STATE_LOCK = threading.RLock()


@contextmanager
def _state_file_lock(*, exclusive: bool):
    """Coordinate capability updates across multiple API worker processes."""
    if fcntl is None:
        yield
        return
    lock_path = STATE_FILE.with_name(f"{STATE_FILE.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _read_tool_state_unlocked() -> Dict[str, bool]:
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: bool(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def _write_tool_state_unlocked(state: Dict[str, bool]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Replace atomically so a concurrent scan/UI request never observes a
    # truncated JSON document or loses a just-applied capability toggle.
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{STATE_FILE.name}.", suffix=".tmp", dir=str(STATE_FILE.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, STATE_FILE)
    finally:
        try:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        except OSError:
            pass

DEFAULT_TOOLS = [
    {
        "id": "dependency-source-capture",
        "name": "External dependency source capture",
        "category": "dependency",
        "description": "Downloads and indexes supported exact dependency archives for later review. Requires Dependency Attack Surface and this optional task to be enabled; captured source is not completed dependency analysis.",
        "languages": ["all"],
        "default_enabled": False,
    },
    {
        "id": "native-package-audits",
        "name": "Nested native package audits",
        "category": "dependency",
        "description": "Runs ecosystem package auditors for additional first-party roots in a monorepo.",
        "languages": ["all"],
        "default_enabled": False,
    },
    {
        "id": "cross-file-taint",
        "name": "Cross-File Taint Analyzer",
        "category": "intelligence",
        "description": "Builds AST-level call graphs and traces source-to-sink data flow across module boundaries.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "high-yield-discovery",
        "name": "High-Yield Discovery Battery",
        "category": "intelligence",
        "description": "Multi-pass deterministic heuristic battery hunting sink reachability, sibling divergence, and weak tokens.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "taint-proximity",
        "name": "Taint-Proximity Scanner",
        "category": "taint-analysis",
        "description": "Detects high-risk sinks operating near unvalidated input variables within local scopes.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "grep-patterns",
        "name": "Core Language Patterns",
        "category": "static",
        "description": "Fast regex scanner matching language-specific sinks (eval, system, unsafe deserialization).",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "methodology-patterns",
        "name": "Methodology Heuristics (T4/T6/T7/T9)",
        "category": "static",
        "description": "Structural analysis targeting error residue, loose comparisons, async race conditions, and pre-auth routes.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "secret-scan",
        "name": "Secret & Credential Scanner",
        "category": "static",
        "description": "Entropy and pattern scanner detecting embedded private keys, tokens, and hardcoded secrets.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "lockfile-audit",
        "name": "Lockfile & Package Auditor",
        "category": "dependency",
        "description": "Extracts dependencies from lockfiles (npm, pip, cargo, gem, composer) for CVE correlation.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "dependency-map",
        "name": "Dependency Topology Mapper",
        "category": "intelligence",
        "description": "Maps third-party packages to application entrypoints and identifies exposed dependencies.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "attack-surface-map",
        "name": "Attack Surface Mapper",
        "category": "intelligence",
        "description": "Discovers exposed HTTP endpoints, CLI flags, RPC interfaces, and public handlers.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "config-audit",
        "name": "Configuration & Manifest Auditor",
        "category": "static",
        "description": "Scans Dockerfiles, CI/CD pipelines, Kubernetes manifests, and framework settings.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "osv-cve-check",
        "name": "OSV Vulnerability Correlator",
        "category": "dependency",
        "description": "Correlates manifest dependencies against the Open Source Vulnerability (OSV) database.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "commit-security-analysis",
        "name": "Git Security History Miner",
        "category": "intelligence",
        "description": "Mines git commit history for security patches and identifies unpatched sibling variants.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "integer-boundary",
        "name": "Integer Boundary & Overflow Scanner",
        "category": "static",
        "description": "Detects integer wraparounds, unsigned conversions, and buffer size calculations.",
        "languages": ["c/cpp", "go", "rust"],
        "default_enabled": True,
    },
    {
        "id": "unsafe-c-api",
        "name": "Unsafe C/C++ API Auditor",
        "category": "static",
        "description": "Flags legacy unsafe functions (strcpy, sprintf, gets) and memory allocation bugs.",
        "languages": ["c/cpp", "php"],
        "default_enabled": True,
    },
    {
        "id": "config-shell-injection",
        "name": "Config-DSL → Generated-Shell Injection Detector",
        "category": "intelligence",
        "description": "Detects tools that turn a config/DSL (YAML/JSON/TOML) into a generated or executed shell script, where an un-escaped data field (filename, option, image, arg) reaches command position. Emits PoC-ready leads for the native config-DSL proving harness.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "test-coverage-gap",
        "name": "Test-Coverage vs Attack-Surface Gap Analyzer",
        "category": "intelligence",
        "description": "Language-agnostic. Maps the repository's own test suite against functions that carry attack surface (read untrusted input and/or reach dangerous sinks) and emits the untested ones as prioritized Phase-2 leads. Persists .lotus/test_coverage_gap.json with coverage metrics. Zero build/toolchain requirements.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "parser-boundary",
        "name": "Parser & Lexer Boundary Auditor",
        "category": "intelligence",
        "description": "Analyzes recursive descent parsers, tokenizers, and AST handlers for stack exhaustion and bounds flaws.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "complexity-hotspot",
        "name": "Cyclomatic Complexity × Taint Hotspot",
        "category": "intelligence",
        "description": "Prioritizes audit focus on highly complex functions intersecting with untrusted inputs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "entry-point-dataflow",
        "name": "Entrypoint Data-Flow Tracer",
        "category": "intelligence",
        "description": "Validates whether public API routes and CLI entrypoints enforce input validation before sinks.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "check-referent-mismatch",
        "name": "Check-Referent Mismatch Detector",
        "category": "intelligence",
        "description": "Finds logic bugs where validation is performed on one variable but operation executes on another.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "single-pass-strip",
        "name": "Single-Pass Sanitization Flaw Detector",
        "category": "static",
        "description": "Flags non-recursive string stripping (e.g. replace('../', '')) vulnerable to nested bypasses.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "error-path-residue",
        "name": "Error-Path State Residue Auditor",
        "category": "static",
        "description": "Detects catch/rescue blocks that fail to rollback privileges or cleanup temporary resources.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "build-flag-audit",
        "name": "Compiler & Build Flag Auditor",
        "category": "static",
        "description": "Verifies ASLR, DEP/NX, Stack Canaries, and RELRO hardening flags in build configurations.",
        "languages": ["c/cpp", "rust", "go"],
        "default_enabled": True,
    },
    {
        "id": "crypto-timing-audit",
        "name": "Cryptographic Timing Leak Scanner",
        "category": "static",
        "description": "Detects non-constant-time comparisons (== vs hmac.compare_digest) in auth and signature verification.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "container-security-audit",
        "name": "Container & Capability Auditor",
        "category": "static",
        "description": "Flags privileged container execution, dangerous Linux capabilities, and root user configs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "c-fuzz-engine",
        "name": "C/C++ Sanitizer Fuzz Engine",
        "category": "dynamic",
        "description": "Builds a standard LLVMFuzzerTestOneInput harness against target C/C++ sources and runs a time-boxed campaign under ASan/UBSan. Coverage-guided via clang+libFuzzer when available, else a dependency-free mutation driver with gcc (runs in minimal lab images). Reports crashes with a captured reproducer; only flags a bug on a real sanitizer abort. Ideal for parsers/decoders consuming untrusted bytes (archive/backup/codec code).",
        "languages": ["c", "cpp"],
        "default_enabled": True,
    },
    {
        "id": "deserialization-chain",
        "name": "Deserialization Gadget Hunter",
        "category": "intelligence",
        "description": "Tracks untrusted payloads flowing into Marshal, Psych/YAML, Pickle, and ObjectInputStream sinks.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "path-containment",
        "name": "Path-Containment / Traversal Auditor",
        "category": "intelligence",
        "description": "Flags externally/config/archive-derived names joined onto a base path and used in filesystem write/extract/symlink sinks without containment (realpath+commonpath), plus the partial-sanitization variant (absolute-path guard present but '..' not rejected). Targets dotfile/backup/sync managers, archive extractors, and upload handlers. Feeds Phase-2 CWE-22/CWE-59 lab PoCs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "auth-structural-bypass",
        "name": "Structural Auth Bypass Scanner",
        "category": "intelligence",
        "description": "Identifies route decorator gaps, middleware exemption flags, and missing authentication guards.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "dynamic-dispatch",
        "name": "Dynamic Dispatch & Metaprogramming Auditor",
        "category": "intelligence",
        "description": "Detects user-controlled reflection, public_send, const_get, and dynamic function dispatch.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "sql-concat-audit",
        "name": "SQL & Query Concatenation Auditor",
        "category": "intelligence",
        "description": "Detects string interpolation into raw database queries across ORMs.",
        "languages": ["java", "python", "ruby/rails", "node", "php", "go"],
        "default_enabled": True,
    },
    {
        "id": "by-design-gate",
        "name": "By-Design Feature Filter Gate",
        "category": "gating",
        "description": "Suppresses false positives on documented product capabilities and intentional features.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "doc-driven-hypothesis",
        "name": "Documentation Invariant Hunter",
        "category": "intelligence",
        "description": "Mines README/docs for security guarantees and generates targeted verification hypotheses.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "boundary-crossing-audit",
        "name": "Boundary Crossing & Serialization Auditor",
        "category": "intelligence",
        "description": "Tracks data boundaries crossing between language runtimes, IPC channels, and FFI bridges.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "high-severity-surface",
        "name": "High-Severity Surface Mapper",
        "category": "intelligence",
        "description": "Fail-open native auth, plugin dlopen, protocol/admin control plane, document-library Marshal/send, SQL LOAD DATA. Feeds Phase-2 protocol PoCs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "trust-boundary-map",
        "name": "Trust-Boundary & Entrypoint Mapper",
        "category": "intelligence",
        "description": "Extracts concrete HTTP routes, auth wrapping, listen/bind defaults, shipped auth-off config, sibling missing guards, queue TCBs. Writes .lotus/trust_boundary.json for Phase 2.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "handler-sink-trace",
        "name": "Handler→Sink Tracer",
        "category": "intelligence",
        "description": "Resolves unauth mutating routes and nested-protocol/queue TCBs to handler bodies and tags RCE/write/SSRF/deser/Join sinks. Writes .lotus/handler_sinks.json so Phase 2 labs the highest-impact edges first.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "component-lab-map",
        "name": "Component × Lab Mapper",
        "category": "intelligence",
        "description": "Splits monorepos into deployable binaries (go.mod/Cargo.toml/Dockerfile/demuxers), attaches unauth routes and sinks, and emits a concrete lab recipe per TCB. Writes .lotus/component_map.json so Phase 2 labs CubeMaster/execd/CLM instead of the repo-level language.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "control-plane-surface",
        "name": "HTTP/Sandbox/Queue Control-Plane Mapper",
        "category": "intelligence",
        "description": "Empty-token fail-open, default-allow HTTP, Go Join absolute escape, sh -c user commands, Redis queue admin, FFmpeg nested protocols. Feeds Phase-2 lab PoCs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "gateway-control-plane",
        "name": "Reverse-Proxy / API-Gateway / WAF Control-Plane Mapper",
        "category": "intelligence",
        "description": "Envoy ext_authz fail-open, admin bind, Lua os.execute; ShenYu Groovy/SpEL/Hessian; frp empty token/dashboard; SafeLine management-plane XFF. Writes .lotus/gateway_plane_trace.json for Phase-2 lab PoCs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "agent-app-control-plane",
        "name": "Ruby-Agent / Unauth-Mail / SSR / AI-Proxy / ACME-Hook / Django-Authz Mapper",
        "category": "intelligence",
        "description": "Puppet YAML/PSON/Execution/auth.conf; Mailcatcher unauth bind; react_on_rails ExecJS/Open3; Headroom SSRF/identity; Certbot root hooks; Zulip object-authz skip. Writes .lotus/agent_app_plane_trace.json for Phase-2 lab PoCs.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "test-oracle-miner",
        "name": "Integration-Test Oracle Miner",
        "category": "intelligence",
        "description": "Reads integration tests for fail-open auth assertions (anonymous admin, empty password) and turns them into Phase-2 PoC recipes.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "bundle-audit",
        "name": "Bundler CVE Audit (Ruby)",
        "category": "static",
        "description": "Checks Ruby Gemfile.lock against RubySec advisory database.",
        "languages": ["ruby/rails"],
        "default_enabled": True,
    },
    {
        "id": "brakeman",
        "name": "Brakeman Rails Scanner",
        "category": "static",
        "description": "Static analysis security scanner specifically designed for Ruby on Rails applications.",
        "languages": ["ruby/rails"],
        "default_enabled": True,
    },
    {
        "id": "semgrep",
        "name": "Semgrep AST Scanner",
        "category": "static",
        "description": "AST-based semantic pattern matching across multiple programming languages.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "joern-cpg",
        "name": "Joern Code Property Graph",
        "category": "cpg",
        "description": "Inter-procedural data-flow slicing, AST graph queries, and taint tracking in a containerized pod.",
        "languages": ["c/cpp", "java", "python", "node", "go", "php", "ruby/rails"],
        "default_enabled": True,
    },
    {
        "id": "gosec",
        "name": "gosec (Go SAST)",
        "category": "static",
        "description": "Containerized Go security analyzer: command injection, SQLi, path traversal, weak crypto, hardcoded creds.",
        "languages": ["go"],
        "default_enabled": True,
    },
    {
        "id": "govulncheck",
        "name": "govulncheck (Go reachable vulns)",
        "category": "dependency",
        "description": "Call-graph-aware detection of known Go vulnerabilities whose vulnerable symbol is actually reachable (not just imported).",
        "languages": ["go"],
        "default_enabled": True,
    },
    {
        "id": "staticcheck",
        "name": "staticcheck (Go correctness)",
        "category": "static",
        "description": "Containerized Go correctness/logic analysis: nil dereferences, dead guards, impossible comparisons.",
        "languages": ["go"],
        "default_enabled": True,
    },
    {
        "id": "semgrep-registry",
        "name": "Semgrep Registry (curated rulesets)",
        "category": "static",
        "description": "Containerized semgrep with OWASP + security-audit + injection rulesets spanning Java/Python/Go/Node.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "osv-scanner",
        "name": "OSV-Scanner (multi-ecosystem)",
        "category": "dependency",
        "description": "Containerized Google OSV scanner correlating lockfiles across ecosystems (Go, npm, pip, Maven, etc.) with the OSV database.",
        "languages": ["all"],
        "default_enabled": True,
    },
    {
        "id": "dynamic-path-exploration",
        "name": "Dynamic Path Exploration (coverage-guided fuzzing + sink tracing)",
        "category": "dynamic",
        "description": "Discovers untrusted-data parse entry points and auto-synthesizes coverage-guided fuzz harnesses driven in isolated pods: Go (go test -fuzz) and Python (Atheris). Emits crashes (proven-in-lab), coverage, and reproducer artifacts. For Node/Java/Ruby it emits a danger-sink tracing map (RCE/deser sinks) for Phase 2 targeting. Fuzzing requires Docker + deep audits (L3+); sink-mapping is always on.",
        "languages": ["go", "python", "node", "java", "ruby/rails"],
        "default_enabled": False,
    },
]

# Keep expensive or environment-sensitive analysis explicitly opt-in. This is
# a default policy, not a claim that the tool itself is broken. Saved operator
# choices still win, and reports continue to expose excluded task coverage.
DEFAULT_OFF_REASONS = {
    "dependency-source-capture": "Disabled by default: downloading dependency archives can use up to 30 minutes before planning. Enable with Dependency Attack Surface when external source capture is needed; repository source indexing and manifest inventory remain available.",
    "component-lab-map": "Disabled by default: component-to-lab mapping can traverse many manifests and source relationships. Enable after reviewing repository scope; basic source inventory and required lab validation remain separate.",
    "osv-cve-check": "Disabled by default: advisory correlation makes up to 50 sequential network requests and can exceed one minute. Enable when advisory access is reliable; dependency inventory remains available, without CVE coverage from this task.",
    "bundle-audit": "Disabled by default: Ruby advisory analysis depends on package tooling and its advisory database, and can exceed one minute. Enable after validating those prerequisites.",
    "brakeman": "Disabled by default: Rails semantic analysis has a three-minute execution budget and can be slow on large applications. Enable after confirming Rails applicability and a suitable task budget.",
    "commit-security-analysis": "Disabled by default: mining history performs serial git log and diff operations whose combined deadlines can exceed one minute. Enable when historical change analysis is needed.",
    "high-yield-discovery": "Disabled by default: this multi-strategy, multi-language discovery battery performs repeated source passes and can exceed one minute. Enable for deeper discovery after checking repository scope and available resources.",
    "test-coverage-gap": "Disabled by default: extracting function and test relationships across up to 6,000 files can exceed one minute. Enable for the optional untested-surface analysis; audit task coverage tracking remains active.",
    "complexity-hotspot": "Disabled by default: whole-repository function ranking repeatedly examines source and has no one-minute execution bound. Enable after validating source size and task responsiveness.",
    "entry-point-dataflow": "Disabled by default: entry-point tracing repeats attack-surface enrichment and source reads and can exceed one minute. Enable for deeper dataflow review after selecting the desired enrichment tools.",
    "handler-sink-trace": "Disabled by default: handler-to-sink tracing has taken too long on the recent audit. Enable for a controlled retry after validating repository scope and monitoring task progress.",
    "trust-boundary-map": "Disabled by default: this analyzer stalled on the recent audit and its completion time is not yet reliable across codebases. Enable only for a controlled retry while monitoring task progress.",
    "osv-scanner": "Disabled by default: the isolated scanner encountered source-volume delivery and cleanup failures in this lab. Enable after validating source delivery; dependency mapping remains available and OSV correlation can be enabled separately.",
    "cross-file-taint": "Disabled by default: whole-program callgraphs can exceed time or file budgets on large or mixed-language repositories. Enable after checking source scope and callgraph limits.",
    "lockfile-audit": "Disabled by default: native package audits depend on repository-specific package managers, lockfiles and advisory services. Dependency mapping remains available and OSV correlation can be enabled separately.",
    "native-package-audits": "Disabled by default: recursively auditing package roots can be slow or fail on missing toolchains and incompatible lockfiles. Enable after verifying the repository's package prerequisites.",
    "semgrep": "Disabled by default: semantic rule analysis has encountered timeouts and incomplete scanner output in this lab. Enable with a suitable memory and time budget; fast source scanners remain enabled.",
    "semgrep-registry": "Disabled by default: the extra Semgrep ruleset adds another resource-intensive pass and depends on registry availability. Enable after the base scanner completes reliably.",
    "joern-cpg": "Disabled by default: code-property graph generation requires substantial memory and time. Enable on a suitably sized lab after validating language support.",
    "gosec": "Disabled by default: Go package loading and toolchain setup can substantially delay analysis or exceed the lab's resource budget. Enable after checking Go prerequisites and resource limits.",
    "govulncheck": "Disabled by default: reachable-vulnerability analysis loads the Go dependency graph and can exceed memory limits. Enable after checking the toolchain, dependency access and memory budget.",
    "staticcheck": "Disabled by default: Go whole-package correctness analysis can be expensive and depends on compatible toolchains. Enable after validating the repository build and memory limits.",
    "dynamic-path-exploration": "Disabled by default: generated fuzz harnesses need compatible builds, additional memory and execution time. Enable for repositories with a validated runtime and fuzzing budget.",
}
for _tool in DEFAULT_TOOLS:
    if _tool["id"] in DEFAULT_OFF_REASONS:
        _tool.update(default_enabled=False, default_disabled_reason=DEFAULT_OFF_REASONS[_tool["id"]])


def _load_tool_state() -> Dict[str, bool]:
    """Load persisted tool enable/disable state from disk."""
    with _STATE_LOCK:
        with _state_file_lock(exclusive=False):
            return _read_tool_state_unlocked()


def _save_tool_state(state: Dict[str, bool]) -> None:
    """Save tool enable/disable state to disk."""
    with _STATE_LOCK:
        with _state_file_lock(exclusive=True):
            _write_tool_state_unlocked(state)


def _update_tool_state(mutator) -> Dict[str, bool]:
    """Read-modify-write capabilities while holding a cross-process lock."""
    with _STATE_LOCK:
        with _state_file_lock(exclusive=True):
            state = _read_tool_state_unlocked()
            mutator(state)
            _write_tool_state_unlocked(state)
            return state


def get_tool_registry() -> List[Dict[str, Any]]:
    """Return all tools enriched with current enabled/disabled state."""
    state = _load_tool_state()
    tools = []
    for t in DEFAULT_TOOLS:
        item = dict(t)
        # Default to tool's default_enabled if not explicitly set in state
        item["enabled"] = state.get(t["id"], t["default_enabled"])
        tools.append(item)
    return tools


def is_tool_enabled(tool_id: str) -> bool:
    """Check if a specific tool is enabled."""
    with _STATE_LOCK:
        state = _load_tool_state()
        if tool_id in state:
            return state[tool_id]
        # Check default_enabled
        for t in DEFAULT_TOOLS:
            if t["id"] == tool_id:
                return t["default_enabled"]
        # Unknown tools default to True
        return True


def set_tool_enabled(tool_id: str, enabled: bool) -> bool:
    """Toggle or set a specific tool's enabled state."""
    _update_tool_state(lambda state: state.__setitem__(tool_id, bool(enabled)))
    return bool(enabled)


def toggle_tool_enabled(tool_id: str) -> bool:
    """Atomically invert a known capability, including across API workers."""
    default = next((tool["default_enabled"] for tool in DEFAULT_TOOLS if tool["id"] == tool_id), None)
    if default is None:
        raise ValueError("Unknown tool identifier")

    def toggle(state):
        state[tool_id] = not state.get(tool_id, default)

    return _update_tool_state(toggle)[tool_id]


def set_tools_bulk(updates: Dict[str, bool]) -> Dict[str, bool]:
    """Bulk update tool states."""
    def _mutate(state):
        for k, v in updates.items():
            state[k] = bool(v)
    return _update_tool_state(_mutate)


def get_tool_summary() -> Dict[str, Any]:
    """Return counts and category summaries for the capabilities view."""
    tools = get_tool_registry()
    total = len(tools)
    enabled_cnt = sum(1 for t in tools if t["enabled"])
    disabled_cnt = total - enabled_cnt

    categories: Dict[str, Dict[str, int]] = {}
    for t in tools:
        cat = t["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "enabled": 0, "disabled": 0}
        categories[cat]["total"] += 1
        if t["enabled"]:
            categories[cat]["enabled"] += 1
        else:
            categories[cat]["disabled"] += 1

    return {
        "total": total,
        "enabled": enabled_cnt,
        "disabled": disabled_cnt,
        "categories": categories,
        "tools": tools,
    }
