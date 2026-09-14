"""Audit depth level configuration.

Maps depth levels 1-5 to concrete scan parameters that control
how aggressive the vulnerability discovery process is.

Level 1: Quick surface scan - core tools only, 1 review iteration
Level 2: Standard discovery - adds structural analysis, 2 iterations
Level 3: Deep analysis - all tools, 3 iterations, expanded callgraph
Level 4: Thorough - larger budgets and variant/chain review guidance
Level 5: Exhaustive - largest bounded budgets and configuration/race review guidance

Every level runs one analyzer pass. Applicability, capability switches, resource
limits and evidence gates still apply; a depth preset is never a coverage claim.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, List, Set
from types import MappingProxyType


@dataclass(frozen=True)
class DepthConfig:
    """Configuration produced by an audit depth level."""

    level: int
    label: str
    description: str
    # Phase 1 tool selection
    phase1_tool_sets: tuple[str, ...]
    # Iteration ceiling for the qualification loop in Phase 3 AI review
    phase2_max_iterations: int
    # Callgraph limits
    callgraph_max_files: int
    # Actual full Phase 1 analyzer passes (no synthetic repeated scans)
    discovery_passes: int
    # Whether extra Phase 2 prompt guidance includes hypotheses
    hypothesis_driven: bool
    # Whether extra Phase 2 prompt guidance includes chain review
    chain_analysis: bool
    # Max concurrent tools during recon
    max_concurrent_tools: int
    # Extra AI prompt context for deeper analysis
    extra_prompt_context: str = ""


# Canonical names used by run_recon. These are eligible tools, not a promise
# that an inapplicable, unavailable or disabled analyzer will execute.
CORE_TOOLS = frozenset({
    "cross-file-taint", "lockfile-audit", "taint-proximity", "secret-scan", "semgrep",
    "grep-patterns", "methodology-patterns", "dependency-map", "attack-surface-map",
    "trust-boundary-map", "handler-sink-trace", "component-lab-map", "config-audit",
    "osv-cve-check", "bundle-audit", "brakeman", "test-coverage-gap", "gosec",
    "govulncheck", "staticcheck", "semgrep-registry", "osv-scanner", "native-package-audits",
})
STRUCTURAL_TOOLS = frozenset({
    "auth-structural-bypass", "entry-point-dataflow", "high-severity-surface",
    "control-plane-surface", "gateway-control-plane", "agent-app-control-plane",
    "by-design-gate", "high-yield-discovery", "commit-security-analysis", "doc-driven-hypothesis",
})
ADVANCED_TOOLS = frozenset({
    "deserialization-chain", "sql-concat-audit", "boundary-crossing-audit",
    "container-security-audit", "build-flag-audit", "crypto-timing-audit",
    "config-shell-injection", "dynamic-dispatch", "test-oracle-miner",
})
DEEP_TOOLS = frozenset({
    "complexity-hotspot", "unsafe-c-api", "parser-boundary", "integer-boundary",
    "error-path-residue", "check-referent-mismatch", "single-pass-strip",
})


def normalize_depth_level(level: object) -> int:
    """Clamp old integer values; corrupt/missing types use the current default.

    Settings writes validate strict integers separately. Never coerce booleans,
    fractions, or arbitrary strings into a different user-selected preset.
    """
    return max(1, min(5, level)) if type(level) is int else 3


def admitted_depth(settings, requested=None, *, previous=None, output=None) -> int:
    """Capture one audit's effort choice without changing the Settings default.

    Recovery/child jobs inherit an existing scalar. Replay can also retain the
    already-read historical recon contract for pre-column audits.
    """
    if requested is not None:
        if type(requested) is not int or not 1 <= requested <= 5:
            raise ValueError("audit_depth must be an integer from 1 to 5")
        return requested
    value = getattr(previous, "audit_depth", None)
    if type(value) is int and 1 <= value <= 5:
        return value
    if isinstance(output, dict):
        recon = output.get("recon_summary")
        depth = recon.get("audit_depth") if isinstance(recon, dict) else None
        value = depth.get("level") if isinstance(depth, dict) else None
        if type(value) is int and 1 <= value <= 5:
            return value
    return normalize_depth_level(settings.get("audit_depth") if isinstance(settings, dict)
                                 else getattr(settings, "audit_depth", None))


# Depth level configurations
DEPTH_CONFIGS = MappingProxyType({
    1: DepthConfig(
        level=1,
        label="Quick",
        description="Surface-level scan with core pattern matching and dependency checks",
        phase1_tool_sets=("core",),
        phase2_max_iterations=1,
        callgraph_max_files=200,
        discovery_passes=1,
        hypothesis_driven=False,
        chain_analysis=False,
        max_concurrent_tools=4,
    ),
    2: DepthConfig(
        level=2,
        label="Standard",
        description="Standard discovery with structural analysis and auth bypass detection",
        phase1_tool_sets=("core", "structural"),
        phase2_max_iterations=2,
        callgraph_max_files=300,
        discovery_passes=1,
        hypothesis_driven=False,
        chain_analysis=False,
        max_concurrent_tools=6,
    ),
    3: DepthConfig(
        level=3,
        label="Deep",
        description="Deep analysis with all tools, expanded callgraph, and extended AI review",
        phase1_tool_sets=("core", "structural", "advanced", "deep"),
        phase2_max_iterations=3,
        callgraph_max_files=500,
        discovery_passes=1,
        hypothesis_driven=False,
        chain_analysis=False,
        max_concurrent_tools=8,
    ),
    4: DepthConfig(
        level=4,
        label="Thorough",
        description="Full analyzer battery with larger budgets and variant/chain review guidance",
        phase1_tool_sets=("core", "structural", "advanced", "deep"),
        phase2_max_iterations=5,
        callgraph_max_files=800,
        discovery_passes=1,
        hypothesis_driven=True,
        chain_analysis=True,
        max_concurrent_tools=10,
        extra_prompt_context=(
            "This is a THOROUGH audit. Push harder for bug discovery. "
            "Re-examine code paths adjacent to any confirmed sinks. "
            "Look for variant patterns of any bugs already found. "
            "Consider multi-step attack chains combining multiple weaknesses."
        ),
    ),
    5: DepthConfig(
        level=5,
        label="Exhaustive",
        description="Largest bounded budgets with variant, chain, configuration and race review guidance",
        phase1_tool_sets=("core", "structural", "advanced", "deep"),
        phase2_max_iterations=8,
        callgraph_max_files=1500,
        discovery_passes=1,
        hypothesis_driven=True,
        chain_analysis=True,
        max_concurrent_tools=12,
        extra_prompt_context=(
            "This is an EXHAUSTIVE audit at maximum depth. "
            "Leave no stone unturned. For every finding, explore: "
            "1) All variant patterns in the same codebase. "
            "2) Adjacent code paths that may have the same class of bug. "
            "3) Multi-step chains combining 2+ weaknesses into higher-impact exploits. "
            "4) Configuration-dependent bugs that appear under non-default settings. "
            "5) Race conditions and TOCTOU issues in concurrent code. "
            "Use recorded Phase 1 evidence and relevant learned skills; never infer missing proof."
        ),
    ),
})


def get_depth_config(level: int, settings: dict | None = None) -> DepthConfig:
    """Get the depth configuration for a given level (1-5).

    Clamps to valid range if out of bounds.
    """
    config = DEPTH_CONFIGS[normalize_depth_level(level)]
    if not isinstance(settings, dict):
        return config
    caps = {}
    for name, lower, upper in (("phase2_max_iterations", 1, 20), ("callgraph_max_files", 10, 5000),
                               ("max_concurrent_tools", 2, 32)):
        value = settings.get(name)
        if type(value) is int and lower <= value <= upper:
            # An explicitly saved file budget is a user choice, including an
            # increase within the validated 5,000-file ceiling. Other depth
            # settings remain lower caps on the selected preset.
            caps[name] = value if name == "callgraph_max_files" else min(getattr(config, name), value)
    return replace(config, **caps)


def get_enabled_tools(level: int) -> Set[str]:
    """Return the set of tool names enabled for a given depth level."""
    config = get_depth_config(level)
    tools = set()
    for tool_set_name in config.phase1_tool_sets:
        if tool_set_name == "core":
            tools |= CORE_TOOLS
        elif tool_set_name == "structural":
            tools |= STRUCTURAL_TOOLS
        elif tool_set_name == "advanced":
            tools |= ADVANCED_TOOLS
        elif tool_set_name == "deep":
            tools |= DEEP_TOOLS
    return tools


def depth_summary(config: DepthConfig) -> dict:
    """Small durable effort contract shared by live progress and audit output."""
    preset = DEPTH_CONFIGS[config.level]
    return {
        "level": config.level, "label": config.label,
        "phase2_max_iterations": config.phase2_max_iterations,
        "callgraph_max_files": config.callgraph_max_files,
        "max_concurrent_tools": config.max_concurrent_tools,
        "discovery_passes": config.discovery_passes,
        "extra_prompt_context": config.extra_prompt_context,
        "preset_phase2_max_iterations": preset.phase2_max_iterations,
        "preset_callgraph_max_files": preset.callgraph_max_files,
        "preset_max_concurrent_tools": preset.max_concurrent_tools,
        "eligible_tools": sorted(get_enabled_tools(config.level)),
        "limitations": "Upper bounds; feature switches, applicability, availability and resource limits apply. Coverage and proof remain required.",
    }


def get_all_levels_summary() -> List[Dict]:
    """Return a summary of all depth levels for UI display."""
    return [
        {
            "level": cfg.level,
            "label": cfg.label,
            "description": cfg.description,
            "phase2_iterations": cfg.phase2_max_iterations,
            "callgraph_files": cfg.callgraph_max_files,
            "discovery_passes": cfg.discovery_passes,
            "tool_count": len(get_enabled_tools(cfg.level)),
            "max_concurrent_tools": cfg.max_concurrent_tools,
        }
        for cfg in DEPTH_CONFIGS.values()
    ]
