from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

"""
AST-Guided Context Slicer for the Lotus AI Security Harness.

Extracts minimal code context around a finding's sink location,
following the call graph backward to provide source-to-sink data flow
context within a token budget.
"""


def _extract_function_body(file_path: Path, line: int, language: str) -> Tuple[str, int, int]:
    """Extract the function body containing the given line number.

    Uses simple regex patterns per language to find function boundaries.
    Returns (function_body, start_line, end_line) where lines are 1-indexed.
    """
    if not file_path.exists():
        return ("", 0, 0)

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ("", 0, 0)

    lines = text.splitlines(keepends=True)
    if not lines or line < 1:
        return ("", 0, 0)

    # Clamp line to file bounds
    target = min(line, len(lines))

    # Language-specific function definition patterns
    func_patterns = {
        "python": re.compile(r"^\s*(async\s+)?def\s+\w+"),
        "ruby/rails": re.compile(r"^\s*def\s+\w+"),
        "node": re.compile(r"^\s*(function\s+\w+|const\s+\w+\s*=\s*(async\s+)?(function|\())"),
        "go": re.compile(r"^\s*func\s+"),
        "java": re.compile(r"^\s*(public|private|protected)\s+"),
        "c/cpp": re.compile(r"^\s*(\w+\s+)+\w+\s*\("),
        "php": re.compile(r"^\s*(public|private|protected|function)\s+"),
    }
    pattern = func_patterns.get(language, re.compile(r"^\s*(def|function|func|public|private|protected)\s+"))

    # Walk backward from target line to find the function start
    func_start = max(0, target - 31)
    for i in range(target - 1, -1, -1):
        if pattern.search(lines[i]):
            func_start = i
            break

    # Walk forward to find the function end (next function def or +60 lines)
    func_end = min(len(lines), func_start + 60)
    for i in range(target, min(len(lines), func_start + 120)):
        if i > target and pattern.search(lines[i]):
            func_end = i
            break

    body = "".join(lines[func_start:func_end])
    return (body, func_start + 1, func_end)  # 1-indexed


def _estimate_tokens(text: str) -> int:
    """Estimate token count (roughly 4 chars per token)."""
    return len(text) // 4


def slice_context_for_finding(
    finding: Dict[str, Any],
    call_graph: Dict[str, Any],
    dest_path: Path,
    max_hops: int = 5,
    max_tokens: int = 3000,
) -> str:
    """Extract minimal code context around a finding, following the call graph.

    1. Reads source file around the finding's line.
    2. Walks the call graph backward from sink to find callers.
    3. For each hop, reads the caller's function body.
    4. Assembles all slices into a single annotated string within token budget.
    """
    file_name = finding.get("file", "")
    line_num = int(finding.get("line", 1) or 1)

    if not file_name:
        return "# No file path in finding"

    file_path = dest_path / file_name
    language = finding.get("language", "python")

    # Extract the primary slice around the finding
    body, start, end = _extract_function_body(file_path, line_num, language)
    if not body:
        # Fallback: try raw line range
        if file_path.exists():
            try:
                all_lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                s = max(0, line_num - 15)
                e = min(len(all_lines), line_num + 15)
                body = "\n".join(all_lines[s:e])
                start, end = s + 1, e
            except Exception:
                return f"# Could not read {file_name}"
        else:
            return f"# File not found: {file_name}"

    slices: List[str] = [f"--- {file_name}:{start}-{end} (finding location) ---\n{body}"]
    current_tokens = _estimate_tokens(slices[0])

    functions = call_graph.get("functions", {})
    taint_paths = call_graph.get("taint_paths", [])

    # Find the function name for this finding
    func_name = None
    abs_file = str(file_path) if file_path.is_absolute() else file_name
    for fname, meta in functions.items():
        meta_file = meta.get("file", "")
        meta_line = meta.get("line", 0)
        # Match by file path (exact or suffix match) and line proximity
        if (meta_file == file_name or meta_file == abs_file or meta_file.endswith("/" + file_name)):
            if abs(meta_line - line_num) < 50:
                func_name = fname
                break

    if not func_name:
        # Try matching by short function name from title
        return "\n".join(slices)

    # Find taint paths involving this function
    relevant_chains: List[List[str]] = []
    for tp in taint_paths:
        chain = tp.get("chain", [])
        if func_name in chain or any(func_name.endswith("." + c.split(".")[-1]) for c in chain):
            relevant_chains.append(chain)

    # Also try using sink_first_paths for backward traversal
    if not relevant_chains:
        try:
            from backend.callgraph import sink_first_paths
            paths = sink_first_paths(call_graph, language, max_hops=max_hops)
            for p in paths:
                chain = p.get("chain", [])
                if func_name in chain:
                    relevant_chains.append(chain)
        except Exception:
            pass

    # Walk the chains to extract caller context
    visited = {func_name}
    for chain in relevant_chains[:3]:  # Limit to 3 chains
        for hop_func in chain:
            if hop_func in visited:
                continue
            if current_tokens >= max_tokens:
                break

            hop_meta = functions.get(hop_func, {})
            hop_file = hop_meta.get("file", "")
            hop_line = hop_meta.get("line", 1)

            if not hop_file:
                continue

            hop_path = dest_path / hop_file
            hop_body, hop_start, hop_end = _extract_function_body(hop_path, hop_line, language)

            if not hop_body:
                continue

            hop_slice = f"--- {hop_file}:{hop_start}-{hop_end} (caller: {hop_func}) ---\n{hop_body}"
            hop_tokens = _estimate_tokens(hop_slice)

            if current_tokens + hop_tokens > max_tokens:
                break

            slices.insert(0, hop_slice)
            current_tokens += hop_tokens
            visited.add(hop_func)

    return "\n".join(slices)
