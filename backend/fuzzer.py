"""
Fuzzing and crash triage for C/C++/Rust targets.

Architecture:
  - Lab container builds target with ASan/UBSan instrumentation
  - Crafted inputs derived from Phase 1 intel (parser entry points, file formats)
  - Crashes triaged via memory conviction bridge (crash → read → write → control → RCE)
  - Results feed back as QUALIFIED findings with lab_evidence
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.async_process import terminate_and_reap


def read_fuzz_settings(api_keys: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    keys = api_keys or {}
    return {
        "fuzzing_enabled": str(keys.get("fuzzing_enabled", os.environ.get("LOTUS_FUZZING", ""))).lower() in ("true", "1", "yes"),
        "fuzz_timeout": int(keys.get("fuzz_timeout") or os.environ.get("LOTUS_FUZZ_TIMEOUT", "300")),
        "crash_triage_enabled": str(keys.get("crash_triage_enabled", "true")).lower() not in ("false", "0", "no"),
    }


def _classify_crash(asan_output: str) -> Dict[str, Any]:
    """Classify an ASan/UBSan crash for exploitability.

    Returns conviction bridge rung and exploitability assessment.
    """
    output_lower = asan_output.lower()

    crash_type = "unknown"
    exploitability = "unknown"
    cvss = 3.0
    conviction_rung = "crash"
    bridge_notes = []

    # Identify crash type from ASan output
    if "heap-buffer-overflow" in output_lower:
        crash_type = "heap-buffer-overflow"
        if "write" in output_lower:
            exploitability = "likely_exploitable"
            cvss = 8.0
            conviction_rung = "bounded_write"
            bridge_notes.append("Heap write overflow  - potential for controlled write primitive")
        else:
            exploitability = "potentially_exploitable"
            cvss = 6.5
            conviction_rung = "controlled_read"
            bridge_notes.append("Heap read overflow  - information disclosure, potential for controlled read")
    elif "stack-buffer-overflow" in output_lower:
        crash_type = "stack-buffer-overflow"
        exploitability = "likely_exploitable"
        cvss = 7.5
        conviction_rung = "bounded_write"
        bridge_notes.append("Stack overflow  - potential return address overwrite (check canary)")
    elif "heap-use-after-free" in output_lower:
        crash_type = "use-after-free"
        exploitability = "likely_exploitable"
        cvss = 8.5
        conviction_rung = "bounded_write"
        bridge_notes.append("Use-after-free  - type confusion via dangling pointer, potential vtable/function pointer overwrite")
    elif "double-free" in output_lower:
        crash_type = "double-free"
        exploitability = "likely_exploitable"
        cvss = 8.0
        conviction_rung = "bounded_write"
        bridge_notes.append("Double-free  - heap metadata corruption, potential arbitrary write primitive")
    elif "null" in output_lower and "dereference" in output_lower or "segv on unknown address: 0x00000000" in output_lower:
        crash_type = "null-pointer-dereference"
        exploitability = "not_exploitable"
        cvss = 3.5
        conviction_rung = "crash"
        bridge_notes.append("NULL dereference  - DoS only (A:L)")
    elif "integer-overflow" in output_lower or "signed-integer-overflow" in output_lower:
        crash_type = "integer-overflow"
        exploitability = "potentially_exploitable"
        cvss = 5.5
        conviction_rung = "crash"
        bridge_notes.append("Integer overflow  - may lead to undersized allocation then heap overflow")
    elif "out-of-bounds" in output_lower or "global-buffer-overflow" in output_lower:
        crash_type = "out-of-bounds"
        if "write" in output_lower:
            exploitability = "likely_exploitable"
            cvss = 7.5
            conviction_rung = "bounded_write"
        else:
            exploitability = "potentially_exploitable"
            cvss = 6.0
            conviction_rung = "controlled_read"
        bridge_notes.append(f"OOB {'write' if 'write' in output_lower else 'read'}")
    elif "undefined-behavior" in output_lower or "ubsan" in output_lower:
        crash_type = "undefined-behavior"
        exploitability = "potentially_exploitable"
        cvss = 4.5
        conviction_rung = "crash"
        bridge_notes.append("UBSan: undefined behavior  - compiler may optimize away security checks")
    elif "segmentation fault" in output_lower or "sigsegv" in output_lower:
        crash_type = "segfault"
        exploitability = "potentially_exploitable"
        cvss = 5.0
        conviction_rung = "crash"
        bridge_notes.append("Segfault without ASan  - needs ASan rebuild for classification")

    # Extract crash location
    location = ""
    for line in asan_output.splitlines():
        if "#0" in line and ("in " in line or "at " in line):
            location = line.strip()[:200]
            break

    # Extract allocation/access info
    alloc_info = ""
    for line in asan_output.splitlines():
        if "allocated" in line.lower() or "freed" in line.lower() or "of size" in line.lower():
            alloc_info += line.strip()[:150] + "; "

    return {
        "crash_type": crash_type,
        "exploitability": exploitability,
        "cvss": cvss,
        "conviction_rung": conviction_rung,
        "bridge_notes": bridge_notes,
        "location": location,
        "alloc_info": alloc_info[:300],
        "bridge_status": {
            "crash": True,
            "controlled_read": conviction_rung in ("controlled_read", "bounded_write", "primitive_upgrade", "rce"),
            "bounded_write": conviction_rung in ("bounded_write", "primitive_upgrade", "rce"),
            "primitive_upgrade": conviction_rung in ("primitive_upgrade", "rce"),
            "rce": conviction_rung == "rce",
        },
        "headline": f"{crash_type} ({exploitability})",
        "ceiling": "RCE if write primitive upgraded to control" if conviction_rung == "bounded_write" else
                   "Write primitive if read extended" if conviction_rung == "controlled_read" else
                   "DoS (A:L)" if conviction_rung == "crash" else "Unknown",
    }


def _discover_fuzz_harness(dest: Path) -> Optional[str]:
    """Find a libFuzzer harness (LLVMFuzzerTestOneInput) in the repo. Returns the
    repo-relative path of the harness source, or None. Prefers conventional fuzz dirs."""
    try:
        candidates = []
        for p in list(dest.rglob("*.c")) + list(dest.rglob("*.cc")) + list(dest.rglob("*.cpp")):
            parts = {x.lower() for x in p.parts}
            if parts & {".git", "node_modules", "vendor", "third_party", "build"}:
                continue
            try:
                if "LLVMFuzzerTestOneInput" in p.read_text(errors="ignore"):
                    rel = str(p.relative_to(dest))
                    # Prefer files under a fuzz/ or test/fuzz dir
                    score = 0 if any(seg in rel.lower() for seg in ("fuzz", "oss-fuzz")) else 1
                    candidates.append((score, len(rel), rel))
            except Exception:
                continue
        if candidates:
            candidates.sort()
            return candidates[0][2]
    except Exception:
        pass
    return None


async def _run_libfuzzer(repo_id, dest, container, harness_rel, timeout, settings, send, _exec):
    """Build + run a coverage-guided libFuzzer harness inside the lab container.

    Best-effort for self-contained harnesses (harness + sibling sources). Returns
    (findings, stats); status='completed' when it built and ran, else 'skipped' so the
    caller can fall back to crafted-input differential fuzzing.
    """
    findings: List[Dict[str, Any]] = []
    stats = {"status": "skipped", "engine": "libfuzzer", "crashes": 0, "execs": 0}
    if send:
        await send(repo_id, f"▶ Coverage-guided libFuzzer on harness {harness_rel} ...",
                   detail_id=f"{repo_id}-task-fuzz-build")
    # Ensure a fuzzer-capable clang is present (best-effort; may be offline).
    chk, _ = await _exec(["docker", "exec", container, "sh", "-c",
                          "command -v clang >/dev/null 2>&1 && echo HAVE_CLANG || "
                          "(apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang >/dev/null 2>&1 && echo HAVE_CLANG || echo NO_CLANG)"],
                         timeout_s=180)
    if "HAVE_CLANG" not in (chk or ""):
        if send:
            await send(repo_id, "libFuzzer skipped (clang unavailable in lab); using crafted inputs",
                       level="warning", detail_id=f"{repo_id}-task-fuzz-build")
        return findings, stats
    hdir = os.path.dirname(harness_rel) or "."
    budget = max(20, min(int(timeout), 600))
    # Compile the harness with sibling C/C++ sources in its directory.
    build = (
        f"cd /app && mkdir -p /tmp/lf && "
        f"SRC=$(ls {hdir}/*.c {hdir}/*.cc {hdir}/*.cpp 2>/dev/null | tr '\\n' ' '); "
        f"clang -g -O1 -fsanitize=fuzzer,address,undefined -I. -I{hdir} $SRC -o /tmp/lf/fuzzer 2>&1 | tail -25 && echo BUILD_OK || echo BUILD_FAIL"
    )
    bout, _ = await _exec(["docker", "exec", container, "sh", "-c", build], timeout_s=240)
    if "BUILD_OK" not in (bout or ""):
        if send:
            await send(repo_id, f"libFuzzer build failed; falling back to crafted inputs ({(bout or '')[-160:]})",
                       level="warning", detail_id=f"{repo_id}-task-fuzz-build")
        return findings, stats
    if send:
        await send(repo_id, f"✓ libFuzzer built; running for {budget}s",
                   detail_id=f"{repo_id}-task-fuzz-build")
        await send(repo_id, "▶ Coverage-guided fuzzing...", detail_id=f"{repo_id}-task-fuzzing")
    run = (
        f"cd /tmp/lf && mkdir -p corpus && "
        f"./fuzzer -max_total_time={budget} -timeout=10 -rss_limit_mb=2048 -artifact_prefix=/tmp/lf/ corpus 2>&1 | tail -80; "
        f"echo EXIT=$?"
    )
    rout, _ = await _exec(["docker", "exec", container, "sh", "-c", run], timeout_s=budget + 120)
    stats["status"] = "completed"
    m = re.search(r"#(\d+)\s+DONE", rout or "") or re.search(r"stat::number_of_executed_units:\s*(\d+)", rout or "")
    if m:
        stats["execs"] = int(m.group(1))
    crashed = bool(re.search(r"AddressSanitizer|UndefinedBehaviorSanitizer|libFuzzer: deadly signal|ERROR: libFuzzer|SUMMARY:", rout or ""))
    if crashed:
        triage = _classify_crash(rout) if settings.get("crash_triage_enabled") else {
            "crash_type": "unclassified", "exploitability": "unknown", "cvss": 6.0,
            "conviction_rung": "crash", "bridge_notes": ["Triage disabled"], "location": "",
            "headline": "libFuzzer crash", "ceiling": "Unknown", "bridge_status": {"crash": True},
        }
        stats["crashes"] = 1
        findings.append({
            "tool": "fuzzer",
            "title": f"Coverage-guided crash: {triage['crash_type']} in {os.path.basename(harness_rel)}",
            "cvss": triage["cvss"],
            "description": (
                f"libFuzzer (coverage-guided, ASan/UBSan) crash: {triage['headline']}. "
                f"Location: {triage.get('location','unknown')[:160]}. "
                f"Conviction: {triage['conviction_rung']}. Ceiling: {triage.get('ceiling','unknown')}. "
                f"{'; '.join(triage.get('bridge_notes', []))}"
            ),
            "file": harness_rel, "line": 0, "confidence": "high",
            "qualification": "QUALIFIED",
            "conviction_level": 3 if triage["exploitability"] == "likely_exploitable" else 2,
            "lab_evidence": [{
                "path": "libfuzzer", "params": {"harness": harness_rel, "max_total_time": budget},
                "snippet": (rout or "")[-400:], "status": 1, "anomaly_type": triage["crash_type"], "method": "fuzz",
            }],
            "proven_in_lab": True, "crash_triage": triage,
            "poc": {"command": f"clang -fsanitize=fuzzer,address {harness_rel} && ./fuzzer <crash-input>",
                    "harness": harness_rel},
            "poc_result": "triggered",
        })
        if send:
            level = "error" if triage["exploitability"] == "likely_exploitable" else "warning"
            await send(repo_id, f"CRASH (coverage-guided): {triage['headline']}", level=level,
                       detail_id=f"{repo_id}-task-fuzzing")
    elif send:
        await send(repo_id, f"✓ Coverage-guided fuzzing: 0 crashes ({stats['execs']} execs, {budget}s)",
                   level="success", detail_id=f"{repo_id}-task-fuzzing")
    return findings, stats


async def run_c_fuzzing(
    repo_id: int,
    dest: Path,
    language: str,
    send: Optional[Callable] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Build with ASan and fuzz C/C++ parser entry points.

    Returns (findings, stats).
    """
    settings = settings or read_fuzz_settings()
    findings: List[Dict[str, Any]] = []
    stats = {"status": "skipped", "crashes": 0, "inputs_tested": 0, "time_ms": 0}

    if language not in ("c/cpp", "c", "cpp", "rust"):
        return findings, stats
    if not settings.get("fuzzing_enabled"):
        stats["status"] = "disabled"
        return findings, stats

    t0 = time.monotonic()

    try:
        from backend import lab as lab_mod
        container = lab_mod.get_lab_container(repo_id)
    except Exception:
        stats["status"] = "no_container"
        return findings, stats

    timeout = min(settings.get("fuzz_timeout", 300), 600)

    async def _exec(cmd, timeout_s=30):
        try:
            from backend.lab import _controlled_child_env
            child_env = _controlled_child_env()
        except Exception:
            child_env = None
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=child_env,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.CancelledError:
            await terminate_and_reap(proc)
            raise
        except asyncio.TimeoutError:
            await terminate_and_reap(proc)
            return "TIMEOUT", -1
        return stdout.decode(errors="replace"), proc.returncode

    # --- Preferred: coverage-guided libFuzzer when the repo ships a fuzz harness ---
    harness = _discover_fuzz_harness(dest)
    if harness:
        cg_findings, cg_stats = await _run_libfuzzer(
            repo_id, dest, container, harness, timeout, settings, send, _exec)
        if cg_stats.get("status") == "completed":
            cg_stats["time_ms"] = int((time.monotonic() - t0) * 1000)
            cg_stats["inputs_tested"] = cg_stats.get("execs", 0)
            return cg_findings, cg_stats
        # else: build/clang unavailable  - fall through to crafted-input differential fuzzing

    if send:
        await send(repo_id, "▶ Building target with ASan/UBSan instrumentation...",
                   detail_id=f"{repo_id}-task-fuzz-build")

    # Step 1: Try to build with sanitizers inside the lab container
    build_cmds = [
        # Try configure + make with sanitizers
        "cd /app && (test -f configure.ac && phpize && ./configure CFLAGS='-fsanitize=address,undefined -g -O1' LDFLAGS='-fsanitize=address,undefined' 2>&1 || "
        "test -f Makefile && make clean 2>/dev/null; make CC='gcc -fsanitize=address,undefined -g -O1' 2>&1 || "
        "test -f CMakeLists.txt && mkdir -p build && cd build && cmake -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' .. && make 2>&1 || "
        "echo 'NO_BUILD_SYSTEM') | tail -20",
    ]
    build_out, build_rc = await _exec(
        ["docker", "exec", container, "sh", "-c", build_cmds[0]],
        timeout_s=120,
    )
    if send:
        if "NO_BUILD_SYSTEM" in build_out:
            await send(repo_id, "✗ No recognized build system for ASan build",
                       level="warning", detail_id=f"{repo_id}-task-fuzz-build")
        elif build_rc != 0:
            await send(repo_id, f"✗ ASan build failed (rc={build_rc})",
                       level="warning", detail_id=f"{repo_id}-task-fuzz-build")
        else:
            await send(repo_id, "✓ ASan/UBSan build complete",
                       detail_id=f"{repo_id}-task-fuzz-build")

    if send:
        await send(repo_id, "▶ Fuzzing parser entry points with crafted inputs...",
                   detail_id=f"{repo_id}-task-fuzzing")

    # Step 2: Generate crafted fuzz inputs from file type
    yaml_inputs = [
        # Standard edge cases
        "---\n" * 100,
        "a: " + "x" * 100000,
        "!!python/object/apply:os.system [id]\n",
        '{"a":' * 50 + '"x"' + '}' * 50,
        # Entity/alias bombs
        "a: &a [x,x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n",
        # Malformed UTF-8
        "key: \xff\xfe\x00\x01\n",
        # Deeply nested
        "a:\n" + "  " * 200 + "b: c\n",
        # Null bytes
        "key: value\x00hidden\n",
        # Very long key
        "a" * 65536 + ": value\n",
        # Binary in YAML
        "!!binary |\n  " + "A" * 10000 + "\n",
        # Tag injection
        "!!str &anchor\n- *anchor\n- !!int 42\n",
        # Multi-document with edges
        "---\na: 1\n...\n---\nb: 2\n...\n" * 100,
    ]

    crashes = []
    for i, payload in enumerate(yaml_inputs):
        # Write payload to container and run through parser
        cmd = (
            f"echo '{json.dumps(payload)}' | python3 -c 'import sys,json; sys.stdout.write(json.loads(sys.stdin.read()))' > /tmp/fuzz_{i}.yaml 2>/dev/null; "
            f"cd /app && ("
            f"php -r 'yaml_parse_file(\"/tmp/fuzz_{i}.yaml\");' 2>&1 || "
            f"python3 -c 'import yaml; yaml.safe_load(open(\"/tmp/fuzz_{i}.yaml\"))' 2>&1 || "
            f"cat /tmp/fuzz_{i}.yaml | timeout 5 ./yaml_parse 2>&1 || "
            f"echo PARSE_DONE"
            f") 2>&1 | head -50"
        )
        out, rc = await _exec(
            ["docker", "exec", container, "sh", "-c", cmd],
            timeout_s=15,
        )
        stats["inputs_tested"] += 1

        # Check for ASan/UBSan/crash output
        is_crash = (
            "AddressSanitizer" in out
            or "UndefinedBehaviorSanitizer" in out
            or "Segmentation fault" in out
            or "SIGSEGV" in out
            or "SIGABRT" in out
            or rc in (134, 135, 136, 137, 139)  # signal exits
        )

        if is_crash:
            stats["crashes"] += 1
            triage = _classify_crash(out) if settings.get("crash_triage_enabled") else {
                "crash_type": "unclassified", "exploitability": "unknown", "cvss": 5.0,
                "conviction_rung": "crash", "bridge_notes": ["Triage disabled"],
                "location": "", "headline": "Crash (triage disabled)", "ceiling": "Unknown",
                "bridge_status": {"crash": True},
            }

            finding = {
                "tool": "fuzzer",
                "title": f"Crash: {triage['crash_type']} in parser (input #{i})",
                "cvss": triage["cvss"],
                "description": (
                    f"ASan/fuzz crash: {triage['headline']}. "
                    f"Location: {triage.get('location', 'unknown')[:120]}. "
                    f"Conviction bridge: {triage['conviction_rung']}. "
                    f"Ceiling: {triage.get('ceiling', 'unknown')}. "
                    f"{'; '.join(triage.get('bridge_notes', []))}"
                ),
                "file": "parser",
                "line": 0,
                "confidence": "high",
                "qualification": "QUALIFIED",
                "conviction_level": 3 if triage["exploitability"] == "likely_exploitable" else 2,
                "lab_evidence": [{
                    "path": "fuzzer",
                    "params": {"input_index": i, "payload_size": len(payload)},
                    "snippet": out[:200],
                    "status": rc,
                    "anomaly_type": triage["crash_type"],
                    "method": "fuzz",
                }],
                "proven_in_lab": True,
                "crash_triage": triage,
                "poc": {
                    "command": f"echo '<payload>' | php -r 'yaml_parse_file(\"/dev/stdin\");'",
                    "payload_index": i,
                },
                "poc_result": "triggered",
            }
            findings.append(finding)
            crashes.append({"index": i, "type": triage["crash_type"], "exploitability": triage["exploitability"]})

            if send:
                level = "error" if triage["exploitability"] == "likely_exploitable" else "warning"
                await send(repo_id,
                    f"CRASH: {triage['headline']}  - {triage.get('ceiling', '?')} "
                    f"(input #{i}, rc={rc})",
                    level=level)

    stats["time_ms"] = int((time.monotonic() - t0) * 1000)
    stats["status"] = "completed"
    stats["crashes"] = len(crashes)
    stats["crash_details"] = crashes

    if send:
        if crashes:
            await send(repo_id,
                f"✓ Fuzzing complete: {len(crashes)} crashes from {stats['inputs_tested']} inputs "
                f"({stats['time_ms']}ms)",
                level="success", detail_id=f"{repo_id}-task-fuzzing")
        else:
            await send(repo_id,
                f"✓ Fuzzing complete: 0 crashes from {stats['inputs_tested']} inputs "
                f"({stats['time_ms']}ms)",
                detail_id=f"{repo_id}-task-fuzzing")

    return findings, stats
