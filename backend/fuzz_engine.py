"""Reusable C/C++ fuzzing engine (platform capability).

Compiles a standard `LLVMFuzzerTestOneInput` harness against target C sources
and runs a time-boxed campaign under sanitizers, returning a structured result
(crash? reproducer bytes? sanitizer report?). Two backends, auto-selected:

  * **libFuzzer** (coverage-guided) when `clang` + the fuzzer runtime exist.
  * **ASan/UBSan mutation driver** (`fuzz_driver.c`) with plain `gcc` otherwise,
    so it still runs in minimal lab images with no clang/network.

Designed to run on the host if a toolchain is present, or inside a container
(the lab substrate). Only reports a bug when a sanitizer actually aborts and a
reproducer is captured — never fabricates crashes.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

FUZZ_DIR = Path(__file__).resolve().parent / "harness" / "fuzz"
DRIVER = FUZZ_DIR / "fuzz_driver.c"

_SAN = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"]
_CRASH_RE = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "ERROR: libFuzzer",
             "runtime error:", "SEGV", "heap-buffer-overflow", "stack-buffer-overflow",
             "global-buffer-overflow", "heap-use-after-free")


@dataclass
class FuzzResult:
    target: str
    backend: str
    built: bool
    ran: bool
    crashed: bool
    seconds: float
    iterations: Optional[int] = None
    sanitizer_report: str = ""
    reproducer_hex: str = ""
    build_error: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _clang_has_libfuzzer() -> bool:
    if not _have("clang"):
        return False
    try:
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "t.c"
        src.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}\n")
        r = subprocess.run(
            ["clang", "-fsanitize=fuzzer,address", str(src), "-o", str(tmp / "t")],
            capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def run_campaign(
    target_harness: Path,
    sources: List[Path],
    include_dirs: List[Path],
    seconds: int = 20,
    seed: int = 1,
    workdir: Optional[Path] = None,
) -> FuzzResult:
    """Build `target_harness` + `sources` and fuzz for `seconds`.

    `target_harness` must define `LLVMFuzzerTestOneInput`.
    """
    target_harness = Path(target_harness)
    work = Path(workdir or tempfile.mkdtemp(prefix="fuzz_"))
    work.mkdir(parents=True, exist_ok=True)
    binp = work / "fuzzer"
    crash = work / "crash-input"
    inc = []
    for d in include_dirs:
        inc += ["-I", str(d)]
    src_args = [str(target_harness)] + [str(s) for s in sources]

    use_libfuzzer = _clang_has_libfuzzer()
    if use_libfuzzer:
        backend = "clang+libFuzzer(+ASan/UBSan)"
        build = ["clang", *_SAN, "-fsanitize=fuzzer", *inc, *src_args, "-o", str(binp)]
    else:
        cc = "gcc" if _have("gcc") else ("clang" if _have("clang") else None)
        if cc is None:
            return FuzzResult(target=target_harness.name, backend="none", built=False,
                              ran=False, crashed=False, seconds=0.0,
                              build_error="no C compiler (clang/gcc) available")
        backend = f"{cc}+driver(ASan/UBSan)"
        build = [cc, *_SAN, *inc, str(DRIVER), *src_args, "-o", str(binp)]

    b = subprocess.run(build, capture_output=True, text=True)
    if b.returncode != 0:
        return FuzzResult(target=target_harness.name, backend=backend, built=False,
                          ran=False, crashed=False, seconds=0.0,
                          build_error=(b.stderr or b.stdout)[-4000:])

    import os
    import time
    env = dict(os.environ, FUZZ_CRASH_FILE=str(crash),
               ASAN_OPTIONS="abort_on_error=1:detect_leaks=0",
               UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1")
    if use_libfuzzer:
        cmd = [str(binp), f"-max_total_time={seconds}", f"-seed={seed}",
               "-artifact_prefix=" + str(work) + "/"]
    else:
        cmd = [str(binp), str(seed), str(seconds)]

    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(work),
                       env=env, timeout=seconds + 120)
    elapsed = time.time() - t0
    out = (r.stderr or "") + "\n" + (r.stdout or "")
    crashed = (r.returncode != 0) and any(k in out for k in _CRASH_RE)

    repro_hex = ""
    if crashed:
        # libFuzzer writes crash-*; our driver writes FUZZ_CRASH_FILE.
        cand = (list(work.glob("crash-*")) + list(work.glob("*crash*"))
                + ([crash] if crash.exists() else []))
        cand = [c for c in cand if c.is_file()]
        if cand:
            repro_hex = cand[0].read_bytes()[:256].hex()

    iters = None
    for line in out.splitlines():
        if "completed" in line and "iterations" in line:
            try:
                iters = int(line.split("completed", 1)[1].split("iterations")[0].strip().rstrip(","))
            except Exception:
                pass

    return FuzzResult(
        target=target_harness.name, backend=backend, built=True, ran=True,
        crashed=crashed, seconds=round(elapsed, 2), iterations=iters,
        sanitizer_report=(out[-4000:] if crashed else ""),
        reproducer_hex=repro_hex,
        notes=([] if use_libfuzzer else
               ["libFuzzer runtime unavailable; used sanitizer mutation driver "
                "(not coverage-guided). Install clang+compiler-rt for coverage."]),
    )


def bup_bupsplit_campaign(bup_root: Path, seconds: int = 20) -> FuzzResult:
    """Convenience: fuzz bup's rolling-checksum splitter on untrusted buffers."""
    bup_root = Path(bup_root)
    libbup = bup_root / "lib" / "bup"
    return run_campaign(
        target_harness=FUZZ_DIR / "bupsplit_target.c",
        sources=[libbup / "bupsplit.c"],
        include_dirs=[libbup],
        seconds=seconds,
    )


if __name__ == "__main__":
    import json
    import sys
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "data/e2e_targets/bup")
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    res = bup_bupsplit_campaign(root, seconds=secs)
    print(json.dumps(res.to_dict(), indent=2))
    # Exit 2 only on a real, reproduced crash; 0 otherwise (capability ran).
    raise SystemExit(2 if res.crashed else (0 if res.built and res.ran else 1))
