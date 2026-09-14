"""Fix verification component.

Given a finding's proposed fix (BEFORE→AFTER code), this actually:
  1. Locates the cited file inside the isolated lab pod.
  2. Runs the reproduction PoC as a BASELINE (expects it to reproduce the issue).
  3. Applies the patch in-place in the pod (BEFORE→AFTER literal replace, backed up).
  4. Re-runs the PoC (expects it now blocked).
  5. Best-effort runs the fix's regression test.
  6. Measures before/after PoC timing.
  7. Restores the original file and returns a quality verdict.

It is deliberately conservative: if the BEFORE snippet is not present in the real file
(class templates won't always match), it reports `applied=False` with a clear reason
instead of guessing. The decisive quality signal is PoC-reproduced-before /
PoC-blocked-after, which is real evidence the fix remediates the issue.
"""
from __future__ import annotations

import base64
import time
from typing import Any, Dict, Optional

from backend import lab


def _safe_path(p: str) -> str:
    return (p or "").replace("'", "").replace("\n", "").strip()


def _b64(s: str) -> str:
    return base64.b64encode((s or "").encode()).decode()


def _looks_vulnerable(out: str) -> bool:
    o = (out or "").lower()
    if "not reproduced" in o and "vulnerable:" not in o:
        return False
    needles = (
        "vulnerable", "uid=", "root:x:0:0",
        "cmd subcommands", "lost connection", "error 2013",
        "progressive_merge", "lotus_poc_impact", "admincommandresponse",
        "kill_ok", "create database", "e_tcpadmin", "brokerconfig",
    )
    return any(n in o for n in needles)


async def verify_fix_in_lab(
    repo_id: int,
    *,
    file: str = "",
    before: str = "",
    after: str = "",
    repro_poc: str = "",
    test: str = "",
    test_lang: str = "python",
    lang: str = "",
    keep_applied: bool = False,
    expected_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply + verify + measure a fix inside the repo's lab pod. Returns a structured
    result the UI renders as a quality verdict."""
    res: Dict[str, Any] = {
        "file_found": False, "applied": False, "apply_reason": "",
        "vulnerable_before": None, "blocked_after": None,
        "test_passed": None, "test_output": "",
        "metrics": {}, "steps": [], "verdict": "", "quality": "inconclusive",
    }

    async def _exec_bound(bound_repo_id, *args, **kwargs):
        def check_identity():
            if expected_context is None:
                return
            from backend.report_context import require_runtime_binding
            if (expected_context.get("binding") or {}).get("repo_id") != bound_repo_id:
                raise ValueError("Verification repository differs from the recorded notebook context.")
            try:
                require_runtime_binding(expected_context, lab.get_lab_state(bound_repo_id) or {})
            except ValueError as exc:
                raise ValueError(
                    f"Verification stopped: {exc} No further commands or restore operations were sent. "
                    "If a patch was already applied, inspect its backup in the original lab before retrying."
                ) from exc
        check_identity()
        result = await lab.exec_in_lab(bound_repo_id, *args, **kwargs,
                                       **({"expected_context": expected_context} if expected_context is not None else {}))
        check_identity()
        return result

    def step(s: str):
        res["steps"].append(s)

    container = lab.get_lab_container(repo_id)
    res["container"] = container

    poc_wrapped = (': "${LAB_URL:=http://127.0.0.1:8080}"\n' + repro_poc) if repro_poc else ""

    # 1) Baseline PoC.
    if poc_wrapped:
        t0 = time.perf_counter()
        b = await _exec_bound(repo_id, poc_wrapped, timeout=60)
        res["metrics"]["poc_before_ms"] = int((time.perf_counter() - t0) * 1000)
        out_b = (b.get("stdout", "") + "\n" + b.get("stderr", ""))
        res["vulnerable_before"] = _looks_vulnerable(out_b)
        step(f"Baseline PoC: {'reproduced (vulnerable)' if res['vulnerable_before'] else 'did not reproduce'}")
    else:
        step("No PoC provided — cannot establish a baseline.")

    # 2) Locate the file.
    target = ""
    if file:
        loc = await _exec_bound(
            repo_id, f"find / -path '*{_safe_path(file)}' -not -path '*/.git/*' 2>/dev/null | head -1",
            timeout=30,
        )
        target = (loc.get("stdout") or "").strip().splitlines()[0].strip() if (loc.get("stdout") or "").strip() else ""
    res["file_found"] = bool(target)
    if target:
        step(f"Located file: {target}")

    # 3) Apply the patch (needs python3 in the pod for a safe multi-line literal replace).
    if target and before.strip():
        has_py = await _exec_bound(repo_id, "command -v python3 >/dev/null 2>&1 && echo yes || echo no")
        if "yes" in (has_py.get("stdout") or ""):
            apply_script = (
                f"echo {_b64(before)} | base64 -d > /tmp/lotus_before && "
                f"echo {_b64(after)} | base64 -d > /tmp/lotus_after && "
                "python3 - <<'PYEOF'\n"
                f"p = r'''{target}'''\n"
                "before = open('/tmp/lotus_before').read()\n"
                "after = open('/tmp/lotus_after').read()\n"
                "src = open(p).read()\n"
                "cand = [before, before.strip()]\n"
                "applied = False\n"
                "for c in cand:\n"
                "    if c and c in src:\n"
                "        open(p + '.lotusbak', 'w').write(src)\n"
                "        open(p, 'w').write(src.replace(c, after, 1))\n"
                "        applied = True\n"
                "        break\n"
                "print('APPLIED' if applied else 'NOMATCH')\n"
                "PYEOF"
            )
            ap = await _exec_bound(repo_id, apply_script, timeout=45)
            ap_out = (ap.get("stdout") or "")
            if "APPLIED" in ap_out:
                res["applied"] = True
                step("Patch applied in the pod (original backed up as <file>.lotusbak).")
            else:
                res["apply_reason"] = "the BEFORE snippet was not found verbatim in the file"
                step("Patch NOT applied: BEFORE snippet not present in the real file.")
        else:
            res["apply_reason"] = "python3 is not available in the lab pod to apply the patch"
            step("Patch NOT applied: python3 missing in pod.")
    elif not target:
        res["apply_reason"] = "the cited file was not found in the lab pod"
    else:
        res["apply_reason"] = "no BEFORE snippet to match"

    # 4) Re-run the PoC after applying.
    if res["applied"] and poc_wrapped:
        t0 = time.perf_counter()
        a = await _exec_bound(repo_id, poc_wrapped, timeout=60)
        res["metrics"]["poc_after_ms"] = int((time.perf_counter() - t0) * 1000)
        out_a = (a.get("stdout", "") + "\n" + a.get("stderr", ""))
        res["blocked_after"] = not _looks_vulnerable(out_a)
        step(f"Post-fix PoC: {'blocked (fixed)' if res['blocked_after'] else 'STILL reproduces (not fixed)'}")

    # 5) Best-effort regression test (python / ruby / go / cargo).
    if res["applied"] and test.strip():
        tl = (test_lang or "python").lower()
        t0 = time.perf_counter()
        tout = ""
        if tl in ("python", "py"):
            has_pytest = await _exec_bound(repo_id, "command -v pytest >/dev/null 2>&1 || python3 -c 'import pytest' 2>/dev/null && echo yes || echo no")
            if "yes" in (has_pytest.get("stdout") or ""):
                trun = await _exec_bound(
                    repo_id,
                    f"echo {_b64(test)} | base64 -d > /tmp/lotus_fix_test.py && "
                    "python3 -m pytest /tmp/lotus_fix_test.py -q 2>&1 | tail -20",
                    timeout=90,
                )
                tout = (trun.get("stdout", "") + trun.get("stderr", ""))
            else:
                step("Regression test skipped: pytest not available in the pod.")
        elif tl in ("ruby", "rb"):
            trun = await _exec_bound(
                repo_id,
                f"echo {_b64(test)} | base64 -d > /tmp/lotus_fix_test.rb && "
                "ruby /tmp/lotus_fix_test.rb 2>&1 | tail -20",
                timeout=90,
            )
            tout = (trun.get("stdout", "") + trun.get("stderr", ""))
        elif tl in ("go",):
            cmd = test if "go test" in test else "go test ./..."
            trun = await _exec_bound(repo_id, f"cd /app && {cmd} 2>&1 | tail -30", timeout=180)
            tout = (trun.get("stdout", "") + trun.get("stderr", ""))
        elif tl in ("rust", "cargo"):
            trun = await _exec_bound(
                repo_id,
                "cd /app && (cargo test --offline 2>/dev/null || cargo test) 2>&1 | tail -30",
                timeout=180,
            )
            tout = (trun.get("stdout", "") + trun.get("stderr", ""))
        else:
            step(f"Regression test skipped: unsupported test_lang={test_lang}")

        if tout:
            res["metrics"]["test_ms"] = int((time.perf_counter() - t0) * 1000)
            res["test_output"] = tout[-800:]
            low = tout.lower()
            if "passed" in low and "failed" not in low and "error" not in low:
                res["test_passed"] = True
            elif ("failed" in low) or ("error" in low):
                res["test_passed"] = None if ("errors" in low and "assert" not in low) else False
            else:
                res["test_passed"] = None
            step(f"Regression test: {res['test_passed']}")

    # 6) Restore original file unless the caller wants it left applied.
    if res["applied"] and target and not keep_applied:
        await _exec_bound(repo_id, f"[ -f '{target}.lotusbak' ] && mv '{target}.lotusbak' '{target}' || true")
        step("Restored the original file (verification is non-destructive).")

    # 7) Verdict / quality.
    if not res["file_found"] or not res["applied"]:
        res["quality"] = "inconclusive"
        res["verdict"] = (
            "Could not auto-apply this fix in the pod "
            + (f"({res['apply_reason']})" if res["apply_reason"] else "")
            + ". Apply the change manually, then re-run the PoC + test to verify."
        )
    elif res["vulnerable_before"] and res["blocked_after"]:
        res["quality"] = "pass"
        res["verdict"] = "Fix verified — the PoC reproduced BEFORE the patch and is BLOCKED after."
        if res["test_passed"] is True:
            res["verdict"] += " Regression test passed."
        elif res["test_passed"] is False:
            res["verdict"] += " (Regression test FAILED — review the test/patch.)"
    elif res["vulnerable_before"] and res["blocked_after"] is False:
        res["quality"] = "fail"
        res["verdict"] = "Patch applied but the PoC STILL reproduces — this fix does not remediate the issue."
    else:
        res["quality"] = "inconclusive"
        res["verdict"] = (
            "Patch applied, but the PoC did not reproduce a baseline in this pod "
            "(is the target service running and LAB_URL correct?). Cannot score remediation."
        )
    return res
