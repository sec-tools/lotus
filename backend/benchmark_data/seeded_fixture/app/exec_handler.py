"""Seeded benchmark fixture (INTENTIONALLY VULNERABLE — not shipped in production).

Each vulnerable sink is labeled in benchmark_data/ground_truth/seeded_fixture.json so the
quality benchmark can measure true/false positives deterministically.
"""
import os
import subprocess


def run_convert(user_input):
    # GT: SEED-CMD-1 — command injection (attacker-controlled arg into a shell string).
    os.system("convert " + user_input + " /tmp/out.png")


def render_expression(expr):
    # GT: SEED-EVAL-1 — code injection (eval of attacker-controlled expression).
    return eval(expr)


def list_dir_safe(name):
    # KNOWN-SAFE: argv list, shell=False, no metachar interpretation. The detectors should
    # NOT surface this as a command-injection lead.
    return subprocess.run(["ls", "-la", name], shell=False, check=False)
