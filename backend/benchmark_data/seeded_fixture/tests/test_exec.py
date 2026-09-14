"""Test file — sinks here are TEST-ONLY and must be suppressed by the tier-0 prefilter.
A finding landing here is a discovery false positive.
"""
import os


def test_run_convert_smoke():
    # KNOWN-SAFE (test path): os.system in a test must be filtered by tier-0.
    os.system("convert sample.png /tmp/out.png")
    assert True
