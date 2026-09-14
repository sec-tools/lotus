"""Vendored third-party code — must be suppressed by the tier-0 prefilter (vendor path).
A finding here is a discovery false positive (out of the audited trust scope).
"""


def unsafe_calc(payload):
    # KNOWN-SAFE (vendor path): eval in vendored code must be filtered by tier-0.
    return eval(payload)
