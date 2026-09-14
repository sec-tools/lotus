"""Successful bounded analysis with an explicitly incomplete source scope."""
from copy import deepcopy


class PartialAnalysis(list):
    """Keep useful observations without treating a configured limit as a crash.

    Only controller adapters construct this result. It does not establish full
    tool coverage or authorize a finding; its scope remains report evidence.
    """
    def __init__(self, leads, *, reason, scope, configure_setting=None):
        if not isinstance(leads, list) or any(not isinstance(row, dict) for row in leads):
            raise ValueError("Partial analysis requires a concrete list of observations")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Partial analysis requires a scope explanation")
        if not isinstance(scope, dict) or scope.get("complete") is not False or not scope.get("coverage_gaps"):
            raise ValueError("Partial analysis requires explicit incomplete coverage")
        super().__init__(leads)
        self.reason = reason
        self.scope = deepcopy(scope)
        self.configure_setting = configure_setting
