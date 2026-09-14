"""Scoped lifecycle stubs for waiter/log/policy unit tests.

The real UID reconciliation, failure, cancellation and absence protocol is
exercised independently in test_k8s_tool_lifecycle; these fixtures never issue CLI.
"""
import copy
from unittest.mock import AsyncMock
import pytest
from backend import k8s_runtime, k8s_network_guard


def install_authored_network_admission(monkeypatch):
    """Opt-in seam for tests of unrelated lifecycle; real admission has its own tests."""
    class Guard:
        owner = "authored-network-owner"
        released = False
        def __init__(self, manifest): self.manifest = copy.deepcopy(manifest)
        async def release(self):
            self.released = True
            return {"status": "verified", "pod_uid": "authored-pod-uid", "workload_uid": "authored-job-uid"}
        async def close(self): pass
    async def prepare(manifest, **kwargs): return Guard(manifest)
    monkeypatch.setattr(k8s_network_guard, "prepare", prepare)
    monkeypatch.setattr(k8s_network_guard, "registry_binding", AsyncMock(return_value={"ip": "10.1.2.3"}))
    return Guard



@pytest.fixture
def stub_tool_ownership(monkeypatch):
    install_authored_network_admission(monkeypatch)
    async def read(manifest, ownership):
        document=copy.deepcopy(manifest)
        document['metadata']['uid']='authored-job-uid'
        ownership['uid']='authored-job-uid'
        return document
    monkeypatch.setattr(k8s_runtime,'_read_owned_tool_job',read)
    monkeypatch.setattr(k8s_runtime,'_remember_owned_tool_pod',lambda *_:None)
    monkeypatch.setattr(k8s_runtime,'_cleanup_tool_job',AsyncMock(return_value=None))
