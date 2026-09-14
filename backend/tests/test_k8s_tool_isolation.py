"""Required policy failures block tool/source admission; no cluster is contacted."""
import asyncio
from copy import deepcopy
from unittest.mock import AsyncMock

import pytest
from backend.tests.k8s_tool_fixtures import stub_tool_ownership

pytestmark = pytest.mark.usefixtures("stub_tool_ownership")

from backend import k8s_runtime as runtime


@pytest.fixture
def policies(monkeypatch):
    runtime._GOVERNED.clear()
    runtime._GOVERNED["done"] = False
    monkeypatch.setenv("LOTUS_K8S_GOVERNANCE", "off")
    applied = []
    stored = {}
    async def apply(manifest, **kwargs):
        applied.append(deepcopy(manifest))
        stored[manifest["metadata"]["name"]] = deepcopy(manifest)
        return "applied", 0
    async def read(kind, name="", **kwargs):
        return deepcopy(stored.get(name) or {}), 0, ""
    monkeypatch.setattr(runtime, "apply", apply)
    monkeypatch.setattr(runtime, "get_json", read)
    monkeypatch.setattr(runtime, "_node_allocatable", AsyncMock(side_effect=AssertionError("node discovery must be optional")))
    yield applied, stored, apply, read
    runtime._GOVERNED.clear()
    runtime._GOVERNED["done"] = False


@pytest.mark.parametrize("blocked", ["lotus-tool-default-deny", "lotus-tool-egress-web"])
def test_failed_required_apply_never_marks_governed_or_creates_source(monkeypatch, tmp_path, policies, blocked):
    applied, stored, apply, _ = policies
    async def deny(manifest, **kwargs):
        if manifest["metadata"]["name"] == blocked:
            return "authored RBAC denial", 1
        return await apply(manifest, **kwargs)
    monkeypatch.setattr(runtime, "apply", deny)
    with pytest.raises(runtime.KubernetesIsolationUnavailable, match="RBAC denial"):
        asyncio.run(runtime.ensure_source_pvc(81, tmp_path))
    assert runtime._GOVERNED["done"] is False
    assert all(item["kind"] == "NetworkPolicy" for item in applied)


@pytest.mark.parametrize("mismatch", ["read_error", "missing", "namespace", "selector", "extra_egress", "types"])
def test_readback_mismatch_blocks_direct_tool_job(monkeypatch, policies, mismatch):
    applied, _, _, read = policies
    async def changed(kind, name="", **kwargs):
        document, rc, text = await read(kind, name, **kwargs)
        if mismatch == "read_error": return {}, 1, "authored get denial"
        if mismatch == "missing": return {}, 0, ""
        if mismatch == "namespace": document["metadata"]["namespace"] = "other"
        if mismatch == "selector": document["spec"]["podSelector"] = {"matchLabels": {"role": "unrelated"}}
        if mismatch == "extra_egress": document["spec"]["egress"] = [{}]
        if mismatch == "types": document["spec"]["policyTypes"] = ["Ingress"]
        return document, rc, text
    monkeypatch.setattr(runtime, "get_json", changed)
    result = asyncio.run(runtime.run_to_completion(81, "fixture", "fixture.invalid/image", argv=["true"]))
    assert result[2] == -1 and "NetworkPolicy" in result[1]
    assert runtime._GOVERNED["done"] is False
    assert all(item["kind"] == "NetworkPolicy" for item in applied)


def test_policy_transport_exception_and_cancellation_do_not_admit_tools(monkeypatch, policies):
    applied, _, _, _ = policies
    monkeypatch.setattr(runtime, "get_json", AsyncMock(side_effect=OSError("authored API unavailable")))
    with pytest.raises(runtime.KubernetesIsolationUnavailable, match="authored API unavailable"):
        asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is False
    monkeypatch.setattr(runtime, "get_json", AsyncMock(side_effect=asyncio.CancelledError))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is False
    assert all(item["kind"] == "NetworkPolicy" for item in applied)


def test_success_cache_and_disabled_quota_never_skip_required_policy_recheck(monkeypatch, policies):
    applied, stored, apply, read = policies
    asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is True
    assert len(applied) == 2
    runtime._node_allocatable.assert_not_awaited()
    async def denied(manifest, **kwargs): return "authored policy removed and write denied", 1
    monkeypatch.setattr(runtime, "apply", denied)
    with pytest.raises(runtime.KubernetesIsolationUnavailable, match="write denied"):
        asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is False
    monkeypatch.setattr(runtime, "apply", apply)
    asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is True and len(applied) == 4


def test_node_permission_absence_keeps_static_pod_limits_and_optional_limitrange(monkeypatch, policies):
    applied, _, _, _ = policies
    monkeypatch.setenv("LOTUS_K8S_GOVERNANCE", "on")
    asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is True
    assert [item["kind"] for item in applied] == ["NetworkPolicy", "NetworkPolicy", "LimitRange"]
    assert applied[-1]["spec"]["limits"][0]["default"] == {"cpu": "2", "memory": "2Gi"}


def test_no_node_permission_still_applies_complete_operator_quota(monkeypatch, policies):
    applied, _, _, _ = policies
    monkeypatch.setenv("LOTUS_K8S_GOVERNANCE", "on")
    for key, value in {"REQUESTS_MEM": "13Gi", "LIMITS_MEM": "14Gi",
                       "REQUESTS_CPU": "3", "LIMITS_CPU": "8"}.items():
        monkeypatch.setenv("LOTUS_K8S_QUOTA_" + key, value)
    asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is True
    assert [item["kind"] for item in applied] == ["NetworkPolicy", "NetworkPolicy", "LimitRange", "ResourceQuota"]
    assert applied[-1]["spec"]["hard"]["requests.memory"] == "13Gi"
    assert "resources_scope" in runtime._GOVERNED


def test_optional_resource_failure_does_not_claim_resource_setup_complete(monkeypatch, policies, caplog):
    applied, _, apply, _ = policies
    monkeypatch.setenv("LOTUS_K8S_GOVERNANCE", "on")
    async def optional_denial(manifest, **kwargs):
        if manifest["kind"] != "NetworkPolicy": return "authored quota denial", 1
        return await apply(manifest, **kwargs)
    monkeypatch.setattr(runtime, "apply", optional_denial)
    asyncio.run(runtime.ensure_namespace_governance())
    assert runtime._GOVERNED["done"] is True
    assert "resources_scope" not in runtime._GOVERNED
    assert "authored quota denial" in caplog.text


@pytest.mark.parametrize("allow_egress", [False, True])
def test_every_tool_pod_matches_deny_policy_before_actual_job_apply(monkeypatch, policies, allow_egress):
    applied, _, _, _ = policies
    monkeypatch.setattr(runtime, "_wait_pod_phase_for_job", AsyncMock(return_value=("Succeeded", {"status": {
        "containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}})))
    monkeypatch.setattr(runtime, "_kubectl_logs", AsyncMock(return_value="authored result"))
    monkeypatch.setattr(runtime.k8s_lab, "_run", AsyncMock(return_value=("", 0)))
    result = asyncio.run(runtime.run_to_completion(81, "fixture", "fixture.invalid/image", argv=["true"], allow_egress=allow_egress))
    assert result == ("authored result", "", 0)
    assert [item["kind"] for item in applied] == ["NetworkPolicy", "NetworkPolicy", "Job"]
    labels = applied[-1]["spec"]["template"]["metadata"]["labels"]
    selector = applied[0]["spec"]["podSelector"]["matchLabels"]
    assert all(labels.get(key) == value for key, value in selector.items())
    web = applied[1]["spec"]["podSelector"]["matchLabels"]
    assert all(labels.get(key) == value for key, value in web.items()) is allow_egress
    limits = applied[-1]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]
    assert limits == {"cpu": "2", "memory": "4Gi"}
