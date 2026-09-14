"""Read-only preview metadata for the exact selected local identity runtime.

Never forwards ports, sends HTTP, accepts a client URL or starts a lab. The
normal execution endpoint reattests these identities before any requests.
"""
from urllib.parse import urlsplit
from backend.deployment_inventory import digest


def runtime_hash(local):
    return digest({key: local.get(key) for key in (
        "provider", "repo_id", "scan_job_id", "target_tree_hash", "target_revision", "url",
        "container_id", "image_digest", "network_id", "lab_run_id", "pod_uid", "namespace",
        "namespace_uid", "service_name", "service_uid", "port", "pods", "transport_binding")})


def public_runtime(local):
    # URL is the already selected Service endpoint, never a browser forwarding
    # URL or a newly accepted destination. Render as text, not a traffic link.
    if local.get("provider") not in {"k8s-job", "k8s-service"} or not local.get("identity_bound"):
        raise ValueError("Local runtime lacks an attested destination transport")
    url = local.get("url", "")
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("Bound local runtime URL is unavailable")
    return {"ready": True, "url": url, "provider": local["provider"],
            "runtime_hash": runtime_hash(local), "reason": "The selected audit runtime is ready for its reviewed GET requests",
            "source_binding": local.get("source_binding", "Selected audit lab runtime"),
            "browser_url": False, "revision_verified": False, "findings_created": 0}


async def resolve_preview(repo, job, binding):
    from backend import deployments_api as api
    if binding:
        from backend.deployment_local import attest
        current = await attest(binding["namespace"], binding["service_name"], binding["port"], api.build_static_signature(repo, job))
        if digest(current) != digest(binding):
            raise ValueError("Owned local runtime changed; bind this audit runtime again")
        local = {**current, "identity_bound": True, "url": "http://"+current["service_name"]+"."+current["namespace"]+".svc.cluster.local:"+str(current["port"])}
        return local, public_runtime(local)
    local, reason = await api._bound_local_lab(repo, job)
    if not local:
        return None, {"ready": False, "url": None, "runtime_hash": None,
                      "reason": reason or "No running local lab is bound to this audit", "findings_created": 0}
    return local, public_runtime(local)
