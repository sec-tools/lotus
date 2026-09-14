"""Measure actual NetworkPolicy allow/deny behavior in owned temporary namespaces.

The test uses only authored HTTP servers and TCP/UDP connectivity checks. It does
not contact public targets or invoke any vulnerability payload. Its clients are
tokenless nonroot pods with no host mounts, no capabilities and a read-only root.
An existing namespace is never reused. Explicit --keep retains owned resources
for inspection; otherwise only the namespaces created by this invocation go away.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time
import yaml

OWNER = {"app.kubernetes.io/managed-by": "lotus", "lotus.io/purpose": "network-policy-verification"}
PYTHON_IMAGE = "python:3.12-alpine"


def pod(name, labels, port, image):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {**OWNER, **labels}},
            "spec": {"automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "http", "image": image, "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-m", "http.server", str(port)], "workingDir": "/tmp",
                                     "ports": [{"containerPort": port}],
                                     "readinessProbe": {"httpGet": {"path": "/", "port": port}, "periodSeconds": 2},
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "20m", "memory": "32Mi"},
                                                   "limits": {"cpu": "100m", "memory": "96Mi"}},
                                     "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}]}],
                     "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}}]}}


def service(name, labels, port):
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
            "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]}}


def cleanup_namespaces(created, kubectl, *, timeout=45, monotonic=time.monotonic, sleep=time.sleep):
    """Delete only original owned namespace UIDs and verify their disappearance.

    A delete acknowledgement is not completion. Every failure retains the
    original identity and any observed replacement identity for inspection.
    """
    result = {"cleanup_verified": True, "removed_namespaces": [],
              "retained_namespaces": [], "cleanup_errors": []}
    for identity in created:
        row = dict(identity)
        deadline = monotonic() + timeout
        deleted = False
        try:
            while True:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise RuntimeError("namespace disappearance timed out")
                current = kubectl("get", "namespace", row["name"], "--ignore-not-found", "-o", "json",
                                  check=False, timeout=min(10, remaining))
                if current.returncode:
                    raise RuntimeError("namespace read failed; original identity retained")
                if not current.stdout.strip():
                    result["removed_namespaces"].append(dict(identity))
                    break
                metadata = json.loads(current.stdout)["metadata"]
                row["observed_uid"] = metadata["uid"]
                if not row.get("uid"):
                    raise RuntimeError("namespace creation identity was not received; observed namespace preserved")
                if metadata["uid"] != row["uid"]:
                    raise RuntimeError("same-name replacement preserved")
                if not all(metadata.get("labels", {}).get(k) == v for k, v in OWNER.items()):
                    raise RuntimeError("namespace ownership labels changed; namespace preserved")
                if not deleted:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise RuntimeError("namespace deletion deadline elapsed")
                    removed = kubectl("delete", "--raw=/api/v1/namespaces/" + row["name"], "-f", "-",
                        data=json.dumps({"apiVersion": "v1", "kind": "DeleteOptions",
                                         "preconditions": {"uid": row["uid"]}, "propagationPolicy": "Foreground"}),
                        check=False, timeout=min(10, remaining))
                    if removed.returncode:
                        raise RuntimeError("UID-bound namespace deletion failed")
                    deleted = True
                sleep(min(.25, max(0, deadline - monotonic())))
        except Exception as error:
            row["delete_submitted"] = deleted
            row["cleanup_error"] = str(error)[:400] or type(error).__name__
            result["retained_namespaces"].append(row)
            result["cleanup_errors"].append(row["name"] + ": " + row["cleanup_error"])
            result["cleanup_verified"] = False
    return result


def finalize_cleanup(output, created, *, keep, kubectl, save, cleanup=cleanup_namespaces):
    """Persist a final truthful outcome even if traffic passed before cleanup."""
    traffic_passed = output.get("status") == "passed"
    output["traffic_passed"] = traffic_passed
    if keep:
        output.update(cleanup_verified=False, cleanup_mode="retained-by-request",
                      retained_namespaces=[dict(row) for row in created])
    else:
        output.update(status="checking-cleanup" if traffic_passed else "failed", cleanup_mode="verified-removal")
        save()
        output.update(cleanup(created, kubectl))
        output["status"] = "passed" if traffic_passed and output["cleanup_verified"] else "failed"
    output["finished_at"] = datetime.now(timezone.utc).isoformat()
    save()
    if traffic_passed and not keep and not output["cleanup_verified"]:
        raise RuntimeError("Network traffic passed, but owned namespace cleanup remains incomplete; inspect the retained identities")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--image", default=PYTHON_IMAGE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--prove-controller-regression", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"lotus-netpol-[a-z0-9][a-z0-9-]{0,35}[a-z0-9]", args.namespace):
        parser.error("Use a new namespace beginning lotus-netpol- (at most 50 characters)")
    if "@sha256:" not in args.image:
        parser.error("--image must be an immutable Python image @sha256 digest")
    base = ["kubectl", "--kubeconfig", str(Path(args.kubeconfig).resolve()), "--context", args.context]
    output = {"started_at": datetime.now(timezone.utc).isoformat(), "context": args.context,
              "namespaces": [args.namespace, args.namespace + "-sink"], "image": args.image,
              "kind": "actual-pod-networkpolicy-conformance", "checks": [], "status": "running"}
    created = []

    def kubectl(*command, data=None, check=True, timeout=65):
        return subprocess.run([*base, *command], input=data, capture_output=True, text=True, timeout=timeout, check=check)

    def apply(objects, namespace=None):
        flags = ["-n", namespace] if namespace else []
        return kubectl(*flags, "apply", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2) + "\n")

    def check(name, observed, expected):
        passed = observed == expected
        output["checks"].append({"name": name, "expected": expected, "observed": observed, "passed": passed})
        save()
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise AssertionError(name + ": " + repr(observed))

    def probe(client, host, port, protocol="tcp"):
        # DNS query is only for the in-cluster kubernetes.default.svc name.
        code = """import socket,json
host,port,protocol = HOST,PORT,PROTOCOL
try:
 if protocol == 'udp':
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
  query=b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'+b'\\x0akubernetes\\x07default\\x03svc\\x07cluster\\x05local\\x00\\x00\\x01\\x00\\x01'
  s.sendto(query,(host,port));response=s.recv(512);reachable=response[:2]==b'\\x12\\x34';s.close()
 else:
  s=socket.create_connection((host,port),timeout=2);s.close();reachable=True
 print(json.dumps({'reachable':reachable}))
except (TimeoutError,OSError) as error:print(json.dumps({'reachable':False,'reason':type(error).__name__}))
""".replace("HOST", repr(host)).replace("PORT", str(port)).replace("PROTOCOL", repr(protocol))
        return json.loads(kubectl("-n", args.namespace, "exec", client, "--", "python", "-c", code).stdout)["reachable"]

    try:
        for namespace in output["namespaces"]:
            existing = kubectl("get", "namespace", namespace, "--ignore-not-found", "-o", "json")
            if existing.stdout.strip():
                raise RuntimeError("Refusing existing namespace: " + namespace)
            # An uncertain create response is evidence to inspect, never a
            # license to delete whichever same-name object is now present.
            created.append({"name": namespace, "uid": None})
            output["creation_intents"] = [dict(row) for row in created]
            save()
            result = kubectl("create", "-f", "-", "-o", "json", data=json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
                "labels": {**OWNER, "pod-security.kubernetes.io/enforce": "restricted"}}}))
            uid = json.loads(result.stdout)["metadata"]["uid"]
            if not isinstance(uid, str) or not uid:
                raise RuntimeError("Namespace create returned no immutable identity")
            created[-1]["uid"] = uid
            output["creation_intents"] = [dict(row) for row in created]
            save()
        ns, sink_ns = output["namespaces"]
        apply([pod("controller", {"app": "lotus"}, 8000, args.image), pod("lab", {"role": "lab-container", "test": "lab"}, 8080, args.image),
               pod("second-lab", {"role": "lab-container", "test": "second-lab"}, 8080, args.image),
               pod("observer", {"test": "observer"}, 8080, args.image), service("lab", {"test": "lab"}, 8080)], ns)
        apply([pod("sink", {"test": "sink"}, 8080, args.image), service("sink", {"test": "sink"}, 8080)], sink_ns)
        for namespace in output["namespaces"]:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                result = kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod", "--all", "--timeout=10s", check=False)
                if result.returncode == 0:
                    break
            else:
                raise RuntimeError("Probe pods did not become Ready: " + namespace + " " + result.stderr)
        pods = json.loads(kubectl("-n", ns, "get", "pods", "-o", "json").stdout)["items"]
        ips = {row["metadata"]["name"]: row["status"]["podIP"] for row in pods}
        sink_ip = json.loads(kubectl("-n", sink_ns, "get", "pod", "sink", "-o", "json").stdout)["status"]["podIP"]
        sink_service = json.loads(kubectl("-n", sink_ns, "get", "service", "sink", "-o", "json").stdout)["spec"]["clusterIP"]
        lab_service = json.loads(kubectl("-n", ns, "get", "service", "lab", "-o", "json").stdout)["spec"]["clusterIP"]
        api_ip = json.loads(kubectl("-n", "default", "get", "service", "kubernetes", "-o", "json").stdout)["spec"]["clusterIP"]
        dns_ip = json.loads(kubectl("-n", "kube-system", "get", "service", "kube-dns", "-o", "json").stdout)["spec"]["clusterIP"]
        check("positive control reaches sink Pod before policy", probe("observer", sink_ip, 8080), True)
        check("positive control reaches sink Service before policy", probe("observer", sink_service, 8080), True)
        check("positive control reaches Kubernetes API", probe("observer", api_ip, 443), True)
        check("positive control receives DNS response", probe("observer", dns_ip, 53, "udp"), True)
        policies = list(yaml.safe_load_all(Path(__file__).parents[1].joinpath("networkpolicy.yaml").read_text()))
        for policy in policies:
            policy["metadata"]["namespace"] = ns
        if args.prove_controller_regression:
            previous = json.loads(json.dumps(policies))
            previous[0]["spec"]["egress"] = [rule for rule in previous[0]["spec"]["egress"] if not any(peer.get("podSelector", {}).get("matchLabels", {}).get("role") == "lab-container" for peer in rule.get("to", []))]
            apply(previous, ns)
            time.sleep(3)
            check("previous policy blocks required controller-to-lab port 8080", probe("controller", lab_service, 8080), False)
        apply(policies, ns)
        time.sleep(3)
        for name, client, ip, port, expected in [
            ("controller reaches lab Pod on application port", "controller", ips["lab"], 8080, True),
            ("controller reaches lab Service on application port", "controller", lab_service, 8080, True),
            ("controller reaches Kubernetes API", "controller", api_ip, 443, True),
            ("controller cannot reach unrelated sink on port 8080", "controller", sink_ip, 8080, False),
            ("lab cannot reach sink Pod", "lab", sink_ip, 8080, False),
            ("lab cannot reach sink Service", "lab", sink_service, 8080, False),
            ("lab cannot reach sibling lab", "lab", ips["second-lab"], 8080, False),
            ("lab cannot reach Kubernetes API", "lab", api_ip, 443, False),
            ("unlabelled observer cannot enter lab", "observer", ips["lab"], 8080, False),
            ("positive control sink still reachable after denials", "observer", sink_ip, 8080, True)]:
            check(name, probe(client, ip, port), expected)
        check("lab cannot send DNS queries", probe("lab", dns_ip, 53, "udp"), False)
        for row in pods:
            spec = row["spec"]
            check(row["metadata"]["name"] + " pod has no host namespaces/mounts or SA token", bool(spec.get("automountServiceAccountToken") is False and not any(spec.get(key) for key in ["hostNetwork", "hostPID", "hostIPC"]) and not any("hostPath" in volume or "projected" in volume for volume in spec.get("volumes", []))), True)
        code = "import os,json,pathlib; status=pathlib.Path('/proc/self/status').read_text(); print(json.dumps({'uid':os.getuid(),'token':pathlib.Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists(),'capabilities_empty':'CapEff:\\t0000000000000000' in status,'no_new_privs':'NoNewPrivs:\\t1' in status,'seccomp_filter':'Seccomp:\\t2' in status}))"
        runtime = json.loads(kubectl("-n", ns, "exec", "lab", "--", "python", "-c", code).stdout)
        check("actual worker process is nonroot, tokenless, capability-free and seccomp confined", runtime, {"uid": 1000, "token": False, "capabilities_empty": True, "no_new_privs": True, "seccomp_filter": True})
        output["pod_identities"] = [{"name": row["metadata"]["name"], "uid": row["metadata"]["uid"], "node": row["spec"]["nodeName"], "image_id": row["status"]["containerStatuses"][0]["imageID"]} for row in pods]
        output["status"] = "passed"
    except Exception as error:
        output["status"] = "failed"
        output["error"] = str(error)
        raise
    finally:
        finalize_cleanup(output, created, keep=args.keep, kubectl=kubectl, save=save)


if __name__ == "__main__":
    main()
