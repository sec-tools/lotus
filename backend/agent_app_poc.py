"""Local-lab PoCs for Ruby-agent / unauth-mail / SSR / AI-proxy / ACME-hook / Django-authz leads.

Nothing is CONFIRMED until an oracle matches (uid=, LOTUS_MAIL_UNAUTH,
LOTUS_PUPPET_AUTH, LOTUS_SSRF, LOTUS_AI_UNAUTH, LOTUS_IDENTITY_SPOOF,
LOTUS_IDOR, PUPPET_YAML_RCE, ROR_EXECJS, CERTBOT_HOOK) with before/after
measurements. Failures are recorded as DISPROVE.

Does not compile Puppet/Zulip/Certbot. Starts an in-process stdlib analog so
every audit can generate and run PoCs without extra pip/apt. Generated scripts
land in ``<repo>/.lotus/pocs/``. Analog is only claimed as proof when Phase-1
found matching leads in ``dest``.
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

from backend.analyzers.agent_app_plane import collect_agent_app_plane


def _ensure_pocs(dest: Path) -> Path:
    d = Path(dest) / ".lotus" / "pocs"
    d.mkdir(parents=True, exist_ok=True)
    readme = d / "README.md"
    if not readme.exists():
        readme.write_text(
            "Lotus-generated agent/app lab PoCs.\n"
            "Oracles: uid=, LOTUS_MAIL_UNAUTH, LOTUS_PUPPET_AUTH, LOTUS_SSRF, "
            "LOTUS_AI_UNAUTH, LOTUS_IDENTITY_SPOOF, LOTUS_IDOR, "
            "PUPPET_YAML_RCE, ROR_EXECJS, CERTBOT_HOOK.\n"
            "Export LOTUS_AGENT_APP_LAB_URL then run poc_*.py.\n",
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


class _AgentAppAnalog(BaseHTTPRequestHandler):
    """Puppet YAML/exec, Mailcatcher unauth UI, ExecJS SSR, Headroom SSRF,
    Certbot hooks, Zulip IDOR analog.
    """

    def log_message(self, *args: Any) -> None:  # noqa: ARG002
        return

    def _send(self, code: int, body: str, ctype: str = "text/plain") -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _cfg(self) -> Dict[str, Any]:
        return _ANALOG_CFG.get(self.server.server_address[1], {})

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        cfg = self._cfg()
        enforce = bool(cfg.get("enforce"))
        token = str(cfg.get("token") or "")
        if path in ("/health", "/"):
            self._send(200, "ok")
            return
        if path.rstrip("/") == "/messages":
            if enforce:
                self._send(401, "mailbox requires auth")
                return
            self._send(
                200,
                json.dumps({
                    "marker": "LOTUS_MAIL_UNAUTH",
                    "messages": [{"from": "root@lab", "subject": "secret"}],
                }),
                "application/json",
            )
            return
        if path.startswith("/messages/"):
            owner = "alice"
            caller = self.headers.get("X-User") or ""
            if enforce and caller != owner:
                self._send(403, "has_message_access denied")
                return
            self._send(
                200,
                json.dumps({
                    "marker": "LOTUS_IDOR",
                    "id": path.rsplit("/", 1)[-1],
                    "owner": owner,
                    "body": "private stream message",
                }),
                "application/json",
            )
            return
        if path.rstrip("/") == "/puppet/v3/catalog":
            if enforce:
                self._send(403, "auth.conf deny")
                return
            self._send(
                200,
                json.dumps({"marker": "LOTUS_PUPPET_AUTH", "allow": "*"}),
                "application/json",
            )
            return
        if path.rstrip("/") in ("/v1/complete", "/v1/messages", "/v1/complete"):
            hdr_url = self.headers.get("X-Headroom-Base-Url") or ""
            hdr_user = self.headers.get("X-Headroom-User-Id") or ""
            auth = self.headers.get("Authorization") or self.headers.get("X-Proxy-Token") or ""
            if enforce and token and auth != token:
                self._send(401, "proxy token required")
                return
            if "169.254.169.254" in hdr_url or "metadata" in hdr_url:
                if enforce:
                    self._send(403, "upstream blocked")
                    return
                self._send(
                    200,
                    json.dumps({
                        "marker": "LOTUS_SSRF",
                        "ami-id": "ami-0lotus",
                        "upstream": hdr_url,
                    }),
                    "application/json",
                )
                return
            if hdr_user.lower() in ("admin", "root", "0") and not enforce:
                self._send(
                    200,
                    json.dumps({
                        "marker": "LOTUS_IDENTITY_SPOOF",
                        "user": hdr_user,
                        "privileged": 1,
                    }),
                    "application/json",
                )
                return
            if not enforce and not token:
                self._send(
                    200,
                    json.dumps({"marker": "LOTUS_AI_UNAUTH", "model": "lab"}),
                    "application/json",
                )
                return
            self._send(200, json.dumps({"ok": True, "user": hdr_user or "anon"}))
            return
        if path.rstrip("/") == "/preview":
            url = (q.get("url") or [""])[0]
            if enforce and ("169.254" in url or url.startswith("file:")):
                self._send(403, "link preview blocked")
                return
            if "169.254" in url:
                self._send(200, json.dumps({"marker": "LOTUS_SSRF", "embed": "ami-0lotus"}))
                return
            self._send(200, json.dumps({"embed": "ok"}))
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
                    blob.get("catalog") or blob.get("script") or blob.get("cmd")
                    or blob.get("hook") or blob.get("payload") or raw
                )
                if isinstance(payload, list):
                    payload = payload[0] if payload else ""
        except Exception:
            pass
        if path.rstrip("/") in ("/catalog", "/deser"):
            if any(k in payload for k in ("!!ruby", "!!python", "json_class", "uid=", "id")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"PUPPET_YAML_RCE {out}")
            else:
                self._send(200, "ok")
            return
        if path.rstrip("/") == "/exec":
            if any(k in payload for k in (";", "`", "$(", "id", "uid=")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"PUPPET_EXEC_RCE {out}")
            else:
                self._send(200, "ok")
            return
        if path.rstrip("/") == "/ssr":
            if any(k in payload for k in ("child_process", "exec", "id", "uid=")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"ROR_EXECJS {out}")
            else:
                self._send(200, "ok")
            return
        if path.rstrip("/") == "/hook":
            if any(k in payload for k in ("id", "uid=", ";", "os.system")):
                out = subprocess.check_output(["id"], text=True)
                self._send(200, f"CERTBOT_HOOK {out}")
            else:
                self._send(200, "ok")
            return
        self._send(404, "no")


def start_analog(
    *,
    enforce: bool = False,
    token: str = "",
    port: Optional[int] = None,
) -> Tuple[ThreadingHTTPServer, int, str]:
    port = port or _free_port()
    _ANALOG_CFG[port] = {"enforce": enforce, "token": token}
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _AgentAppAnalog)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return httpd, port, f"http://127.0.0.1:{port}"


def _write_poc_scripts(pocs: Path, base: str) -> None:
    scripts = {
        "poc_mail_unauth.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
r = urllib.request.urlopen(base + "/messages")
body = r.read().decode()
print("status", r.status, body)
assert "LOTUS_MAIL_UNAUTH" in body, body
print("PROVEN mail_ui_unauth")
''',
        "poc_puppet_auth.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
r = urllib.request.urlopen(base + "/puppet/v3/catalog")
body = r.read().decode()
print(body)
assert "LOTUS_PUPPET_AUTH" in body, body
print("PROVEN puppet_auth_star")
''',
        "poc_puppet_yaml.py": f'''#!/usr/bin/env python3
import os, json, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/catalog",
    data=json.dumps({{"catalog": "!!ruby/object:ERB"}}).encode(),
    method="POST",
)
req.add_header("Content-Type", "application/json")
body = urllib.request.urlopen(req).read().decode()
print(body)
assert "uid=" in body and "PUPPET_YAML_RCE" in body, body
print("PROVEN puppet_yaml_deser")
''',
        "poc_ror_execjs.py": f'''#!/usr/bin/env python3
import os, json, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/ssr",
    data=json.dumps({{"script": "require('child_process').execSync('id')"}}).encode(),
    method="POST",
)
req.add_header("Content-Type", "application/json")
body = urllib.request.urlopen(req).read().decode()
print(body)
assert "uid=" in body and "ROR_EXECJS" in body, body
print("PROVEN ror_execjs_rce")
''',
        "poc_ai_ssrf.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/v1/complete",
    headers={{"X-Headroom-Base-Url": "http://169.254.169.254/latest/meta-data/"}},
)
r = urllib.request.urlopen(req)
body = r.read().decode()
print(body)
assert "LOTUS_SSRF" in body, body
print("PROVEN ai_proxy_header")
''',
        "poc_certbot_hook.py": f'''#!/usr/bin/env python3
import os, json, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
req = urllib.request.Request(
    base + "/hook",
    data=json.dumps({{"hook": "id"}}).encode(),
    method="POST",
)
req.add_header("Content-Type", "application/json")
body = urllib.request.urlopen(req).read().decode()
print(body)
assert "uid=" in body and "CERTBOT_HOOK" in body, body
print("PROVEN certbot_hook_rce")
''',
        "poc_zulip_idor.py": f'''#!/usr/bin/env python3
import os, urllib.request
base = os.environ.get("LOTUS_AGENT_APP_LAB_URL", "{base}")
req = urllib.request.Request(base + "/messages/42", headers={{"X-User": "mallory"}})
r = urllib.request.urlopen(req)
body = r.read().decode()
print(body)
assert "LOTUS_IDOR" in body, body
print("PROVEN zulip_idor_skip")
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
        "puppet_yaml_deser": "deser",
        "puppet_pson_deser": "deser",
        "puppet_marshal_deser": "deser",
        "certbot_yaml_deser": "deser",
        "django_pickle": "deser",
        "ai_tar_slip": "deser",
        "puppet_exec_rce": "exec",
        "puppet_eval_rce": "exec",
        "puppet_pluginsync": "exec",
        "ror_execjs_rce": "ssr",
        "ror_open3_node": "ssr",
        "ror_system_node": "ssr",
        "ror_prerender": "ssr",
        "certbot_hook_rce": "hook",
        "certbot_subprocess": "hook",
        "certbot_os_system": "hook",
        "zulip_thumb_rce": "hook",
        "certbot_chmod_777": "hook",
        "puppet_auth_star": "auth_star",
        "mail_ui_unauth": "mail",
        "mail_ui_unauth": "mail",
        "ruby_bind_all": "mail",
        "sinatra_unauth": "mail",
        "ai_proxy_token_optional": "ai_auth",
        "ai_tls_off": "ai_auth",
        "django_csrf_exempt": "idor",
        "zulip_idor_skip": "idor",
        "zulip_idor_skip": "idor",
        "ai_proxy_header": "ssrf",
        "ai_ssrf_metadata": "ssrf",
        "zulip_link_ssrf": "ssrf",
    }.get(hint)


# Per-hint analog-PoC attribution. Titles describe the ACTUAL fired lead so an analog
# demonstration is never mislabeled with another product's brand. A brand name only
# appears when that brand's own (product-specific) rule fired. Keyed by phase2_hint.
_HINT_POC_META: Dict[str, Tuple[str, float, str]] = {
    # deser bucket
    "puppet_yaml_deser": ("Puppet YAML/PSON catalog deserialization analog RCE", 9.1, "deserialization"),
    "puppet_pson_deser": ("Puppet PSON catalog deserialization analog RCE", 9.1, "deserialization"),
    "puppet_marshal_deser": ("Puppet Marshal deserialization analog RCE", 9.1, "deserialization"),
    "certbot_yaml_deser": ("Unsafe yaml.load object-deserialization analog RCE", 9.0, "deserialization"),
    "django_pickle": ("pickle/unsafe-yaml deserialization analog RCE", 9.0, "deserialization"),
    "ai_tar_slip": ("tarfile.extractall path-traversal analog", 7.9, "deserialization"),
    # exec bucket
    "puppet_exec_rce": ("Execution.execute interpolation analog RCE", 9.0, "rce"),
    "puppet_eval_rce": ("eval() of interpolated input analog RCE", 9.0, "rce"),
    "puppet_pluginsync": ("pluginsync code-load analog RCE", 9.0, "rce"),
    # ssr bucket
    "ror_execjs_rce": ("ReactOnRails ExecJS prerender analog RCE", 9.0, "rce"),
    "ror_open3_node": ("Open3 node/webpack spawn analog RCE", 8.7, "rce"),
    "ror_system_node": ("Kernel.system webpack analog RCE", 8.5, "rce"),
    "ror_prerender": ("ReactOnRails prerender analog RCE", 7.6, "rce"),
    # hook bucket
    "certbot_hook_rce": ("Privileged deploy/renew-hook analog RCE", 8.9, "rce"),
    "certbot_subprocess": ("apache/nginx/certbot subprocess analog RCE", 8.6, "rce"),
    "certbot_os_system": ("os.system in privileged CLI analog RCE", 9.0, "rce"),
    "zulip_thumb_rce": ("thumbnail/ffmpeg subprocess analog RCE", 8.4, "rce"),
    "certbot_chmod_777": ("world-writable cert/challenge path analog", 7.5, "logic"),
    # auth_star bucket
    "puppet_auth_star": ("Puppet auth.conf allow * unauthenticated catalog", 8.6, "authz_bypass"),
    # mail bucket
    "mail_ui_unauth": ("Unauthenticated catch-all mailbox UI (Mailcatcher-class)", 7.8, "authz_bypass"),
    "sinatra_unauth": ("Unauthenticated Sinatra UI analog", 7.8, "authz_bypass"),
    "ruby_bind_all": ("Service bound to all interfaces analog", 7.5, "authz_bypass"),
    # ai_auth bucket
    "ai_proxy_token_optional": ("AI-proxy optional-token fail-open (Headroom-class)", 8.3, "authz_bypass"),
    "ai_tls_off": ("Upstream TLS verification disabled analog", 8.0, "authz_bypass"),
    # idor bucket
    "zulip_idor_skip": ("Django/Zulip object fetch skips has_message_access", 8.2, "authz_bypass"),
    "django_csrf_exempt": ("csrf_exempt mutating view analog", 7.8, "authz_bypass"),
    # ssrf bucket
    "ai_proxy_header": ("AI-proxy caller-supplied upstream SSRF (Headroom-class)", 8.8, "ssrf"),
    "ai_ssrf_metadata": ("Cloud-metadata upstream SSRF analog", 8.5, "ssrf"),
    "zulip_link_ssrf": ("Link-preview / embed-fetch SSRF analog", 8.1, "ssrf"),
}

# Generic (brand-free) fallback per bucket, used when a bucket fired but no specific
# hint meta is known. Never asserts a product name.
_BUCKET_DEFAULT: Dict[str, Tuple[str, str, float, str]] = {
    "deser": ("deser_analog", "Object-deserialization analog RCE", 9.0, "deserialization"),
    "exec": ("exec_analog", "Command-execution interpolation analog RCE", 9.0, "rce"),
    "ssr": ("ssr_analog", "Server-side JS execution analog RCE", 9.0, "rce"),
    "hook": ("hook_analog", "Privileged hook/subprocess analog RCE", 8.9, "rce"),
    "auth_star": ("auth_star_analog", "Unauthenticated privileged endpoint analog", 8.6, "authz_bypass"),
    "mail": ("mail_analog", "Unauthenticated UI analog", 7.8, "authz_bypass"),
    "ai_auth": ("ai_auth_analog", "Proxy auth fail-open analog", 8.3, "authz_bypass"),
    "idor": ("idor_analog", "Object-level authorization gap analog", 8.2, "authz_bypass"),
    "ssrf": ("ssrf_analog", "Server-side request forgery analog", 8.1, "ssrf"),
}


def _pick(leads: List[dict], bucket: str) -> Tuple[str, str, float, str]:
    """Return (id, title, cvss, canonical_class) for the analog PoC in ``bucket``,
    derived from the highest-CVSS lead whose hint actually fired in that bucket.
    Guarantees a brand name only surfaces when that brand's own rule fired.
    """
    fired = [
        str(f.get("phase2_hint") or "")
        for f in leads
        if _bucket(str(f.get("phase2_hint") or "")) == bucket
    ]
    best_hint = None
    best_cvss = -1.0
    for h in fired:
        meta = _HINT_POC_META.get(h)
        if meta and meta[1] > best_cvss:
            best_hint, best_cvss = h, meta[1]
    if best_hint is not None:
        title, cvss, klass = _HINT_POC_META[best_hint]
        return best_hint, title, cvss, klass
    return _BUCKET_DEFAULT.get(bucket, (f"{bucket}_analog", f"{bucket} analog PoC", 8.0, "logic"))


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
        # Agent/application checks use an in-process stdlib analog.  They are
        # discovery/regression evidence only and are never target-bound proof.
        "evidence_scope": "analog",
        "target_bound": False,
        "proof_authority": "unattested-analog",
        "analog_source": "test_projects/agent_app_lab/app.py",
    }


def run_agent_app_pocs(dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    leads, trace = collect_agent_app_plane(dest, "")
    pocs_dir = _ensure_pocs(dest)
    results: List[dict] = []
    if not leads:
        payload = {
            "proven": [],
            "disproven": [],
            "all": [],
            "trace": trace,
            "note": "no agent-app-control-plane leads; analog not claimed as a finding",
        }
        try:
            (dest / ".lotus").mkdir(exist_ok=True)
            (dest / ".lotus" / "agent_app_poc_results.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8",
            )
        except Exception:
            pass
        return payload

    httpd_open, _, base = start_analog(enforce=False, token="")
    httpd_closed, _, base_c = start_analog(enforce=True, token="secret")
    try:
        _write_poc_scripts(pocs_dir, base)
        os.environ["LOTUS_AGENT_APP_LAB_URL"] = base
        buckets = {_bucket(str(f.get("phase2_hint") or "")) for f in leads} - {None}

        if "mail" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/messages")
            st_a, body_a = _http("GET", f"{base}/messages")
            ok = st_b in (401, 403) and st_a == 200 and "LOTUS_MAIL_UNAUTH" in body_a
            _pid, _title, _cvss, _klass = _pick(leads, "mail")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before status={st_b} body={body_b[:120]} | after status={st_a} body={body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_MAIL_UNAUTH" in body_a,
                },
            ))

        if "auth_star" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/puppet/v3/catalog")
            st_a, body_a = _http("GET", f"{base}/puppet/v3/catalog")
            ok = st_b in (401, 403) and st_a == 200 and "LOTUS_PUPPET_AUTH" in body_a
            _pid, _title, _cvss, _klass = _pick(leads, "auth_star")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_PUPPET_AUTH" in body_a,
                },
            ))

        if "deser" in buckets:
            st_b, body_b = _http("POST", f"{base}/catalog", data=b'{"catalog":"hello"}')
            st_a, body_a = _http("POST", f"{base}/catalog", data=b'{"catalog":"!!ruby/object id"}')
            ok = "uid=" in body_a and "PUPPET_YAML_RCE" in body_a and "uid=" not in body_b
            _pid, _title, _cvss, _klass = _pick(leads, "deser")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b,
                },
            ))

        if "exec" in buckets:
            st_b, body_b = _http("POST", f"{base}/exec", data=b'{"cmd":"true"}')
            st_a, body_a = _http("POST", f"{base}/exec", data=b'{"cmd":"id"}')
            ok = "uid=" in body_a and "uid=" not in body_b
            _pid, _title, _cvss, _klass = _pick(leads, "exec")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {"uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b, "status_after": st_a},
            ))

        if "ssr" in buckets:
            st_b, body_b = _http("POST", f"{base}/ssr", data=b'{"script":"1+1"}')
            st_a, body_a = _http(
                "POST", f"{base}/ssr",
                data=b'{"script":"require(\'child_process\').execSync(\'id\')"}',
            )
            ok = "uid=" in body_a and "ROR_EXECJS" in body_a and "uid=" not in body_b
            _pid, _title, _cvss, _klass = _pick(leads, "ssr")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b,
                },
            ))

        if "ssrf" in buckets:
            st_b, body_b = _http(
                "GET", f"{base_c}/v1/complete",
                headers={"X-Headroom-Base-Url": "http://169.254.169.254/latest/meta-data/"},
            )
            st_a, body_a = _http(
                "GET", f"{base}/v1/complete",
                headers={"X-Headroom-Base-Url": "http://169.254.169.254/latest/meta-data/"},
            )
            ok = st_b in (401, 403) and st_a == 200 and "LOTUS_SSRF" in body_a
            _pid, _title, _cvss, _klass = _pick(leads, "ssrf")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_SSRF" in body_a,
                },
            ))

        if "ai_auth" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/v1/complete")
            st_a, body_a = _http("GET", f"{base}/v1/complete")
            ok = st_b == 401 and st_a == 200 and "LOTUS_AI_UNAUTH" in body_a
            _pid, _title, _cvss, _klass = _pick(leads, "ai_auth")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_AI_UNAUTH" in body_a,
                },
            ))

        if "hook" in buckets:
            st_b, body_b = _http("POST", f"{base}/hook", data=b'{"hook":"true"}')
            st_a, body_a = _http("POST", f"{base}/hook", data=b'{"hook":"id"}')
            ok = "uid=" in body_a and "CERTBOT_HOOK" in body_a and "uid=" not in body_b
            _pid, _title, _cvss, _klass = _pick(leads, "hook")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before {body_b[:80]} | after {body_a[:200]}",
                {
                    "uid_after": "uid=" in body_a, "uid_before": "uid=" in body_b,
                    "status_after": st_a,
                },
            ))

        if "idor" in buckets:
            st_b, body_b = _http("GET", f"{base_c}/messages/42", headers={"X-User": "mallory"})
            st_a, body_a = _http("GET", f"{base}/messages/42", headers={"X-User": "mallory"})
            ok = st_b in (401, 403) and st_a == 200 and "LOTUS_IDOR" in body_a
            _pid, _title, _cvss, _klass = _pick(leads, "idor")
            results.append(_row(
                _pid, _title, _cvss, _klass, ok,
                f"before status={st_b} {body_b[:80]} | after status={st_a} {body_a[:200]}",
                {
                    "status_before": st_b, "status_after": st_a,
                    "oracle_after": "LOTUS_IDOR" in body_a,
                },
            ))
    finally:
        for srv in (httpd_open, httpd_closed):
            try:
                srv.shutdown()
            except Exception:
                pass
            finally:
                # ``shutdown`` stops serve_forever but intentionally leaves
                # the listening socket open.  Closing it is required when
                # this proof adapter runs repeatedly in a long-lived worker
                # (or a test event loop), otherwise descriptors accumulate.
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
        "analog": "test_projects/agent_app_lab/app.py",
    }
    try:
        (dest / ".lotus").mkdir(exist_ok=True)
        (dest / ".lotus" / "agent_app_poc_results.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8",
        )
    except Exception:
        pass
    return payload


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out = run_agent_app_pocs(target)
    print(json.dumps({
        "proven": len(out.get("proven") or []),
        "disproven": len(out.get("disproven") or []),
        "leads": out.get("n_source_leads"),
    }, indent=2))
