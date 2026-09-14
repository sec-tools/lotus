#!/usr/bin/env python3
"""Stdlib analog of Envoy fail-open, ShenYu Groovy, frp dashboard, SafeLine XFF.

No pip dependencies. Used by backend.gateway_poc and as a copy-paste lab target.
Env:
  PORT=18080
  EXT_AUTHZ_UP=0|1
  DASHBOARD_TOKEN=   (empty = fail-open)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Reuse the analog bundled in gateway_poc so oracles never drift.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.gateway_poc import start_analog  # noqa: E402

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "18080"))
    authz = os.environ.get("EXT_AUTHZ_UP", "0") == "1"
    token = os.environ.get("DASHBOARD_TOKEN", "")
    httpd, bound, base = start_analog(authz_up=authz, dashboard_token=token, port=port)
    print(f"gateway analog listening on {base} authz_up={authz} token_set={bool(token)}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
