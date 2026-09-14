#!/usr/bin/env python3
"""Stdlib analog of Puppet/Mailcatcher/react_on_rails/Headroom/Certbot/Zulip classes.

No pip dependencies. Used by backend.agent_app_poc and as a copy-paste lab target.
Env:
  PORT=18090
  ENFORCE=0|1
  PROXY_TOKEN=   (empty = fail-open)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.agent_app_poc import start_analog  # noqa: E402

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "18090"))
    enforce = os.environ.get("ENFORCE", "0") == "1"
    token = os.environ.get("PROXY_TOKEN", "")
    httpd, bound, base = start_analog(enforce=enforce, token=token, port=port)
    print(
        f"agent-app analog listening on {base} enforce={enforce} token_set={bool(token)}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
