#!/usr/bin/env python3
"""Create private local bootstrap configuration without overwriting settings."""
import argparse
import errno
import os
from pathlib import Path
import secrets
import socket


def validate_port(value):
    """Accept a concrete TCP port, never a wildcard or a Compose expression."""
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdecimal():
        raise ValueError("port must be an integer from 1 to 65535")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return port


def ensure_port_available(port):
    """Preflight the loopback binding; Docker still checks it again at startup."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", validate_port(port)))


def create_config(path, port=8000):
    port = validate_port(port)
    content = (
        "# Local single-user configuration. Keep this file private.\n"
        "LOTUS_DEPLOY_PROFILE=single\nLOTUS_NO_SEED=1\n"
        "LOTUS_MAX_CONCURRENT_SCANS=1\n"
        f"LOTUS_HTTP_PORT={port}\n"
        f"LOTUS_CORS_ORIGINS=http://127.0.0.1:{port},http://localhost:{port}\n"
        f"LOTUS_SECRET_KEY={secrets.token_hex(32)}\n"
        f"LOTUS_PROOF_SIGNING_KEY={secrets.token_hex(32)}\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    parser.add_argument("--port", type=validate_port, default=8000,
                        help="local HTTP port (default: 8000)")
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise FileExistsError(args.output)
        ensure_port_available(args.port)
        create_config(args.output, args.port)
    except FileExistsError:
        parser.exit(1, "Configuration already exists; preserved without changes.\n")
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            parser.exit(1, f"Port {args.port} is already in use. No configuration was created. "
                        "Identify the listener before stopping it. If it is another Lotus instance, "
                        "stop it before reusing its data directory. For an unrelated service, "
                        "choose --port with a free port.\n")
        parser.exit(1, f"Could not prepare local configuration: {exc.strerror}.\n")
    print(f"Private local configuration created for http://127.0.0.1:{args.port}. "
          "Secret values were not printed. Follow the README Kubernetes deployment or explicit Docker backup instructions.")


if __name__ == "__main__":
    main()
