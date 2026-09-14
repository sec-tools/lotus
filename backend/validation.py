"""Centralized input validation and sanitization.

All user-facing input MUST pass through these functions before
being stored, used in queries, or passed to subprocesses.
"""
from __future__ import annotations

import re
import os
import ipaddress
import socket
import unicodedata
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


# Characters that MUST NEVER appear in shell-adjacent strings
_SHELL_META = set(";|&$`\\\"'\n\r<>{}[]()")

# ASCII control characters (except tab, newline, carriage return)
_CONTROL_CHARS = set(chr(i) for i in range(32) if chr(i) not in "\t\n\r")

# Null byte
_NULL = "\x00"

# Private IP ranges for SSRF prevention
_PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^fc00:", re.IGNORECASE),
    re.compile(r"^fd", re.IGNORECASE),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.IGNORECASE),
]

_PRIVATE_HOSTNAMES = {"localhost", "0.0.0.0", "[::]", "[::1]", "metadata.google.internal"}


class ValidationError(ValueError):
    """Raised when input fails validation."""

    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


def sanitize_text(text: str, max_len: int = 10000, field_name: str = "text") -> str:
    """Strip dangerous characters from general text input.

    - Removes null bytes
    - Removes ASCII control characters (keeps tab, newline, CR)
    - Normalizes Unicode to NFC form
    - Truncates to max_len
    - Strips leading/trailing whitespace
    """
    if not isinstance(text, str):
        raise ValidationError(field_name, "must be a string")

    # Remove null bytes
    text = text.replace(_NULL, "")

    # Remove control characters
    text = "".join(c for c in text if c not in _CONTROL_CHARS)

    # Normalize unicode
    text = unicodedata.normalize("NFC", text)

    # Truncate
    if len(text) > max_len:
        text = text[:max_len]

    return text.strip()


def sanitize_html(text: str, max_len: int = 10000, field_name: str = "text") -> str:
    """Strip HTML tags and entities from text to prevent stored XSS."""
    text = sanitize_text(text, max_len, field_name)

    # Strip HTML tags
    text = re.sub(r"<[^>]*>", "", text)

    # Encode HTML entities
    text = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )

    return text


def validate_repo_source(source: str, allow_local_paths: Optional[bool] = None) -> str:
    """Validate repository source URL or path.

    Accepts:
    - HTTPS Git URLs (github.com, gitlab.com, bitbucket.org, etc.)
    - SSH Git URLs (git@host:...)
    - Local paths only when explicitly enabled; by default an absolute local
      path is rejected by API callers to prevent arbitrary host-file ingestion.

    Rejects:
    - Path traversal (../)
    - file:// URIs
    - Private/internal IPs (SSRF prevention)
    - Shell metacharacters
    - Empty or whitespace-only
    """
    if not source or not source.strip():
        raise ValidationError("source", "must not be empty")

    source = source.strip()

    # Block null bytes
    if _NULL in source:
        raise ValidationError("source", "contains null bytes")

    # Block path traversal
    if ".." in source:
        raise ValidationError("source", "path traversal not allowed")

    # Block file:// URIs
    if source.lower().startswith("file://"):
        raise ValidationError("source", "file:// URIs not allowed")

    # Block shell metacharacters
    bad_chars = set(source) & _SHELL_META
    if bad_chars:
        raise ValidationError(
            "source",
            f"contains disallowed characters: {', '.join(repr(c) for c in sorted(bad_chars))}",
        )

    # If it looks like a URL, validate it
    if source.startswith("http://") or source.startswith("https://"):
        parsed = urlparse(source)
        host = parsed.hostname or ""

        # Credentials and query/fragment material are not needed to enroll a
        # public repository and can leak through audit logs, git diagnostics,
        # browser history, or persisted Repo.source values. Use an explicit
        # credential helper/secret store instead of embedding secrets in URLs.
        if parsed.username or parsed.password:
            raise ValidationError("source", "embedded URL credentials are not allowed")
        if parsed.query or parsed.fragment:
            raise ValidationError("source", "URL query/fragment is not allowed")

        # Block private IPs
        if host.lower() in _PRIVATE_HOSTNAMES:
            raise ValidationError("source", f"private hostname not allowed: {host}")

        for pattern in _PRIVATE_IP_PATTERNS:
            if pattern.match(host):
                raise ValidationError("source", f"private IP not allowed: {host}")

        # Must have a valid host
        if not host or "." not in host:
            raise ValidationError("source", "invalid URL hostname")

    # Local filesystem sources are a privileged capability.  Callers that need
    # them must opt in and enforce an allowlisted root; URL validation above is
    # intentionally independent of this branch.
    candidate_path = Path(source).expanduser()
    # Existing relative paths are local sources too (e.g. ``./fixture``), even
    # though only absolute paths are obvious from the string alone.
    local = candidate_path if source.startswith("/") or (not source.startswith(("http://", "https://", "git@")) and candidate_path.exists()) else None
    if local is not None:
        if allow_local_paths is False:
            raise ValidationError("source", "local filesystem sources are disabled")
        if allow_local_paths is True:
            resolved = local.resolve()
            raw_roots = os.environ.get("LOTUS_ALLOWED_SOURCE_ROOTS", "")
            roots = [Path(x).expanduser().resolve() for x in raw_roots.split(",") if x.strip()]
            if not roots:
                roots = [Path.cwd().resolve()]
            if not any(resolved == root or root in resolved.parents for root in roots):
                raise ValidationError("source", "local path is outside configured source roots")

    return source


def validate_outbound_http_url(url: str, *, allow_private: Optional[bool] = None,
                               allowed_hosts: Optional[set[str]] = None,
                               field_name: str = "url") -> str:
    """Validate a control-plane HTTP destination before making an outbound call.

    Local model and webhook URLs are operator-controlled in the UI.  In a
    network deployment they must not become an SSRF primitive for loopback,
    cloud metadata, or RFC1918 services.  Single-user localhost remains
    available for Ollama/LM Studio; shared profiles can explicitly allow a
    host via ``LOTUS_AI_ALLOWED_HOSTS`` (or the caller's set).
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError(field_name, "must not be empty")
    value = url.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationError(field_name, "must use http or https")
    if parsed.username or parsed.password:
        raise ValidationError(field_name, "embedded credentials are not allowed")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValidationError(field_name, "hostname is required")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(field_name, "invalid port") from exc
    if any(ord(c) < 32 for c in value):
        raise ValidationError(field_name, "contains control characters")

    if allow_private is None:
        profile = (os.environ.get("LOTUS_DEPLOY_PROFILE") or os.environ.get("LOTUS_PROFILE") or "single").strip().lower()
        allow_private = profile not in {"team", "enterprise", "prod", "production", "org", "cluster", "k8s"}
    configured = allowed_hosts if allowed_hosts is not None else {
        h.strip().lower().rstrip(".")
        for h in (os.environ.get("LOTUS_AI_ALLOWED_HOSTS") or "").split(",") if h.strip()
    }
    if host in configured:
        return value

    if not allow_private:
        if host in _PRIVATE_HOSTNAMES:
            raise ValidationError(field_name, f"private hostname not allowed: {host}")
        try:
            parsed_ip = ipaddress.ip_address(host)
        except ValueError:
            parsed_ip = None
        if parsed_ip is not None:
            if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_reserved:
                raise ValidationError(field_name, f"private IP not allowed: {host}")
        else:
            # Resolve DNS before the request.  Reject any address in the
            # answer set that could route to a private/link-local service;
            # callers should use an explicit allowlist for intentional internal
            # model endpoints.  Resolution failures are surfaced as input
            # errors rather than silently bypassing the policy.
            try:
                infos = socket.getaddrinfo(host, port or (443 if parsed.scheme.lower() == "https" else 80), type=socket.SOCK_STREAM)
            except OSError as exc:
                raise ValidationError(field_name, f"hostname resolution failed: {host}") from exc
            for info in infos:
                addr = info[4][0]
                try:
                    resolved = ipaddress.ip_address(addr)
                except ValueError:
                    continue
                if resolved.is_private or resolved.is_loopback or resolved.is_link_local or resolved.is_reserved:
                    raise ValidationError(field_name, f"hostname resolves to a private address: {host}")
    return value


def validate_branch(branch: str) -> str:
    """Validate Git branch name.

    Allows: alphanumeric, /, ., _, -
    Rejects: everything else including shell metacharacters
    """
    if not branch or not branch.strip():
        raise ValidationError("branch", "must not be empty")

    branch = branch.strip()

    if not re.match(r"^[a-zA-Z0-9/_.\-]+$", branch):
        raise ValidationError("branch", "contains invalid characters (allowed: alphanumeric, /, ., _, -)")

    if ".." in branch:
        raise ValidationError("branch", "path traversal not allowed")

    if len(branch) > 200:
        raise ValidationError("branch", "too long (max 200 characters)")

    return branch


def validate_path_within(filepath: Path, base_dir: Path) -> Path:
    """Ensure a file path resolves within a base directory.

    Prevents path traversal attacks (../../etc/passwd).
    """
    resolved = filepath.resolve()
    base_resolved = base_dir.resolve()

    # Python 3.9 compatible: use str comparison instead of is_relative_to
    resolved_str = str(resolved)
    base_str = str(base_resolved)

    if not (resolved_str == base_str or resolved_str.startswith(base_str + "/")):
        raise ValidationError(
            "path",
            f"path escapes base directory: {resolved} is not within {base_resolved}",
        )

    return resolved


def validate_filename(filename: str, allowed_extensions: Optional[set] = None) -> str:
    """Validate a filename - no path separators, no traversal.

    Args:
        filename: The filename to validate
        allowed_extensions: Optional set of allowed extensions (e.g. {".md", ".txt"})
    """
    if not filename or not filename.strip():
        raise ValidationError("filename", "must not be empty")

    filename = filename.strip()

    # Block path separators
    if "/" in filename or "\\" in filename:
        raise ValidationError("filename", "must not contain path separators")

    # Block traversal
    if filename.startswith(".") and filename != ".":
        if filename.startswith(".."):
            raise ValidationError("filename", "path traversal not allowed")

    # Block null bytes
    if _NULL in filename:
        raise ValidationError("filename", "contains null bytes")

    # Check extensions
    if allowed_extensions is not None:
        ext = Path(filename).suffix.lower()
        if ext not in allowed_extensions:
            raise ValidationError(
                "filename",
                f"extension {ext!r} not allowed (allowed: {', '.join(sorted(allowed_extensions))})",
            )

    if len(filename) > 255:
        raise ValidationError("filename", "too long (max 255 characters)")

    return filename


def validate_integer_range(value, min_val: int, max_val: int, field_name: str = "value") -> int:
    """Validate and clamp an integer to a valid range."""
    try:
        val = int(value)
    except (TypeError, ValueError):
        raise ValidationError(field_name, f"must be an integer (got {type(value).__name__})")

    if val < min_val or val > max_val:
        raise ValidationError(field_name, f"must be between {min_val} and {max_val} (got {val})")

    return val


def validate_float_range(value, min_val: float, max_val: float, field_name: str = "value") -> float:
    """Validate a float is within range."""
    try:
        val = float(value)
    except (TypeError, ValueError):
        raise ValidationError(field_name, f"must be a number (got {type(value).__name__})")

    if val < min_val or val > max_val:
        raise ValidationError(field_name, f"must be between {min_val} and {max_val} (got {val})")

    return val


def sanitize_json_string_values(obj, max_depth: int = 10, max_str_len: int = 10000):
    """Recursively sanitize all string values in a JSON-like object."""
    if max_depth <= 0:
        return obj

    if isinstance(obj, str):
        return sanitize_text(obj, max_len=max_str_len)
    elif isinstance(obj, dict):
        return {
            sanitize_text(str(k), max_len=200): sanitize_json_string_values(v, max_depth - 1, max_str_len)
            for k, v in obj.items()
        }
    elif isinstance(obj, (list, tuple)):
        return [sanitize_json_string_values(item, max_depth - 1, max_str_len) for item in obj]
    else:
        return obj
