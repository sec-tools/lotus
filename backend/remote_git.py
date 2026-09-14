"""Remote enrollment syntax and bounded, credential-free HTTPS branch discovery."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
import re
import signal
import socket
import tempfile
import threading
from urllib.parse import urlsplit

from backend.validation import ValidationError, validate_branch, validate_repo_source

MAX_BYTES = 131072
MAX_BRANCHES = 512
TIMEOUT_SECONDS = 10
CLEANUP_SECONDS = 2
_reads = threading.BoundedSemaphore(2)
_dns_slots = threading.BoundedSemaphore(2)
_dns_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="git-branch-dns")
_host = re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}\Z")
_oid = re.compile(r"(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\Z")


class BranchDiscoveryError(ValueError):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


def validate_enrollment_source(source: str) -> str:
    """Accept remote Git URLs only; local ingestion remains an internal capability."""
    if not isinstance(source, str) or len(source) > 512:
        raise ValidationError("source", "must be a Git URL of at most 512 characters")
    source = validate_repo_source(source, allow_local_paths=False)
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in source):
        raise ValidationError("source", "whitespace/control characters are not allowed")
    if source.startswith("git@"):
        match = re.fullmatch(r"git@([^/:]+):([^?#]+)", source)
        if not match:
            raise ValidationError("source", "invalid SSH Git URL")
        host, path = match.groups()
    else:
        try:
            parsed = urlsplit(source)
            if parsed.scheme not in {"https", "http", "ssh"}:
                raise ValueError()
            if parsed.query or parsed.fragment or parsed.password:
                raise ValueError()
            if parsed.username and not (parsed.scheme == "ssh" and parsed.username == "git"):
                raise ValueError()
            if parsed.scheme == "ssh" and parsed.username != "git":
                raise ValueError()
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError()
            host, path = parsed.hostname or "", parsed.path.lstrip("/")
        except ValueError:
            raise ValidationError("source", "use an HTTPS or SSH Git repository URL") from None
    if not _host.fullmatch(host) or not path or path.startswith("-") or "%" in source:
        raise ValidationError("source", "use a public Git repository hostname and repository path")
    try:
        if not ipaddress.ip_address(host).is_global:
            raise ValidationError("source", "private repository hosts are not allowed")
    except ValueError as exc:
        if isinstance(exc, ValidationError):
            raise
    if host.lower().endswith((".local", ".internal", ".localhost")):
        raise ValidationError("source", "private repository hosts are not allowed")
    return source


async def _public_addresses(host, port):
    # Resolver calls can outlive a request deadline. Keep their *actual* worker
    # slots until completion, so cancelled callers cannot grow an unbounded queue.
    if not _dns_slots.acquire(blocking=False):
        raise BranchDiscoveryError("Branch discovery is busy; retry shortly", 503)
    try:
        future = _dns_pool.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    except BaseException:
        _dns_slots.release()
        raise
    future.add_done_callback(lambda _: _dns_slots.release())
    rows = await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), 3)
    addresses = sorted({row[4][0] for row in rows})
    if not addresses or len(addresses) > 16 or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise BranchDiscoveryError("Repository hostname must resolve only to public addresses", 422)
    return addresses


def parse_branches(raw: bytes, source: str, *, truncated=False, default_branch=None, head_only=False) -> dict:
    if len(raw) > MAX_BYTES:
        raise BranchDiscoveryError("Repository branch list exceeds the supported response limit")
    branches, default, head_seen = set(), None, False
    try:
        for line in raw.decode("utf-8", errors="strict").splitlines():
            left, ref = line.split("\t")
            if left.startswith("ref: ") and ref == "HEAD":
                target = left[5:]
                if not target.startswith("refs/heads/") or default is not None:
                    raise ValueError()
                default = validate_branch(target[11:])
                if len(default) > 128:
                    raise ValueError()
            elif _oid.fullmatch(left) and ref == "HEAD":
                head_seen = True
                continue
            elif _oid.fullmatch(left) and ref.startswith("refs/heads/"):
                branch = validate_branch(ref[11:])
                if len(branch) > 128:
                    raise ValueError()
                if branch in branches:
                    raise ValueError()
                if len(branches) < MAX_BRANCHES:
                    branches.add(branch)
                else:
                    truncated = True
            else:
                raise ValueError()
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, BranchDiscoveryError):
            raise
        raise BranchDiscoveryError("Remote returned an invalid or unsupported branch name") from None
    if head_only and head_seen and default:
        branches.add(default)
    if default_branch:
        # This default was separately verified by the bounded HEAD query.
        default = default_branch
        if default not in branches and len(branches) == MAX_BRANCHES:
            branches.remove(max(branches))
            truncated = True
        branches.add(default)
    if default not in branches:
        default = None
    result = {"source": source, "branches": sorted(branches), "default_branch": default}
    if truncated:
        result["truncated"] = True
    return result


async def discover_branches(source: str, *, branch: str | None = None) -> dict:
    source = validate_enrollment_source(source)
    if branch is not None:
        branch = validate_branch(branch)
        if len(branch) > 128:
            raise ValidationError("branch", "too long (max 128 characters)")
    parsed = urlsplit(source)
    if parsed.scheme != "https":
        raise BranchDiscoveryError("Branch discovery requires a public HTTPS Git URL; SSH enrollment may use a manually entered branch", 422)
    if not _reads.acquire(blocking=False):
        raise BranchDiscoveryError("Branch discovery is busy; retry shortly", 503)
    proc = None
    stdout_complete = False
    release_slot = True
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            addresses = await _public_addresses(parsed.hostname, parsed.port or 443)
            # Pin curl's resolution after rejecting private answers. DNS changes
            # between validation and Git must not redirect this read internally.
            address = next((ip for ip in addresses if ":" not in ip), addresses[0])
            if ":" in address:
                address = f"[{address}]"
            with tempfile.TemporaryDirectory(prefix="lotus-branches-") as temporary:
                env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
                env.update(HOME=temporary, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_CEILING_DIRECTORIES=temporary, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="",
                           GIT_CONFIG_COUNT="0", GIT_ALLOW_PROTOCOL="https")
                command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
                    "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                    "-c", "http.followRedirects=false", "-c", "http.proxy=",
                    "-c", f"http.curloptResolve={parsed.hostname}:{parsed.port or 443}:{address}",
                    "ls-remote", "--symref", "--", source]
                # HEAD is read first so a large branch advertisement cannot hide
                # the repository default. Both commands share the same deadline.
                queries = [["refs/heads/" + branch]] if branch is not None else [["HEAD"], ["refs/heads/*"]]
                default = None
                for patterns in queries:
                    stdout_complete = False
                    proc = await asyncio.create_subprocess_exec(*command, *patterns, cwd=temporary, env=env,
                        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL, limit=MAX_BYTES + 1, start_new_session=True)
                    output, limited = bytearray(), False
                    while True:
                        chunk = await proc.stdout.read(min(8192, MAX_BYTES + 1 - len(output)))
                        if not chunk:
                            stdout_complete = True
                            break
                        output.extend(chunk)
                        if len(output) > MAX_BYTES:
                            if patterns != ["refs/heads/*"]:
                                raise BranchDiscoveryError("Repository branch response exceeds the supported limit")
                            # Retain only complete records, then the finally block
                            # kills/drains the owned process before returning.
                            output = output[:MAX_BYTES].rsplit(b"\n", 1)[0] + b"\n"
                            limited = True
                            break
                    if not limited and await proc.wait() != 0:
                        raise BranchDiscoveryError("Git branch discovery failed; verify the public HTTPS repository URL and access")
                    refs = parse_branches(bytes(output), source, truncated=limited,
                        default_branch=default, head_only=patterns == ["HEAD"])
                    if branch is not None:
                        # ls-remote patterns can match ref suffixes. Require the
                        # exact returned branch, not merely a nonempty response.
                        if branch not in refs["branches"]:
                            raise BranchDiscoveryError("This branch was not found in the repository; check its exact name", 422)
                        return {"source": source, "branches": [branch], "default_branch": None, "verified_branch": branch}
                    if patterns == ["HEAD"]:
                        default = refs["default_branch"]
                        continue
                    return refs
    except (TimeoutError, socket.gaierror, OSError) as exc:
        raise BranchDiscoveryError("Git branch discovery timed out or is unavailable; verify repository access", 504 if isinstance(exc, TimeoutError) else 502) from None
    finally:
        try:
            if proc is not None:
                # An exited leader can leave a helper holding the pipe open.
                # That pipe still belongs to our dedicated process session.
                if proc.returncode is None or not stdout_complete:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL) if os.name == "posix" else proc.kill()
                    except ProcessLookupError:
                        pass
                # Drain the owned process even when the HTTP task was cancelled.
                async def reap_and_close_pipe():
                    await proc.wait()
                    if not stdout_complete:
                        while await proc.stdout.read(8192):
                            pass
                drain = asyncio.create_task(reap_and_close_pipe())
                cancelled = False
                deadline = asyncio.get_running_loop().time() + CLEANUP_SECONDS
                while not drain.done():
                    try:
                        remaining = deadline - asyncio.get_running_loop().time()
                        if remaining <= 0:
                            raise TimeoutError
                        await asyncio.wait_for(asyncio.shield(drain), remaining)
                    except asyncio.CancelledError:
                        cancelled = True
                    except TimeoutError:
                        # Keep admission occupied until the actual child drains.
                        # The request refuses without permitting an unlimited
                        # sequence of timed-out workers to accumulate.
                        release_slot = False
                        drain.add_done_callback(lambda _: _reads.release())
                        if cancelled:
                            raise asyncio.CancelledError
                        raise BranchDiscoveryError("Git cleanup is still pending; branch discovery is unavailable", 503) from None
                drain.result()
                if cancelled:
                    raise asyncio.CancelledError
        finally:
            if release_slot:
                _reads.release()
