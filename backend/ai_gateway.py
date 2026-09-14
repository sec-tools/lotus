"""Unified AI Gateway for the Lotus platform.

This module is the single, provider-agnostic path for every AI task the
platform performs (triage, PoC generation/refinement, chain construction,
report enrichment, chat, validation).

Design goals (built out across phases):
  * Phase 0 (this file's initial form): typed results + one provider-dispatch
    implementation that ``backend.main.call_ai`` delegates to, with byte-for-byte
    behavior parity so nothing downstream changes yet.
  * Later phases add: structured-output schemas, devin_mode routing, Devin
    session reuse / multi-turn, bounded concurrency, idempotent caching, and
    observability.

IMPORTANT: to avoid an import cycle, this module imports NOTHING from
``backend.main``. Callers inject ``log`` / ``progress_callback`` callables and
pass primitive settings values explicitly.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import json
import math
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import httpx


# ---------------------------------------------------------------------------
# Typed result contract
# ---------------------------------------------------------------------------

class AIStatus(str, Enum):
    """Outcome of an AI call. Callers branch on this instead of sniffing the
    text for magic prefixes like ``[ai-timeout]`` / ``[ai-error]``."""

    OK = "ok"                      # got usable content
    EMPTY = "empty"                # no credentials / nothing to do
    REFUSED = "refused"            # model declined (guardrail)
    TIMEOUT = "timeout"            # provider did not finish in budget
    ERROR = "error"                # transport / provider error
    UNAUTHORIZED = "unauthorized"  # 401/403 from provider
    UNSUPPORTED = "unsupported"    # unknown provider


@dataclass
class AIResult:
    """Structured outcome of an AI invocation."""

    status: AIStatus
    text: str = ""                       # free-text content (legacy contract)
    data: Any = None                     # parsed/validated structured output
    session_id: str = ""                 # provider session id (for follow-ups)
    raw: Optional[dict] = None           # raw provider payload
    meta: dict = field(default_factory=dict)  # latency_s, attempts, mode, ...

    @property
    def ok(self) -> bool:
        return self.status == AIStatus.OK


# ---------------------------------------------------------------------------
# Provider constants (canonical source of truth; re-exported by main/ai.py)
# ---------------------------------------------------------------------------

AI_MODELS = {
    "devin": ["devin-swe-1.7-medium"],
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o1-mini"],
    "anthropic": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
    "openrouter": ["openai/gpt-4o", "anthropic/claude-3.5-sonnet", "meta-llama/llama-3.1-70b-instruct"],
    "ollama": [],
    "lmstudio": [],
}
DEFAULT_MODELS = {
    "devin": "devin-swe-1.7-medium",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-20250514",
    "openrouter": "openai/gpt-4o",
    "ollama": "",
    "lmstudio": "",
}
LOCAL_PROVIDERS = {"ollama", "lmstudio"}
DEFAULT_BASE_URLS = {"ollama": "http://localhost:11434", "lmstudio": "http://localhost:1234"}

DEVIN_API_BASE = "https://api.devin.ai/v1"
# v1 terminal states. "blocked"/"suspended" mean the agent finished its turn
# and is awaiting a follow-up message (multi-turn); the others are fully done.
DEVIN_TERMINAL_STATES = ("finished", "stopped", "failed", "blocked", "suspended", "expired")
DEVIN_FULLY_DONE_STATES = ("finished", "stopped", "failed", "expired")


def _noop_log(message: str, level: str = "info") -> None:  # pragma: no cover
    pass


# ---------------------------------------------------------------------------
# Task taxonomy + per-task Devin agent-mode defaults (Phase 2 routing hook)
# ---------------------------------------------------------------------------

class AITask(str, Enum):
    TRIAGE = "triage"          # REAL vs FALSE_POSITIVE conviction gating
    LEAD_TRIAGE = "lead_triage"  # complete, strictly validated primary lead interpretations
    INDEPENDENT_REVIEW = "independent_review"  # strictly validated second-model interpretations
    DOMAIN_AGENT = "domain"    # per-domain specialized triage
    POC = "poc"                # reproduction command generation
    POC_REFINE = "poc_refine"  # refine a failed reproduction
    CHAIN = "chain"            # attack-chain construction
    REPORT = "report"          # root-cause / impact / remediation enrichment
    VALIDATION = "validation"  # manual finding validation (gates)
    CHAT = "chat"              # interactive assistant
    RECON = "recon"            # coverage-gap / untested-surface annotation
    DISCOVERY = "discovery"    # continuous-scan lead discovery
    AUDIT_PLAN = "audit_plan"  # how to build/run/audit an arbitrary repo
    LAB_BUILD = "lab_build"    # Dockerfile / start-command rescue
    SKILL_SYNTHESIS = "skill_synthesis"  # distill proven/DISPROVE into skills
    MODEL_VERIFICATION = "model_verification"  # explicit Settings Save & Test only
    GENERIC = "generic"


# Fast/cheap modes for lightweight structured work; heavier modes for agentic
# reproduction. Applied only when the provider is Devin and a mode is not
# explicitly supplied by the caller.
DEFAULT_DEVIN_MODE_BY_TASK = {
    AITask.TRIAGE: "lite",
    AITask.INDEPENDENT_REVIEW: "lite",
    AITask.MODEL_VERIFICATION: "lite",
    AITask.DOMAIN_AGENT: "lite",
    AITask.REPORT: "lite",
    AITask.VALIDATION: "fast",
    AITask.CHAT: "fast",
    AITask.RECON: "fast",
    AITask.DISCOVERY: "fast",
    AITask.AUDIT_PLAN: "lite",
    AITask.LAB_BUILD: "lite",
    AITask.SKILL_SYNTHESIS: "lite",
    AITask.POC: "normal",
    AITask.POC_REFINE: "normal",
    AITask.CHAIN: "normal",
    AITask.GENERIC: None,
}


_REFUSAL_MARKERS = (
    "i can't help with", "i cannot help with", "i won't", "i will not",
    "i'm not able to help", "i am not able to help", "i don't do that",
    "i do not do that", "against my guidelines", "i can't assist",
    "i cannot assist", "exploit generation", "i must decline", "i have to decline",
    "cannot provide exploit", "can't provide exploit", "not comfortable",
)


def looks_like_refusal(text: str) -> bool:
    """Heuristic: did the model decline the task on policy grounds?

    Deliberately specific to avoid flagging legitimate JSON verdicts that merely
    contain words like "exploit" inside an ``attack_vector`` field.
    """
    if not text:
        return False
    head = text[:600].lower()
    # A well-formed JSON payload is never a refusal.
    if head.lstrip().startswith(("[", "{")):
        return False
    return any(m in head for m in _REFUSAL_MARKERS)


def extract_json(text: str) -> Any:
    """Best-effort extraction of a JSON array/object embedded in free text.
    Returns the parsed value or ``None``."""
    if not text:
        return None
    import re as _re
    for pat in (r"\[.*\]", r"\{.*\}"):
        m = _re.search(pat, text, _re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                continue
    try:
        return json.loads(text)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OpenAI-compatible chat completion (OpenAI, OpenRouter, Ollama, LM Studio)
# ---------------------------------------------------------------------------

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_INDEPENDENT_REVIEW_MAX_BYTES = 1024 * 1024
_INDEPENDENT_REVIEW_STOP = ContextVar("independent_review_transport_stop", default=None)
_LEAD_TRIAGE_TOKENS = ContextVar("lead_triage_output_tokens", default=4096)
_AUDIT_PLAN_OUTPUT_TOKENS = 8192
_LAB_BUILD_OUTPUT_TOKENS = 8192
_LAB_REVIEW_OUTPUT_TOKENS = 16384


class _ReviewResponseError(ValueError):
    """A successful HTTP response cannot supply bounded review content."""


@contextmanager
def lead_triage_transport(stop_event=None, *, output_tokens=4096):
    """Reuse the bounded owned HTTP transport only for the new triage task."""
    if output_tokens not in (4096, 8192) or type(output_tokens) is not int:
        raise ValueError("Lead triage output budget must be 4096 or 8192 tokens")
    token = _LEAD_TRIAGE_TOKENS.set(output_tokens)
    try:
        with independent_review_transport(stop_event):
            yield
    finally:
        _LEAD_TRIAGE_TOKENS.reset(token)


def independent_review_stop_event():
    """Expose only the current invocation's cooperative cancellation event."""
    return _INDEPENDENT_REVIEW_STOP.get()


@contextmanager
def independent_review_transport(stop_event=None):
    """Bind cancellation to this review invocation without changing other tasks.

    HTTP review callers run in an owned synchronous worker. The Devin session
    transport remains separate and does not consume this cancellation binding.
    """
    token = _INDEPENDENT_REVIEW_STOP.set(stop_event)
    try:
        yield
    finally:
        _INDEPENDENT_REVIEW_STOP.reset(token)


class _Deadline:
    """One monotonic budget for transport, retries, backoff and polling.

    The synchronous transport's timeout is an I/O inactivity bound. Passing
    the remaining budget and checking each returned response avoids resetting
    that budget across attempts; it cannot interrupt a single trickling read.
    """

    def __init__(self, timeout):
        self.started = time.monotonic()
        self.timeout = float(timeout)
        if not math.isfinite(self.timeout) or self.timeout < 0:
            raise ValueError("AI timeout must be a finite nonnegative duration")
        self.ends = self.started + self.timeout

    @property
    def elapsed(self):
        return max(0.0, time.monotonic() - self.started)

    def remaining(self, ceiling=None):
        remaining = self.ends - time.monotonic()
        if remaining <= 0:
            raise httpx.TimeoutException("AI operation exhausted its total timeout budget")
        return min(remaining, ceiling) if ceiling is not None else remaining

    def result(self, session_id=""):
        return AIResult(AIStatus.TIMEOUT, text="[ai-timeout] AI operation exceeded its total timeout budget",
                        session_id=session_id,
                        meta={"elapsed_s": self.elapsed, "timeout_seconds": self.timeout})


def _post_with_retry(url: str, *, json: dict, headers: dict, timeout: int,
                     attempts: int = 3, log: Callable[[str, str], None] = _noop_log,
                     independent_review: bool = False) -> httpx.Response:
    """POST with exponential backoff on transient failures (timeouts, connection
    errors, 429/5xx). Non-transient 4xx errors raise immediately so we don't mask
    auth/validation problems. Makes cloud AI calls resilient to blips instead of
    failing a whole scan on one hiccup."""
    if independent_review:
        # Do not nest an event loop or create an unowned fallback thread. This
        # task's caller already owns and drains its synchronous review worker.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(_post_independent_review(
                url, json=json, headers=headers, timeout=timeout, attempts=attempts, log=log,
                stop_event=_INDEPENDENT_REVIEW_STOP.get()))
        raise RuntimeError("Independent review HTTP calls require an owned synchronous worker")
    import random
    deadline = _Deadline(timeout)
    last_exc: Optional[Exception] = None
    for i in range(max(1, attempts)):
        try:
            r = httpx.post(url, json=json, headers=headers, timeout=deadline.remaining())
            deadline.remaining()  # A late response cannot be accepted as success.
            if r.status_code in _RETRYABLE_STATUS and i < attempts - 1:
                raise httpx.HTTPStatusError(f"retryable {r.status_code}", request=r.request, response=r)
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as e:
            # Only retry the transient status codes; surface real 4xx immediately.
            if e.response is not None and e.response.status_code not in _RETRYABLE_STATUS:
                raise
            last_exc = e
        except (httpx.TimeoutException, httpx.TransportError) as e:
            last_exc = e
        deadline.remaining()
        if i < attempts - 1:
            delay = min(8.0, 0.5 * (2 ** i)) + random.uniform(0, 0.25)
            log(f"AI call transient failure ({str(last_exc)[:80]}); retry {i + 1}/{attempts - 1} in {delay:.1f}s", "warning")
            time.sleep(min(delay, deadline.remaining()))
    if last_exc:
        raise last_exc
    raise RuntimeError("AI POST failed with no response")


async def _post_independent_review(url: str, *, json: dict, headers: dict, timeout: float,
                                   attempts: int = 3, log=_noop_log, stop_event=None) -> httpx.Response:
    """Bound the entire HTTP exchange, including a continuously trickling body.

    Retain HTTPX's normal proxy/TLS policy and existing redirect prohibition.
    Identity encoding avoids decompression before the response-size bound can
    be enforced; an unsolicited compressed response is an explicit error.
    """
    import random
    deadline = _Deadline(timeout)
    if stop_event is not None and stop_event.is_set():
        raise asyncio.CancelledError()
    owner = asyncio.current_task()

    async def watch_stop():
        while not stop_event.is_set():
            await asyncio.sleep(.025)
        owner.cancel()

    watcher = asyncio.create_task(watch_stop()) if stop_event is not None else None
    request_headers = httpx.Headers(headers)
    request_headers["Accept-Encoding"] = "identity"
    last_exc = None
    try:
        async with asyncio.timeout(deadline.remaining()):
            async with httpx.AsyncClient(follow_redirects=False) as client:
                for i in range(max(1, attempts)):
                    try:
                        async with client.stream("POST", url, json=json, headers=request_headers,
                                                 timeout=deadline.remaining()) as response:
                            encoding = response.headers.get("content-encoding", "identity").strip().lower()
                            if encoding not in {"", "identity"}:
                                raise _ReviewResponseError("Independent review response used an unsupported content encoding")
                            length = response.headers.get("content-length", "")
                            if length.isdecimal() and int(length) > _INDEPENDENT_REVIEW_MAX_BYTES:
                                raise _ReviewResponseError("Independent review response exceeded the 1 MiB body limit")
                            content = bytearray()
                            async for chunk in response.aiter_raw(chunk_size=65536):
                                if len(chunk) > _INDEPENDENT_REVIEW_MAX_BYTES - len(content):
                                    raise _ReviewResponseError("Independent review response exceeded the 1 MiB body limit")
                                content.extend(chunk)
                            deadline.remaining()
                            result = httpx.Response(response.status_code, headers=response.headers,
                                                    content=bytes(content), request=response.request)
                        result.raise_for_status()
                        return result
                    except httpx.HTTPStatusError as error:
                        if error.response.status_code not in _RETRYABLE_STATUS:
                            raise
                        last_exc = error
                    except (httpx.TimeoutException, httpx.TransportError) as error:
                        last_exc = error
                    deadline.remaining()
                    if i < attempts - 1:
                        delay = min(8.0, .5 * (2 ** i)) + random.uniform(0, .25)
                        log(f"Independent review transient HTTP failure; retry {i + 1}/{attempts - 1} in {delay:.1f}s", "warning")
                        await asyncio.sleep(min(delay, deadline.remaining()))
                if last_exc:
                    raise last_exc
                raise RuntimeError("Independent review POST failed with no response")
    except TimeoutError as error:
        raise httpx.TimeoutException("Independent review exhausted its total HTTP timeout budget") from error
    finally:
        if watcher is not None:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)


def _call_openai_compatible(url: str, model: str, prompt: str, headers: dict, timeout: int,
                            log: Callable[[str, str], None] = _noop_log, *, openai_api: bool = False,
                            independent_review: bool = False, response_metadata: Optional[dict] = None,
                            output_tokens: int = 2048, structured_schema: Optional[dict] = None) -> str:
    """Call an OpenAI-compatible chat completions endpoint. Returns text."""
    body = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    if openai_api:
        # OpenAI's current chat schema supersedes max_tokens with
        # max_completion_tokens (including reasoning tokens). Do not force a
        # sampling temperature unsupported by reasoning models. Keep the
        # existing token ceiling and exact requested model; compatible local
        # servers and OpenRouter retain their established wire contract.
        # https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
        body["max_completion_tokens"] = output_tokens
    else:
        body.update(temperature=0.2, max_tokens=output_tokens)
    if structured_schema is not None:
        # OpenRouter supports JSON-schema output for compatible models. The
        # consumer still validates completeness and the full local contract.
        # https://openrouter.ai/docs/guides/features/structured-outputs
        body["response_format"] = {"type": "json_schema", "json_schema": {
            "name": "lotus_lab_review", "strict": True, "schema": structured_schema}}
        body["provider"] = {"require_parameters": True}
    r = _post_with_retry(url, json=body, headers=headers, timeout=timeout, log=log,
                         **({"independent_review": True} if independent_review else {}))
    if independent_review:
        return _independent_review_text(r, response_metadata, anthropic=False)
    data = r.json()
    if openai_api:
        choices = data.get("choices") if isinstance(data, dict) else None
        first = choices[0] if isinstance(choices, list) and choices else None
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(first, dict) and first.get("finish_reason") == "length":
            raise RuntimeError("Selected OpenAI model exhausted the completion token limit; the incomplete response was not accepted")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Selected OpenAI model returned no text completion; choose a compatible text model and test it")
        return content
    choices = data.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", r.text[:1000])
    return r.text[:1000]


def _independent_review_text(response, metadata, *, anthropic):
    """A real HTTP success with unusable model output is a quality decision.

    Preserve truncation even when the returned text happens to parse as JSON;
    strict independent-review validation must never accept that partial result.
    """
    quality = {"empty": True, "truncated": False, "finish_reason": ""}
    content = None
    try:
        data = response.json()
    except (ValueError, UnicodeError):
        data = None
    if isinstance(data, dict):
        if anthropic:
            blocks = data.get("content")
            if isinstance(blocks, list) and all(isinstance(block, dict) for block in blocks):
                texts = [block["text"] for block in blocks if isinstance(block.get("text"), str)]
                content = "\n".join(texts)
            finish = data.get("stop_reason")
        else:
            choices = data.get("choices")
            first = choices[0] if isinstance(choices, list) and choices else None
            message = first.get("message") if isinstance(first, dict) else None
            content = message.get("content") if isinstance(message, dict) else None
            finish = first.get("finish_reason") if isinstance(first, dict) else None
        quality["finish_reason"] = str(finish or "")[:80]
        quality["truncated"] = finish in {"length", "max_tokens"} if isinstance(finish, str) else False
    if not isinstance(content, str):
        quality["invalid_provider_payload"] = True
        content = ""
    quality["empty"] = not content.strip()
    if metadata is not None:
        metadata["response_quality"] = quality
    return content


# ---------------------------------------------------------------------------
# Devin session dispatch
# ---------------------------------------------------------------------------

def _poll_devin_session(
    session_id: str,
    headers: dict,
    timeout: int,
    *,
    progress_callback: Optional[Callable[[str], None]] = None,
    log: Callable[[str, str], None] = _noop_log,
    devin_mode: Optional[str] = None,
    poll_interval: int = 6,
    min_msg_count: int = 0,
    _deadline: Optional[_Deadline] = None,
) -> AIResult:
    """Poll a Devin session until it reaches a terminal state, then extract the
    result. ``min_msg_count`` supports multi-turn reuse: only messages produced
    after that index count as *this turn's* output, so a follow-up never returns
    a previous turn's answer. structured_output (overwritten each turn) is always
    the current turn's and is preferred when present.
    """
    deadline = _deadline if _deadline is not None else _Deadline(timeout)
    if poll_interval <= 0:
        raise ValueError("Devin poll interval must be positive")
    while True:
        try:
            time.sleep(min(poll_interval, deadline.remaining()))
            poll = httpx.get(f"{DEVIN_API_BASE}/session/{session_id}", headers=headers,
                             timeout=deadline.remaining(15))
            deadline.remaining()
            if poll.status_code != 200:
                continue
            data = poll.json()
            deadline.remaining()
            elapsed = round(deadline.elapsed, 3)
            status = data.get("status", "")
            status_enum = data.get("status_enum", "")
            messages = data.get("messages", []) or []
            if progress_callback:
                progress_callback(f"AI analyzing... ({status_enum or status}, {elapsed}s elapsed)")
            elif elapsed % 60 < poll_interval:
                log(f"Devin session {session_id[:12]}... status={status}/{status_enum} ({elapsed}s elapsed)", "info")
            deadline.remaining()
            if status_enum in DEVIN_TERMINAL_STATES:
                so = data.get("structured_output")
                parsed = so if isinstance(so, (dict, list)) else None
                output = ""
                if isinstance(so, (dict, list)):
                    output = json.dumps(so)
                elif isinstance(so, str) and so:
                    output = so
                if not output:
                    new_msgs = messages[min_msg_count:]
                    devin_msgs = [m.get("message", "") for m in new_msgs if m.get("type") == "devin_message"]
                    if devin_msgs:
                        output = max(devin_msgs, key=len)
                if output:
                    return AIResult(
                        AIStatus.OK, text=str(output)[:8000], data=parsed, session_id=session_id,
                        raw=data, meta={"elapsed_s": elapsed, "status_enum": status_enum,
                                        "acus": data.get("acus_consumed"), "devin_mode": devin_mode,
                                        "msg_count": len(messages)},
                    )
                if status_enum in DEVIN_FULLY_DONE_STATES and len(messages) >= min_msg_count:
                    return AIResult(
                        AIStatus.OK, text=(data.get("title", "") + " | " + str(status_enum))[:8000],
                        session_id=session_id, raw=data,
                        meta={"elapsed_s": elapsed, "status_enum": status_enum, "msg_count": len(messages)},
                    )
                # blocked/suspended with no new output yet -> keep polling
        except Exception:
            # Poll errors are transient only while the original turn has time
            # left; HTTP waits count just as much as the polling sleeps.
            try:
                deadline.remaining()
            except httpx.TimeoutException:
                return deadline.result(session_id)


def _dispatch_devin(
    prompt: str,
    headers: dict,
    timeout: int,
    *,
    progress_callback: Optional[Callable[[str], None]] = None,
    log: Callable[[str, str], None] = _noop_log,
    devin_mode: Optional[str] = None,
    structured_schema: Optional[dict] = None,
    idempotent: bool = False,
) -> AIResult:
    """Create a single-shot Devin session, poll to completion, return the result.

    Supports optional ``devin_mode`` (lite/fast/normal/ultra/fusion),
    ``structured_schema`` (JSON Schema for validated structured output), and
    ``idempotent`` (dedupe identical create requests).
    """
    url = f"{DEVIN_API_BASE}/sessions"
    deadline = _Deadline(timeout)
    body: dict = {"prompt": prompt}
    if devin_mode:
        body["devin_mode"] = devin_mode
    if structured_schema:
        body["structured_output_schema"] = structured_schema
        body["structured_output_required"] = True
    if idempotent:
        body["idempotent"] = True
    r = httpx.post(url, json=body, headers=headers, timeout=deadline.remaining(30))
    deadline.remaining()
    if r.status_code in (401, 403):
        log(f"Devin API returned {r.status_code}; authentication failed and no AI result was produced", "warn")
        return AIResult(AIStatus.UNAUTHORIZED, text="", raw={"status_code": r.status_code})
    r.raise_for_status()
    session_data = r.json()
    deadline.remaining()
    session_id = session_data.get("session_id") or session_data.get("id", "")
    if not session_id:
        return AIResult(AIStatus.OK, text=r.text[:2000], raw=session_data)
    log(f"Devin session created: {session_id} - polling up to {timeout}s", "info")
    if progress_callback:
        progress_callback(f"AI session created ({session_id[:12]}...) - polling for results...")
    return _poll_devin_session(
        session_id, headers, timeout,
        progress_callback=progress_callback, log=log, devin_mode=devin_mode, min_msg_count=0,
        _deadline=deadline,
    )


# ---------------------------------------------------------------------------
# Multi-turn session reuse (Devin) — amortizes cold-start + preserves context
# ---------------------------------------------------------------------------

class SessionManager:
    """A reusable AI session for a sequence of related turns (e.g. per-finding
    PoC -> refine -> refine -> chain).

    For Devin, the first :meth:`run` creates a session (paying the one-time
    cold-start) and subsequent calls send follow-up messages to the *same* warm
    session via ``POST /v1/sessions/{id}/message`` — the agent already has the
    repo/context loaded, so refinements are far cheaper than new sessions.

    For non-Devin providers there is no session concept, so each :meth:`run` is
    an independent stateless :func:`dispatch` (still fully functional, just
    without reuse). Credential/mock handling is the caller's responsibility;
    this operates on primitives only.
    """

    def __init__(
        self,
        *,
        provider: str,
        api_key: str = "",
        base_url: str = "",
        is_local: bool = False,
        log: Callable[[str, str], None] = _noop_log,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.provider = provider
        self.api_key = api_key
        self.base_url = base_url
        self.is_local = is_local
        self.log = log or _noop_log
        self.progress_callback = progress_callback
        self.session_id: str = ""
        self._msg_count: int = 0
        self._closed: bool = False
        self.turns: int = 0
        self._headers = {"Content-Type": "application/json"}
        if not is_local and api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    @property
    def active(self) -> bool:
        return bool(self.session_id) and not self._closed

    def run(
        self,
        prompt: str,
        *,
        task: Optional[AITask] = None,
        devin_mode: Optional[str] = None,
        structured_schema: Optional[dict] = None,
        timeout: int = 300,
        idempotent: bool = False,
    ) -> AIResult:
        """Start the session (first call) or send a follow-up (subsequent calls)."""
        from backend.ai_credentials import key_provider_mismatch
        if key_provider_mismatch(self.provider, self.api_key):
            return AIResult(AIStatus.ERROR, text="[ai-configuration] API key belongs to a different provider; configure the matching provider and key")
        self.turns += 1
        if devin_mode is None and task is not None:
            devin_mode = DEFAULT_DEVIN_MODE_BY_TASK.get(task)
        if self.provider != "devin":
            # No session concept: fall back to a stateless dispatch.
            return dispatch(
                provider=self.provider, model="", api_key=self.api_key, base_url=self.base_url,
                prompt=prompt, timeout=timeout, is_local=self.is_local,
                progress_callback=self.progress_callback, log=self.log,
                task=task, devin_mode=devin_mode, structured_schema=structured_schema,
            )
        if not self.active:
            return self._start(prompt, devin_mode=devin_mode, structured_schema=structured_schema,
                               timeout=timeout, idempotent=idempotent)
        return self._send(prompt, structured_schema=structured_schema, timeout=timeout, devin_mode=devin_mode)

    def _start(self, prompt, *, devin_mode, structured_schema, timeout, idempotent) -> AIResult:
        deadline = _Deadline(timeout)
        body: dict = {"prompt": prompt}
        if devin_mode:
            body["devin_mode"] = devin_mode
        if structured_schema:
            body["structured_output_schema"] = structured_schema
            body["structured_output_required"] = True
        if idempotent:
            body["idempotent"] = True
        try:
            r = httpx.post(f"{DEVIN_API_BASE}/sessions", json=body, headers=self._headers,
                           timeout=deadline.remaining(30))
            deadline.remaining()
        except httpx.TimeoutException:
            return deadline.result()
        except Exception as e:
            return AIResult(AIStatus.ERROR, text=f"[ai-error] {str(e)[:300]}")
        if r.status_code in (401, 403):
            self.log(f"Devin API returned {r.status_code} Unauthorized", "warn")
            return AIResult(AIStatus.UNAUTHORIZED, text="", raw={"status_code": r.status_code})
        try:
            r.raise_for_status()
        except Exception as e:
            return AIResult(AIStatus.ERROR, text=f"[ai-error] {str(e)[:300]}")
        data = r.json()
        try:
            deadline.remaining()
        except httpx.TimeoutException:
            return deadline.result()
        sid = data.get("session_id") or data.get("id", "")
        if not sid:
            return _finalize(AIResult(AIStatus.OK, text=r.text[:2000], raw=data))
        self.session_id = sid
        self._closed = False
        self.log(f"Devin session started: {sid} (mode={devin_mode})", "info")
        if self.progress_callback:
            self.progress_callback(f"AI session created ({sid[:12]}...) - polling for results...")
        res = _poll_devin_session(
            sid, self._headers, timeout,
            progress_callback=self.progress_callback, log=self.log, devin_mode=devin_mode, min_msg_count=0,
            _deadline=deadline,
        )
        self._msg_count = res.meta.get("msg_count", self._msg_count) if res.meta else self._msg_count
        return _finalize(res)

    def _send(self, message, *, structured_schema, timeout, devin_mode) -> AIResult:
        deadline = _Deadline(timeout)
        prev = self._msg_count
        try:
            response = httpx.post(
                f"{DEVIN_API_BASE}/sessions/{self.session_id}/message",
                json={"message": message}, headers=self._headers, timeout=deadline.remaining(30),
            )
            deadline.remaining()
            response.raise_for_status()
        except httpx.TimeoutException:
            return deadline.result(self.session_id)
        except Exception as e:
            return AIResult(AIStatus.ERROR, text=f"[ai-error] follow-up failed: {str(e)[:200]}",
                            session_id=self.session_id)
        self.log(f"Devin follow-up sent to {self.session_id[:12]}... (turn {self.turns})", "info")
        if self.progress_callback:
            self.progress_callback(f"AI follow-up sent ({self.session_id[:12]}...) - polling...")
        res = _poll_devin_session(
            self.session_id, self._headers, timeout,
            progress_callback=self.progress_callback, log=self.log, devin_mode=devin_mode, min_msg_count=prev,
            _deadline=deadline,
        )
        self._msg_count = res.meta.get("msg_count", self._msg_count) if res.meta else self._msg_count
        return _finalize(res)

    def close(self) -> None:
        """Mark the session closed. (Devin v1 has no explicit close; this stops
        further reuse and lets the session expire on its own.)"""
        self._closed = True


# ---------------------------------------------------------------------------
# Unified dispatch entrypoint
# ---------------------------------------------------------------------------

def dispatch(
    *,
    provider: str,
    model: str,
    api_key: str,
    base_url: str,
    prompt: str,
    timeout: int,
    is_local: bool = False,
    progress_callback: Optional[Callable[[str], None]] = None,
    log: Callable[[str, str], None] = _noop_log,
    task: Optional[AITask] = None,
    devin_mode: Optional[str] = None,
    structured_schema: Optional[dict] = None,
    idempotent: bool = False,
) -> AIResult:
    """Route a prompt to the configured provider and return a typed AIResult.

    Credential validation and synthetic-key/mock handling are done by the
    caller (``backend.main.call_ai``) so this stays a pure provider dispatch.
    ``task`` selects a default Devin agent mode when ``devin_mode`` is omitted.
    """
    log = log or _noop_log
    from backend.ai_credentials import key_provider_mismatch
    if key_provider_mismatch(provider, api_key):
        return AIResult(AIStatus.ERROR, text="[ai-configuration] API key belongs to a different provider; configure the matching provider and key")
    if devin_mode is None and task is not None:
        devin_mode = DEFAULT_DEVIN_MODE_BY_TASK.get(task)
    headers = {"Content-Type": "application/json"}
    if not is_local and api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    structured_triage = task == AITask.LEAD_TRIAGE
    structured_plan = task == AITask.AUDIT_PLAN
    structured_build = task == AITask.LAB_BUILD
    build_token_budget = _LAB_REVIEW_OUTPUT_TOKENS if structured_build and structured_schema is not None else _LAB_BUILD_OUTPUT_TOKENS
    strict_quality = structured_triage or structured_plan or structured_build
    review_transport = {"independent_review": True} if task in {AITask.INDEPENDENT_REVIEW, AITask.LEAD_TRIAGE, AITask.AUDIT_PLAN, AITask.LAB_BUILD} else {}
    review_metadata = {}
    review_call = {**review_transport, "response_metadata": review_metadata} if review_transport else {}
    if structured_triage and provider != "devin":
        review_call["output_tokens"] = _LEAD_TRIAGE_TOKENS.get()
        review_metadata["output_token_budget"] = _LEAD_TRIAGE_TOKENS.get()
    elif structured_plan and provider != "devin":
        # Planning needs room for the complete schema and, on reasoning
        # models, internal reasoning. Keep the selected model and finite
        # request deadline; there is no unbounded token escalation.
        review_call["output_tokens"] = _AUDIT_PLAN_OUTPUT_TOKENS
        review_metadata["output_token_budget"] = _AUDIT_PLAN_OUTPUT_TOKENS
    elif structured_build and provider != "devin":
        # Leave room for a reasoning model to finish its short review JSON.
        # The same per-call wall deadline and two-review limit remain in force.
        review_call["output_tokens"] = build_token_budget
        review_metadata["output_token_budget"] = build_token_budget
    try:
        if provider == "devin":
            res = _dispatch_devin(
                prompt, headers, timeout,
                progress_callback=progress_callback, log=log,
                devin_mode=devin_mode, structured_schema=structured_schema, idempotent=idempotent,
            )
        elif provider == "openai":
            res = AIResult(AIStatus.OK, text=_call_openai_compatible(
                "https://api.openai.com/v1/chat/completions", model, prompt, headers, timeout, log=log, openai_api=True,
                **review_call))
        elif provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
            headers.pop("Authorization", None)
            url = "https://api.anthropic.com/v1/messages"
            body = {"model": model, "max_tokens": (_LEAD_TRIAGE_TOKENS.get() if structured_triage else
                    _AUDIT_PLAN_OUTPUT_TOKENS if structured_plan else build_token_budget if structured_build else 2048),
                    "messages": [{"role": "user", "content": prompt}]}
            r = _post_with_retry(url, json=body, headers=headers, timeout=timeout, log=log, **review_transport)
            if review_transport:
                res = AIResult(AIStatus.OK, text=_independent_review_text(r, review_metadata, anthropic=True))
            else:
                data = r.json()
                res = AIResult(AIStatus.OK, text=data.get("content", [{}])[0].get("text", r.text[:1000]), raw=data)
        elif provider == "openrouter":
            headers["HTTP-Referer"] = "https://lotus-bdaas.local"
            headers["X-Title"] = "Lotus BDAAS"
            res = AIResult(AIStatus.OK, text=_call_openai_compatible(
                "https://openrouter.ai/api/v1/chat/completions", model, prompt, headers, timeout, log=log,
                **({"structured_schema": structured_schema} if structured_build and structured_schema is not None else {}), **review_call))
        elif provider in LOCAL_PROVIDERS:
            base = (base_url or DEFAULT_BASE_URLS.get(provider, "")).rstrip("/")
            try:
                from backend.validation import validate_outbound_http_url
                base = validate_outbound_http_url(base, field_name="ai_base_url")
            except Exception as exc:
                # Treat destination-policy rejection as a transport error for
                # callers that already fail closed on non-OK AI results.  Do
                # not attempt the request or silently fall back to another
                # provider.
                return AIResult(AIStatus.ERROR, text=f"[ai-policy] {str(exc)[:240]}")
            url = f"{base}/v1/chat/completions"
            res = AIResult(AIStatus.OK, text=_call_openai_compatible(url, model, prompt, headers, timeout,
                                                                  log=log, **review_call))
        else:
            return AIResult(AIStatus.UNSUPPORTED, text=f"[ai-unsupported] provider {provider}")
    except httpx.TimeoutException:
        return AIResult(AIStatus.TIMEOUT, text="[ai-timeout] AI operation exceeded its timeout budget",
            meta={"provider_failure": {"schema_version": 1, "kind": "timeout", "retryable": True}})
    except Exception as e:
        if strict_quality:
            if isinstance(e, (_ReviewResponseError, RecursionError)):
                return AIResult(AIStatus.OK, text="", meta={"response_quality": {
                    "invalid_provider_payload": True, "response_body_rejected": True}})
            if (structured_plan or structured_build) and not isinstance(e, (httpx.HTTPStatusError, httpx.TransportError)):
                # An implementation exception is not evidence of bad credentials.
                raise
        status_code = e.response.status_code if isinstance(e, httpx.HTTPStatusError) else None
        kind = "http_status" if status_code is not None else "transport" if isinstance(e, httpx.TransportError) else "provider_response"
        diagnostic = {"schema_version": 1, "kind": kind, "retryable": status_code in _RETRYABLE_STATUS if status_code else isinstance(e, httpx.TransportError)}
        if status_code is not None:
            diagnostic["status_code"] = status_code
        return AIResult(AIStatus.UNAUTHORIZED if status_code in (401, 403) else AIStatus.ERROR,
            text="AI provider did not return an available response" if strict_quality else f"[ai-error] {str(e)[:300]}",
            meta={"provider_failure": diagnostic})
    if review_metadata:
        res.meta.update(review_metadata)
        if strict_quality:
            # This task's strict consumer owns parsing and content quality.
            # Refusal-shaped prose, deep JSON, empty and truncated responses
            # must not become credential/availability failures here.
            return res
        quality = review_metadata.get("response_quality") or {}
        if any(quality.get(key) is True for key in ("truncated", "empty", "invalid_provider_payload")):
            # Even refusal-shaped partial text is an incomplete response to
            # validate/repair, not evidence that provider credentials failed.
            res.data = extract_json(res.text) if res.text else None
            return res
    return res if strict_quality else _finalize(res)


def _finalize(res: AIResult) -> AIResult:
    """Enrich a successful result: parse embedded JSON into ``.data`` and
    downgrade OK->REFUSED when the model declined. Never mutates ``.text`` so
    the legacy string contract used by ``call_ai`` is preserved exactly.
    """
    if res.status != AIStatus.OK:
        return res
    if res.data is None and res.text:
        res.data = extract_json(res.text)
    if res.text and res.data is None and looks_like_refusal(res.text):
        res.status = AIStatus.REFUSED
    return res


# ---------------------------------------------------------------------------
# Bounded concurrency — parallelize independent AI calls without overrunning
# provider rate limits / cost. Order-preserving; one failure never aborts the
# batch (exceptions are returned in place, like gather(return_exceptions=True)).
# ---------------------------------------------------------------------------

def default_ai_concurrency() -> int:
    """Concurrency cap for parallel AI calls (``$LOTUS_AI_CONCURRENCY``, min 1,
    default 3). Callers may override per-batch via the ``limit`` argument."""
    try:
        return max(1, int(os.environ.get("LOTUS_AI_CONCURRENCY", "3")))
    except (TypeError, ValueError):
        return 3


async def bounded_gather(factories, limit: Optional[int] = None):
    """Run zero-arg async callables with bounded concurrency, preserving order.

    ``factories`` is an iterable of callables, each returning an awaitable (use
    a factory rather than a bare coroutine so nothing starts before its slot is
    acquired). The semaphore is created inside the running loop, so this is safe
    to call from any event loop (no import-time loop binding).
    """
    factories = list(factories)
    if not factories:
        return []
    if limit is None or limit <= 0:
        limit = default_ai_concurrency()
    sem = asyncio.Semaphore(max(1, limit))

    async def _run(factory):
        async with sem:
            return await factory()

    return await asyncio.gather(*[_run(f) for f in factories], return_exceptions=True)
