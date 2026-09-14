"""
AI provider integration for Lotus BDAAS.

Re-exports AI functions from main.py. New code can import from here:
    from backend.ai import call_ai, AI_MODELS, detect_provider

Handles all AI model communication: cloud providers (OpenAI, Anthropic,
OpenRouter, Devin) and local providers (Ollama, LM Studio).
"""

# Re-export all AI functions from main for clean import paths
from backend.main import (  # noqa: F401
    AI_MODELS,
    DEFAULT_MODELS,
    LOCAL_PROVIDERS,
    DEFAULT_BASE_URLS,
    call_ai,
    _call_openai_compatible,
    mask_key,
    detect_provider,
    test_key,
    _test_local_provider,
    fetch_local_models,
)

from backend.langchain_adapter import (  # noqa: F401
    get_langchain_chat_model,
    invoke_structured_findings,
    parse_structured_findings_text,
    StructuredFinding,
    StructuredFindingList,
    StructuredPhase2Plan,
)
