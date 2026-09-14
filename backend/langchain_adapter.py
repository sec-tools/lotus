"""
LangChain Adapter for Lotus BDAAS Platform.

Provides unified chat model factory for cloud (OpenAI, Anthropic, OpenRouter)
and local (Ollama, LM Studio) providers using LangChain. Implements Pydantic
structured output schemas and fix-up output parsers for high reliability.
"""

import json
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.language_models.chat_models import BaseChatModel


# ---------------------------------------------------------------------------
# Structured Pydantic Schemas for Vulnerability Audit Outputs
# ---------------------------------------------------------------------------

class StructuredFinding(BaseModel):
    title: str = Field(description="Short descriptive title of the vulnerability")
    cvss: float = Field(default=0.0, description="CVSS v3.1 score between 0.0 and 10.0")
    file: str = Field(default="", description="Relative file path where vulnerability originates")
    line: int = Field(default=0, description="Line number where vulnerable sink or entry point is located")
    description: str = Field(default="", description="Detailed root cause explanation and data flow description")
    attack_vector: str = Field(default="", description="Attack vector / PoC execution path")
    confidence: str = Field(default="medium", description="Confidence level: high, medium, low")
    primitive_type: Optional[str] = Field(default=None, description="R/W/X primitive category: X-1, W-1, R-1, etc.")
    conviction_level: int = Field(default=0, description="Conviction level: 0=hypothesis, 1=reachable, 2=triggerable, 3=impactful")


class StructuredFindingList(BaseModel):
    findings: List[StructuredFinding] = Field(default_factory=list, description="List of validated results or candidate leads")


class Phase2Task(BaseModel):
    title: str = Field(description="Task title")
    category: str = Field(description="Task category: validation, authorization, injection, etc.")
    priority: str = Field(description="Priority: critical, high, medium, informational")
    target: str = Field(description="Target file or endpoint")
    technique: str = Field(description="Audit technique code: T1, T2, T4, T6, T7, T9, etc.")
    why: str = Field(description="Rationale for inclusion")


class StructuredPhase2Plan(BaseModel):
    tasks: List[Phase2Task] = Field(default_factory=list, description="Prioritized task list for Phase 2 discovery")


# ---------------------------------------------------------------------------
# LangChain Chat Model Factory
# ---------------------------------------------------------------------------

def get_langchain_chat_model(settings: Any, timeout: int = 30) -> Optional[BaseChatModel]:
    """Instantiate a LangChain chat model based on platform settings."""
    provider = getattr(settings, 'ai_provider', '') or ""
    model_name = getattr(settings, 'ai_model', '') or ""
    api_key = getattr(settings, 'ai_api_key', '') or ""
    base_url = getattr(settings, 'ai_base_url', '') or ""

    if provider == "ollama":
        from langchain_ollama import ChatOllama
        url = base_url or "http://localhost:11434"
        return ChatOllama(
            base_url=url,
            model=model_name or "llama3",
            temperature=0.1,
            client_kwargs={"timeout": timeout},
        )

    if provider == "lmstudio":
        from langchain_openai import ChatOpenAI
        url = (base_url or "http://localhost:1234").rstrip("/")
        if not url.endswith("/v1"):
            url += "/v1"
        return ChatOpenAI(
            model=model_name or "local-model", api_key=api_key or "lm-studio-local",
            base_url=url, temperature=0.1, timeout=timeout,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        if not api_key:
            return None
        return ChatOpenAI(
            model=model_name or "gpt-4o-mini",
            api_key=api_key,
            temperature=0.1,
            timeout=timeout,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        if not api_key:
            return None
        return ChatAnthropic(
            model_name=model_name or "claude-3-5-sonnet-20241022",
            api_key=api_key,
            temperature=0.1,
            timeout=timeout,
        )

    if provider == "openrouter":
        from langchain_openai import ChatOpenAI
        if not api_key:
            return None
        return ChatOpenAI(
            model=model_name or "openai/gpt-4o-mini",
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0.1,
            timeout=timeout,
        )

    return None


# ---------------------------------------------------------------------------
# Structured Output Invocation & Robust JSON Parsing
# ---------------------------------------------------------------------------

def invoke_structured_findings(prompt: str, settings: Any, timeout: int = 30) -> List[Dict[str, Any]]:
    """Invoke LLM via LangChain model with fallback parsing for local/cloud models."""
    llm = get_langchain_chat_model(settings, timeout=timeout)
    if not llm:
        return []

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        raw_text = response.content if hasattr(response, "content") else str(response)
        return parse_structured_findings_text(str(raw_text))
    except Exception as e:
        return []


def parse_structured_findings_text(text: str) -> List[Dict[str, Any]]:
    """Robust JSON extractor for LLM findings response."""
    if not text or not text.strip():
        return []

    # First try direct JSON array parsing
    try:
        json_match = re.search(r'\[.*\]', text, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            if isinstance(data, list):
                return [_clean_finding_dict(item) for item in data if isinstance(item, dict)]
    except Exception:
        pass

    # Try Pydantic list structure
    try:
        json_obj_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_obj_match:
            data = json.loads(json_obj_match.group())
            if isinstance(data, dict) and "findings" in data:
                return [_clean_finding_dict(item) for item in data["findings"] if isinstance(item, dict)]
    except Exception:
        pass

    return []


def _clean_finding_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize and validate finding fields."""
    return {
        "title": str(item.get("title", "Untitled Vulnerability")),
        "cvss": float(item.get("cvss", 5.0)),
        "file": str(item.get("file", "")),
        "line": int(item.get("line", 0) or 0),
        "description": str(item.get("description", "")),
        "attack_vector": str(item.get("attack_vector", "")),
        "confidence": str(item.get("confidence", "medium")).lower(),
        "primitive_type": item.get("primitive_type"),
        "conviction_level": int(item.get("conviction_level", 0)),
    }
