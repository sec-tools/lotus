"""Read provider model catalogs without changing or verifying AI settings.

Only fixed HTTPS endpoints receive credentials. A failed or incomplete lookup
never masquerades as an account catalog by substituting the built-in examples.
"""
from __future__ import annotations

import json
import time

import httpx

from backend.ai_credentials import key_provider_mismatch


MODEL_URLS = {
    "openai": "https://api.openai.com/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
    "openrouter": "https://openrouter.ai/api/v1/models",
}
MAX_PAGES = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
LOOKUP_SECONDS = 15.0


class CatalogError(Exception):
    """An intentionally credential-free message safe for the Settings UI."""


def _model_id(value):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 1024
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def _page(client, url, headers, params, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CatalogError("Model list request timed out; retry when the provider is reachable.")
    timeout = httpx.Timeout(remaining, connect=min(remaining, 5.0))
    with client.stream("GET", url, headers=headers, params=params, timeout=timeout,
                       follow_redirects=False) as response:
        status = response.status_code
        if status in (401, 403):
            raise CatalogError(f"Provider rejected model listing ({status}); check this API key and its permissions.")
        if status == 429:
            raise CatalogError("Provider rate limit reached; wait briefly and refresh models.")
        if 300 <= status < 400:
            raise CatalogError("Provider redirected model listing; the credential was not forwarded.")
        if status != 200:
            raise CatalogError(f"Provider could not list models (HTTP {status}); try again later.")
        body = bytearray()
        for chunk in response.iter_bytes():
            if time.monotonic() >= deadline:
                raise CatalogError("Model list request timed out; retry when the provider is reachable.")
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise CatalogError("Provider model list exceeded the response limit; no partial catalog was accepted.")
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            raise CatalogError("Provider returned an unreadable model list; try again later.") from None
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise CatalogError("Provider returned an invalid model list; try again later.")
        return data


def fetch_cloud_models(provider: str, key: str, *, configured_models=()):
    """Return all listed IDs, including fine-tunes and future model families.

Catalog presence is not completion compatibility or readiness. The separate
saved-model completion test remains mandatory before audit admission.
"""
    result = {"success": False, "provider": provider, "models": [],
              "message": "", "source": "provider"}
    if key_provider_mismatch(provider, key):
        result["message"] = "This API key belongs to a different provider. Select its provider or enter the matching key."
        return result
    if provider == "devin":
        result.update(success=True, source="configured",
            models=sorted(set(value for value in configured_models if _model_id(value))),
            message="Devin does not expose model enumeration here. Showing configured model names; save and test the selected model.")
        return result
    if provider not in MODEL_URLS:
        result["message"] = "Choose a supported cloud provider."
        return result
    if not key:
        result["message"] = "Enter an API key for this provider to load its model list."
        return result
    if "•" in key or "***" in key or any(ord(char) < 33 or ord(char) > 126 for char in key):
        result["message"] = "Enter the complete API key, or leave the field empty to use the saved key for this provider."
        return result
    headers = ({"x-api-key": key, "anthropic-version": "2023-06-01"}
               if provider == "anthropic" else {"Authorization": f"Bearer {key}"})
    headers["Accept"] = "application/json"
    deadline = time.monotonic() + LOOKUP_SECONDS
    models, cursors, params = set(), set(), {"limit": 1000} if provider == "anthropic" else {}
    try:
        with httpx.Client(follow_redirects=False) as client:
            for _ in range(MAX_PAGES):
                data = _page(client, MODEL_URLS[provider], headers, params, deadline)
                for item in data["data"]:
                    if not isinstance(item, dict) or not _model_id(item.get("id")) or key in item["id"]:
                        raise CatalogError("Provider returned an invalid model identifier; no partial catalog was accepted.")
                    models.add(item["id"])
                more = data.get("has_more", False)
                if not isinstance(more, bool):
                    raise CatalogError("Provider returned invalid model pagination; no partial catalog was accepted.")
                if not more:
                    result.update(success=True, models=sorted(models),
                        message=(f"{len(models)} models listed by the provider. Select a model and test it before starting an audit."
                                 if models else "The provider returned no models for this key; check its access permissions."))
                    return result
                cursor = data.get("last_id")
                if provider != "anthropic" or not _model_id(cursor) or cursor in cursors or key in cursor or not data["data"]:
                    raise CatalogError("Provider returned invalid model pagination; no partial catalog was accepted.")
                cursors.add(cursor)
                params = {"limit": 1000, "after_id": cursor}
        raise CatalogError("Provider model pagination exceeded the limit; no partial catalog was accepted.")
    except CatalogError as exc:
        result["message"] = str(exc)
    except httpx.TimeoutException:
        result["message"] = "Model list request timed out; retry when the provider is reachable."
    except Exception:
        # Provider response bodies and transport exception strings can contain
        # credentials. Deliberately do not echo or log either of them.
        result["message"] = "Could not load models from the provider; check connectivity and try again."
    return result
