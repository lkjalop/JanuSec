"""Endpoints to manage LLM provider settings (OpenAI, Anthropic, Ollama)."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.core.config.llm_settings_store import load_settings, save_settings
from src.integrations.llm_client import DEFAULT_CLIENT as LLM_CLIENT, get_client_status

router = APIRouter(prefix="/api/v1/llm", tags=["llm"])

try:  # optional dependency for Ollama reachability
    import requests
except Exception:  # pragma: no cover
    requests = None


class LLMSettings(BaseModel):
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None
    ollama_model: Optional[str] = None


def _sanitize(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    val = value.strip()
    return val if val else ""


@router.get("/settings")
async def get_settings() -> Dict[str, Any]:
    data = load_settings()
    return {
        "openai_configured": bool(data.get("openai_api_key")),
        "anthropic_configured": bool(data.get("anthropic_api_key")),
        "ollama_base_url": data.get("ollama_base_url") or "",
        "ollama_model": data.get("ollama_model") or "",
    }


@router.post("/settings")
async def update_settings(payload: LLMSettings) -> Dict[str, Any]:
    try:
        data = load_settings()
        if payload.openai_api_key is not None:
            val = _sanitize(payload.openai_api_key)
            data["openai_api_key"] = val
            if val:
                os.environ["OPENAI_API_KEY"] = val
            else:
                os.environ.pop("OPENAI_API_KEY", None)
        if payload.anthropic_api_key is not None:
            val = _sanitize(payload.anthropic_api_key)
            data["anthropic_api_key"] = val
            if val:
                os.environ["ANTHROPIC_API_KEY"] = val
            else:
                os.environ.pop("ANTHROPIC_API_KEY", None)
        if payload.ollama_base_url is not None:
            data["ollama_base_url"] = payload.ollama_base_url.strip()
        if payload.ollama_model is not None:
            data["ollama_model"] = payload.ollama_model.strip()
        save_settings(data)
        return {"status": "saved"}
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=f"llm_settings_save_failed:{exc}")


@router.post("/probe")
async def llm_probe() -> Dict[str, Any]:
    """Trigger a live re-probe of the Ollama connection on the running singleton."""
    client = LLM_CLIENT
    ok = False
    if hasattr(client, '_probe_ollama'):
        try:
            ok = client._probe_ollama()
        except Exception as exc:
            return {"probed": False, "error": str(exc)}
    return {"probed": True, "reachable": ok}


@router.get("/health")
async def llm_health() -> Dict[str, Any]:
    data = load_settings()
    client = LLM_CLIENT
    # Re-probe on each health check so a startup-race doesn't permanently hide availability
    if hasattr(client, '_probe_ollama') and getattr(client, 'ollama_enabled', False):
        try:
            client._probe_ollama()
        except Exception:
            pass
    status = get_client_status(client)
    openai_key = os.getenv("OPENAI_API_KEY") or data.get("openai_api_key")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY") or data.get("anthropic_api_key")
    ollama_url = status.get("ollama_host") or os.getenv("OLLAMA_HOST") or data.get("ollama_base_url")
    ollama_url = ollama_url.rstrip("/") if isinstance(ollama_url, str) and ollama_url else ""
    reachable = bool(status.get("ollama_reachable"))
    provider = status.get("provider") or "unknown"
    result: Dict[str, Any] = {
        "provider": provider,
        "requested_provider": status.get("requested_provider"),
        "environment": status.get("environment"),
        "available": bool(status.get("available")),
        "strict_provider": bool(status.get("strict_provider")),
        "fallback_active": bool(status.get("fallback_active")),
        "fallback_reason": status.get("fallback_reason"),
        "local_deterministic_active": bool(status.get("local_deterministic_active")),
        "client_class": status.get("client_class"),
        "openai": {"configured": bool(openai_key)},
        "anthropic": {"configured": bool(anthropic_key)},
        "ollama": {
            "enabled": bool(status.get("ollama_enabled", bool(ollama_url))),
            "reachable": reachable,
            "base_url": ollama_url,
            "model": status.get("ollama_model") or data.get("ollama_model") or "",
        },
        "breaker": status.get("breaker") or {},
        "budget": status.get("budget") or {},
        "mock": os.getenv("LLM_MOCK", "0").lower() in {"1", "true", "yes"},
    }
    return result
