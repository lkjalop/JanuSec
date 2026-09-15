"""Unified model-provider discovery and real health probes.

Discovery is read-only.  In particular, it never submits case evidence and it
never treats an external provider as an automatic fallback.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(slots=True)
class ProviderStatus:
    provider: str
    endpoint: str
    location: str
    available: bool
    configured: bool
    latency_ms: int | None = None
    models: list[str] = field(default_factory=list)
    error: str | None = None
    checked_at: float = field(default_factory=time.time)
    external_data_transfer: bool = False
    health_checks: dict[str, Any] = field(default_factory=dict)
    model_manifests: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def runtime_provider_config(provider: str) -> dict[str, Any]:
    """Read the existing in-memory AI settings without exposing secrets."""
    try:
        from src.api.integrations_endpoints import _STATE

        providers = (((_STATE.get("ai") or {}).get("config") or {}).get("providers") or {})
        value = providers.get(provider) if isinstance(providers, dict) else None
        return dict(value) if isinstance(value, dict) else {}
    except Exception:
        return {}


def _request_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 2.5) -> tuple[dict[str, Any], int]:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: configured provider endpoints
        body = json.loads(response.read().decode("utf-8"))
    return body, int((time.perf_counter() - started) * 1000)


def _post_json(url: str, payload: dict[str, Any], *, timeout: float) -> tuple[dict[str, Any], int]:
    started = time.perf_counter()
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: configured provider endpoints
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"ollama_http_{exc.code}:{detail}") from exc
    return body, int((time.perf_counter() - started) * 1000)


def _ollama_runtime_checks(endpoint: str) -> dict[str, Any]:
    executable = shutil.which("ollama")
    local_endpoint = (urlparse(endpoint).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
    server_candidates: list[Path] = []
    if executable:
        root = Path(executable).resolve().parent
        server_candidates.extend((root / "lib" / "ollama" / "llama-server.exe", root / "llama-server.exe"))
    server = next((path for path in server_candidates if path.is_file()), None)
    return {
        "local_endpoint": local_endpoint,
        "client_executable": executable,
        "client_executable_present": bool(executable),
        "inference_executable": str(server) if server else None,
        "inference_executable_present": bool(server) if os.name == "nt" and local_endpoint else None,
        "runtime_layout": "windows_split_server" if os.name == "nt" and local_endpoint else "remote_or_embedded",
    }


def _probe_ollama(endpoint: str) -> ProviderStatus:
    checks = _ollama_runtime_checks(endpoint)
    if checks["local_endpoint"] and not checks["client_executable_present"]:
        return ProviderStatus("ollama", endpoint, "local", False, False, error="ollama_client_executable_missing", health_checks=checks)
    if checks.get("inference_executable_present") is False:
        return ProviderStatus("ollama", endpoint, "local", False, True, error="ollama_inference_executable_missing", health_checks=checks)
    try:
        body, latency = _request_json(f"{endpoint.rstrip('/')}/api/tags")
        models = [str(item.get("name")) for item in (body.get("models") or []) if item.get("name")]
        manifests = [
            {"name": str(item.get("name")), "digest": item.get("digest"), "modified_at": item.get("modified_at"), "size": item.get("size")}
            for item in body.get("models") or [] if isinstance(item, dict) and item.get("name")
        ]
        checks["tags_api"] = "ok"
        return ProviderStatus("ollama", endpoint, "local", True, True, latency, models, health_checks=checks, model_manifests=manifests)
    except Exception as exc:
        checks["tags_api"] = "failed"
        return ProviderStatus("ollama", endpoint, "local", False, True, error=str(exc)[:240], health_checks=checks)


def _probe_openai_compatible(name: str, endpoint: str, *, local: bool, key: str | None = None) -> ProviderStatus:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        body, latency = _request_json(f"{endpoint.rstrip('/')}/models", headers=headers)
        models = [str(item.get("id")) for item in (body.get("data") or []) if item.get("id")]
        return ProviderStatus(name, endpoint, "local" if local else "external", True, bool(local or key), latency, models, external_data_transfer=not local)
    except Exception as exc:
        return ProviderStatus(name, endpoint, "local" if local else "external", False, bool(local or key), error=str(exc)[:240], external_data_transfer=not local)


def _probe_anthropic(endpoint: str, key: str | None) -> ProviderStatus:
    if not key:
        return ProviderStatus("anthropic", endpoint, "external", False, False, error="secret_not_configured", external_data_transfer=True)
    try:
        body, latency = _request_json(
            f"{endpoint.rstrip('/')}/v1/models",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        )
        models = [str(item.get("id")) for item in (body.get("data") or []) if item.get("id")]
        return ProviderStatus("anthropic", endpoint, "external", True, True, latency, models, external_data_transfer=True)
    except Exception as exc:
        return ProviderStatus("anthropic", endpoint, "external", False, True, error=str(exc)[:240], external_data_transfer=True)


def discover_providers(*, probe_external: bool = False) -> list[dict[str, Any]]:
    """Return deterministic and discovered local providers, plus configured APIs."""
    statuses = [
        ProviderStatus(
            provider="deterministic",
            endpoint="internal://janusec",
            location="internal",
            available=True,
            configured=True,
            latency_ms=0,
            models=["janusec-rules"],
        )
    ]
    ollama_cfg = runtime_provider_config("ollama")
    ollama = os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_URL") or ollama_cfg.get("url") or "http://127.0.0.1:11434"
    statuses.append(_probe_ollama(ollama))
    statuses.append(_probe_openai_compatible("lmstudio", os.getenv("LM_STUDIO_URL", "http://127.0.0.1:1234/v1"), local=True))
    statuses.append(_probe_openai_compatible("vllm", os.getenv("VLLM_URL", "http://127.0.0.1:8000/v1"), local=True))

    openai_cfg = runtime_provider_config("openai")
    openai_key = os.getenv("OPENAI_API_KEY") or openai_cfg.get("key")
    if probe_external and openai_key:
        statuses.append(_probe_openai_compatible("openai", os.getenv("OPENAI_BASE_URL") or openai_cfg.get("url") or "https://api.openai.com/v1", local=False, key=openai_key))
    else:
        statuses.append(
            ProviderStatus("openai", os.getenv("OPENAI_BASE_URL") or openai_cfg.get("url") or "https://api.openai.com/v1", "external", False, bool(openai_key), error=None if openai_key else "secret_not_configured", external_data_transfer=True)
        )
    anthropic_cfg = runtime_provider_config("anthropic")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY") or anthropic_cfg.get("key")
    statuses.append(
        _probe_anthropic(os.getenv("ANTHROPIC_BASE_URL") or anthropic_cfg.get("url") or "https://api.anthropic.com", anthropic_key)
        if probe_external
        else ProviderStatus("anthropic", os.getenv("ANTHROPIC_BASE_URL") or anthropic_cfg.get("url") or "https://api.anthropic.com", "external", False, bool(anthropic_key), error=None if anthropic_key else "secret_not_configured", external_data_transfer=True)
    )
    return [status.to_dict() for status in statuses]


def probe_ollama_inference(
    model: str,
    *,
    endpoint: str | None = None,
    context_tokens: int = 8192,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Explicit launch/JSON/context probe. It never receives case evidence."""

    if not model.strip():
        raise ValueError("ollama_probe_model_required")
    if context_tokens < 1024 or context_tokens > 1_048_576:
        raise ValueError("ollama_probe_context_out_of_range")
    endpoint = (endpoint or os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_URL") or "http://127.0.0.1:11434").rstrip("/")
    runtime = _probe_ollama(endpoint)
    if not runtime.available:
        return {"status": "unavailable", "model": model, "context_tokens": context_tokens, "runtime": runtime.to_dict()}
    manifest = next((item for item in runtime.model_manifests if item.get("name") == model), None)
    if manifest is None:
        return {
            "status": "model_not_installed", "model": model, "context_tokens": context_tokens,
            "installed_models": runtime.models, "runtime": runtime.to_dict(),
        }
    try:
        body, latency = _post_json(
            f"{endpoint}/api/generate",
            {
                "model": model,
                "prompt": 'Return exactly {"probe":"ok"}.',
                "stream": False,
                "format": "json",
                "think": False,
                "keep_alive": 0,
                "options": {"temperature": 0, "num_ctx": context_tokens, "num_predict": 24},
            },
            timeout=timeout,
        )
        raw = str(body.get("response") or "")
        parsed = json.loads(raw)
        valid = parsed.get("probe") == "ok"
        return {
            "status": "ok" if valid else "structured_output_invalid",
            "model": model,
            "model_manifest": manifest,
            "context_tokens": context_tokens,
            "latency_ms": latency,
            "structured_output_valid": valid,
            "prompt_eval_count": body.get("prompt_eval_count"),
            "eval_count": body.get("eval_count"),
            "runtime": runtime.to_dict(),
        }
    except Exception as exc:
        return {
            "status": "inference_failed", "model": model, "model_manifest": manifest,
            "context_tokens": context_tokens, "error": f"{type(exc).__name__}:{exc}"[:700],
            "runtime": runtime.to_dict(),
        }


__all__ = ["ProviderStatus", "discover_providers", "probe_ollama_inference", "runtime_provider_config"]
