"""Immutable, tenant-scoped model narrative runs for case comparison."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_BREAKER_LOCK = threading.Lock()
_BREAKER_STATE: dict[str, dict[str, float | int]] = {}


def _part(value: str) -> str:
    if not value or not _SAFE.fullmatch(value):
        raise ValueError("invalid_model_run_path_component")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class ModelRunStore:
    def __init__(self, root: str | Path = "data/model-runs") -> None:
        self.root = Path(root).resolve()

    def _case_dir(self, tenant_id: str, case_id: str) -> Path:
        path = self.root / _part(tenant_id) / _part(case_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create(self, tenant_id: str, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        run_id = str(payload.get("run_id") or f"run-{uuid.uuid4().hex[:16]}")
        record = {
            **payload,
            "run_id": _part(run_id),
            "tenant_id": tenant_id,
            "case_id": case_id,
            "created_at": time.time(),
            "immutable": True,
        }
        record["record_hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
        path = self._case_dir(tenant_id, case_id) / f"{run_id}.json"
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(record, indent=2, ensure_ascii=False, default=str))
        return record

    def list(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        path = self._case_dir(tenant_id, case_id)
        return sorted(
            (json.loads(item.read_text(encoding="utf-8")) for item in path.glob("run-*.json")),
            key=lambda item: float(item.get("created_at") or 0),
        )


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None, timeout: float = 180.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: configured provider endpoints
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:700]
        raise RuntimeError(f"provider_http_{exc.code}:{detail}") from exc


def _get_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: configured provider endpoints
        return json.loads(response.read().decode("utf-8"))


def _breaker_before(provider: str) -> None:
    now = time.time()
    with _BREAKER_LOCK:
        state = _BREAKER_STATE.get(provider) or {}
        if float(state.get("open_until") or 0) > now:
            raise RuntimeError("model_provider_circuit_open")


def _breaker_success(provider: str) -> None:
    with _BREAKER_LOCK:
        _BREAKER_STATE.pop(provider, None)


def _breaker_failure(provider: str) -> None:
    threshold = max(1, int(os.getenv("MODEL_PROVIDER_BREAKER_FAILURES", "2")))
    cooldown = max(1.0, float(os.getenv("MODEL_PROVIDER_BREAKER_COOLDOWN_SECONDS", "60")))
    with _BREAKER_LOCK:
        state = _BREAKER_STATE.setdefault(provider, {"failures": 0, "open_until": 0.0})
        state["failures"] = int(state.get("failures") or 0) + 1
        if int(state["failures"]) >= threshold:
            state["open_until"] = time.time() + cooldown


def _run_case_model_once(
    provider: str,
    model: str,
    prompt: str,
    *,
    external_allowed: bool = False,
    provider_config: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    provider = provider.lower().strip()
    provider_config = provider_config or {}
    started = time.perf_counter()
    if provider == "ollama":
        endpoint = (os.getenv("OLLAMA_HOST") or os.getenv("OLLAMA_URL") or provider_config.get("url") or "http://127.0.0.1:11434").rstrip("/")
        timeout = float(os.getenv("MODEL_RUN_TIMEOUT_SECONDS", "300"))
        context_tokens = int(os.getenv("MODEL_CONTEXT_TOKENS", "8192"))
        max_output_tokens = max(256, int(os.getenv("MODEL_RUN_MAX_OUTPUT_TOKENS", "1400")))
        keep_alive = os.getenv("MODEL_RUN_KEEP_ALIVE", "2m")
        manifest = None
        try:
            tags = _get_json(f"{endpoint}/api/tags")
            manifest = next(
                ({"name": item.get("name"), "digest": item.get("digest"), "modified_at": item.get("modified_at"), "size": item.get("size")}
                 for item in tags.get("models") or [] if isinstance(item, dict) and item.get("name") == model),
                None,
            )
        except Exception:
            manifest = None
        body = _post_json(
            f"{endpoint}/api/generate",
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "keep_alive": keep_alive,
                # Structured case runs need an answer, not a reasoning-only
                # completion. Newer Qwen/Ollama combinations otherwise return
                # an empty response after consuming the budget in `thinking`.
                "think": False,
                "options": {"temperature": 0.1, "num_ctx": context_tokens, "num_predict": max_output_tokens},
            },
            timeout=timeout,
        )
        text = str(body.get("response") or "")
        usage = {"prompt_tokens": body.get("prompt_eval_count"), "completion_tokens": body.get("eval_count")}
    elif provider in {"openai", "lmstudio", "vllm"}:
        external = provider == "openai"
        if external and not external_allowed:
            raise PermissionError("external_model_requires_explicit_approval")
        endpoint = {
            "openai": os.getenv("OPENAI_BASE_URL") or provider_config.get("url") or "https://api.openai.com/v1",
            "lmstudio": os.getenv("LM_STUDIO_URL") or provider_config.get("url") or "http://127.0.0.1:1234/v1",
            "vllm": os.getenv("VLLM_URL") or provider_config.get("url") or "http://127.0.0.1:8000/v1",
        }[provider].rstrip("/")
        key = (os.getenv("OPENAI_API_KEY") or provider_config.get("key")) if external else provider_config.get("key")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        body = _post_json(
            f"{endpoint}/chat/completions",
            {"model": model, "temperature": 0.1, "response_format": {"type": "json_object"}, "messages": [{"role": "system", "content": "Return only valid JSON. Never invent evidence."}, {"role": "user", "content": prompt}]},
            headers=headers,
        )
        text = str((((body.get("choices") or [{}])[0]).get("message") or {}).get("content") or "")
        usage = body.get("usage") or {}
    elif provider == "anthropic":
        if not external_allowed:
            raise PermissionError("external_model_requires_explicit_approval")
        key = os.getenv("ANTHROPIC_API_KEY") or provider_config.get("key")
        if not key:
            raise RuntimeError("anthropic_secret_not_configured")
        body = _post_json(
            f"{(os.getenv('ANTHROPIC_BASE_URL') or provider_config.get('url') or 'https://api.anthropic.com').rstrip('/')}/v1/messages",
            {"model": model, "max_tokens": 2500, "temperature": 0.1, "system": "Return only valid JSON. Never invent evidence.", "messages": [{"role": "user", "content": prompt}]},
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        )
        text = "".join(str(item.get("text") or "") for item in (body.get("content") or []) if item.get("type") == "text")
        usage = body.get("usage") or {}
    else:
        raise ValueError("unsupported_model_provider")
    metadata = {"latency_ms": int((time.perf_counter() - started) * 1000), "usage": usage}
    if provider == "ollama":
        metadata["model_manifest"] = manifest
        metadata["context_tokens_requested"] = context_tokens
        metadata["max_output_tokens_requested"] = max_output_tokens
    return text, metadata


def run_case_model(
    provider: str,
    model: str,
    prompt: str,
    *,
    external_allowed: bool = False,
    provider_config: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Execute one model run with a small provider-level circuit breaker."""

    key = provider.lower().strip()
    _breaker_before(key)
    try:
        result = _run_case_model_once(
            provider, model, prompt,
            external_allowed=external_allowed,
            provider_config=provider_config,
        )
    except Exception:
        _breaker_failure(key)
        raise
    _breaker_success(key)
    return result


__all__ = ["ModelRunStore", "run_case_model"]
