from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Protocol

try:
    import httpx
except Exception:  # pragma: no cover - httpx always installed in prod image
    httpx = None  # type: ignore

LOGGER = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 30.0


class HttpResponseProtocol(Protocol):
    status_code: int
    headers: Dict[str, Any]

    def json(self) -> Any: ...

    @property
    def text(self) -> str: ...


class HttpClientProtocol(Protocol):
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponseProtocol: ...


class EmailConnectorError(RuntimeError):
    """Generic connector error."""


class RateLimitError(EmailConnectorError):
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


def ensure_async_client(base_url: str) -> httpx.AsyncClient:
    if httpx is None:
        raise EmailConnectorError("httpx not installed; provide custom http_client")
    return httpx.AsyncClient(base_url=base_url, timeout=DEFAULT_TIMEOUT)


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if isinstance(value, str):
        val = value.strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val.replace("Z", ""), fmt)
            except Exception:
                continue
    return datetime.utcnow()


def extract_domain(addr: Optional[str]) -> Optional[str]:
    if not addr or "@" not in addr:
        return None
    return addr.split("@")[-1].strip().lower() or None


async def json_or_error(response: HttpResponseProtocol) -> Dict[str, Any]:
    if response.status_code == 204:
        return {}
    if response.status_code >= 400:
        text = ""
        try:
            text = response.text
        except Exception:
            pass
        try:
            payload = response.json()
            text = text or json.dumps(payload)[:512]
        except Exception:
            payload = {}
        if response.status_code == 429:
            retry = None
            retry_hdr = response.headers.get("Retry-After") if response.headers else None
            try:
                retry = float(retry_hdr) if retry_hdr else None
            except Exception:
                retry = None
            raise RateLimitError(f"email connector rate limited ({text})", retry_after=retry)
        raise EmailConnectorError(f"email connector HTTP {response.status_code}: {text}")
    try:
        return response.json()
    except Exception as exc:  # pragma: no cover - httpx handles json
        raise EmailConnectorError(f"invalid JSON response: {exc}")


def backoff_delay(attempt: int, base: float = 0.5, cap: float = 8.0) -> float:
    delay = min(cap, base * (2 ** (attempt - 1)))
    jitter = 0.1 * delay
    return max(0.05, delay + jitter)


async def with_retry(
    func,
    *,
    max_attempts: int = 3,
    retry_exceptions: tuple[type[Exception], ...] = (RateLimitError, EmailConnectorError),
) -> Any:
    attempt = 1
    while True:
        try:
            return await func()
        except retry_exceptions as exc:
            if attempt >= max_attempts:
                raise
            delay = backoff_delay(attempt)
            if isinstance(exc, RateLimitError) and exc.retry_after:
                delay = max(delay, exc.retry_after)
            LOGGER.debug("Retrying email connector call (attempt %s/%s) delay=%.2fs error=%s", attempt, max_attempts, delay, exc)
            await asyncio.sleep(delay)
            attempt += 1


__all__ = [
    "EmailConnectorError",
    "RateLimitError",
    "HttpClientProtocol",
    "HttpResponseProtocol",
    "ensure_async_client",
    "parse_timestamp",
    "extract_domain",
    "json_or_error",
    "with_retry",
]
