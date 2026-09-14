"""Connector SDK: base interfaces, errors, HTTP helpers, and policies.

Provides a standard contract for connectors:
- `BaseConnector.execute(domain, entity, window, context)` returning typed result
- `estimate_cost_usd(...)` cost hints
- Cache-key and TTL guidance via `cache_key()` and `cache_ttl_seconds()`
- Resilient HTTP helper with retries/backoff and egress allow-list enforcement
- Rate limiting hooks via a simple token-bucket interface
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import httpx  # type: ignore
except Exception:
    httpx = None  # type: ignore

try:
    from src.core.rate_limit import TokenBucketLimiter
except Exception:
    TokenBucketLimiter = None  # type: ignore


class ConnectorError(Exception):
    pass


class BackoffError(ConnectorError):
    pass


class EgressPolicyError(ConnectorError):
    pass


@dataclass
class ConnectorContext:
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    allow_hosts: Optional[set[str]] = None
    rate_key: Optional[str] = None


class BaseConnector:
    name: str = "base"

    def __init__(self, *, rate_limiter: Any | None = None, allow_hosts: set[str] | None = None):
        self._rate = rate_limiter
        self._hosts = allow_hosts or set()

    async def execute(self, domain: str, entity: str, window: Optional[str] = None, context: ConnectorContext | None = None) -> Dict[str, Any]:
        raise NotImplementedError

    def estimate_cost_usd(self, domain: str, entity: str, window: Optional[str] = None) -> float:
        return 0.0

    def cache_key(self, domain: str, entity: str, window: Optional[str] = None) -> str:
        w = window or ""
        return f"{self.name}|{domain}|{entity}|{w}"

    def cache_ttl_seconds(self) -> int:
        return 600

    async def _rate_limit(self, key: str, *, tokens: float = 1.0) -> None:
        if self._rate is None:
            return
        try:
            await self._rate.consume(key, tokens=tokens)
        except Exception as exc:
            raise BackoffError(str(exc))

    def _check_egress_host(self, host: str) -> None:
        if self._hosts and host not in self._hosts:
            raise EgressPolicyError(f"egress host not allowed: {host}")


async def http_get(url: str, *, headers: Dict[str, str] | None = None, allow_hosts: set[str] | None = None,
                   attempts: int = 5, base_delay: float = 0.05, max_delay: float = 1.0, jitter: float = 0.1) -> tuple[int, bytes, Dict[str, Any]]:
    if httpx is None:
        raise ConnectorError("httpx not available")
    # Enforce allow-list
    try:
        import urllib.parse as _up
        host = _up.urlsplit(url).hostname or ""
        if allow_hosts and host not in allow_hosts:
            raise EgressPolicyError(f"egress host not allowed: {host}")
    except Exception:
        pass
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers or {})
                return resp.status_code, resp.content or b"", dict(resp.headers)
        except Exception as exc:
            last_err = exc
            if attempt == attempts:
                raise ConnectorError(str(exc))
            # backoff
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay *= (1 + jitter)
            await asyncio.sleep(delay)
    raise ConnectorError(str(last_err) if last_err else "http_get failed")
