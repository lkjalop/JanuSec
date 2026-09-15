from __future__ import annotations

from typing import Any, Optional
import asyncio
import hashlib
import json
import logging
from abc import ABC, abstractmethod

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

LOG = logging.getLogger(__name__)


class SandboxProvider(ABC):
    """Base class for sandbox providers.

    Subclasses should implement `_submit_file`, `_submit_url` and `_fetch_report`.
    This base implements an async HTTP client, basic retries, and idempotency helpers.
    """

    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional["httpx.AsyncClient"] = None

    async def _get_client(self):
        if httpx is None:
            raise RuntimeError("httpx is required for sandbox HTTP operations")
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _content_hash_header(self, data: bytes) -> dict[str, str]:
        """Return idempotency header based on content hash."""
        h = hashlib.sha256(data).hexdigest()
        return {"Idempotency-Key": h}

    async def _do_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Perform an HTTP request with simple retry/backoff."""
        client = await self._get_client()
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                return resp
            except Exception as exc:  # pragma: no cover - runtime network errors
                last_exc = exc
                wait = min(2 ** attempt, 8)
                LOG.debug("HTTP request failed (attempt %s) to %s: %s; retry in %ss", attempt, url, exc, wait)
                await asyncio.sleep(wait)

        # If we exhausted retries, raise the last exception
        LOG.error("HTTP request failed after %s attempts to %s: %s", self.max_retries, url, last_exc)
        raise last_exc

    @abstractmethod
    async def submit(self, file_bytes: bytes | None, filename: str | None, url: str | None) -> str:
        """Submit a file or URL for analysis and return a task id."""

    @abstractmethod
    async def result(self, task_id: str) -> dict[str, Any] | None:
        """Return a normalized analysis result or None if still pending."""


def normalize_output(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize sandbox output to expected schema.

    Returns a dict with keys: summary, iocs{domains, ips, hashes, urls}, mitre[list], factors[list]
    """
    # Attempt to extract IOCs from common shapes
    iocs = raw.get("iocs") or {}
    # Some sandboxes embed iocs under 'indicators' or 'ioc'
    if not iocs:
        iocs = raw.get("indicators") or raw.get("ioc") or {}

    domains = list(iocs.get("domains") or iocs.get("domains_list") or [])
    ips = list(iocs.get("ips") or iocs.get("ip_list") or [])
    hashes = list(iocs.get("hashes") or iocs.get("hash_list") or [])
    urls = list(iocs.get("urls") or iocs.get("url_list") or [])

    # Map sandbox verdicts to normalized severity/factors
    verdict = (raw.get("verdict") or raw.get("summary") or "").lower()
    factors = list(raw.get("factors") or [])
    mitre = list(raw.get("mitre") or [])

    if "ransom" in verdict or "ransomware" in verdict:
        factors.append("sandbox:ransomware")
        mitre.append("T1486")
    if "suspicious" in verdict:
        factors.append("sandbox:suspicious")
    if "inject" in verdict or "injection" in verdict:
        factors.append("sandbox:process_injection")
        mitre.append("T1055")

    # Behavior-driven MITRE hints
    behaviors = raw.get("behaviors") or raw.get("behavioral_summary") or []
    for b in behaviors:
        bl = b.lower()
        if "process injection" in bl or "inject" in bl:
            if "T1055" not in mitre:
                mitre.append("T1055")
        if "powershell" in bl and "T1059.001" not in mitre:
            mitre.append("T1059.001")

    return {
        "summary": raw.get("summary") or raw.get("verdict") or "analysis complete",
        "iocs": {
            "domains": domains,
            "ips": ips,
            "hashes": hashes,
            "urls": urls,
        },
        "mitre": mitre,
        "factors": factors,
        "verdict": verdict,
    }

