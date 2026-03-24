from __future__ import annotations

"""Duo Security IAM connector."""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.integrations.tenant_store import TenantStore

try:  # pragma: no cover
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

LOGGER = logging.getLogger(__name__)


class DuoCollector:
    def __init__(
        self,
        tenant_id: str,
        *,
        base_url: Optional[str] = None,
        integration_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        http_client: Optional[Any] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.base_url = base_url or os.getenv("DUO_BASE_URL", "https://api.duosecurity.com")
        self.integration_key = integration_key or os.getenv("DUO_IKEY")
        self.secret_key = secret_key or os.getenv("DUO_SKEY")
        self._http_client = http_client
        self._store = tenant_store or TenantStore()
        self._since_ts = self._store.load_cursor(tenant_id, "duo", "since_ts")
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None
        self._metrics_path = Path(os.getenv("DUO_IAM_RUN_LOG", "logs/collectors/duo_iam/run.log"))

    async def _http_get(self, url: str, **kwargs: Any):
        if self._http_client is not None:
            return await self._http_client.get(url, **kwargs)
        if httpx is None:
            raise RuntimeError("httpx_unavailable")
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.get(url, **kwargs)

    async def _http_post(self, url: str, **kwargs: Any):
        if self._http_client is not None:
            return await self._http_client.post(url, **kwargs)
        if httpx is None:
            raise RuntimeError("httpx_unavailable")
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.post(url, **kwargs)

    def _record_metrics(self, action: str, meta: Dict[str, Any]) -> None:
        payload = {"ts": int(time.time()), "tenant": self.tenant_id, "action": action, **meta}
        try:
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with self._metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload) + "\n")
        except Exception:
            LOGGER.debug("Failed to write Duo metrics", exc_info=True)

    async def poll_events(self) -> List[Dict[str, Any]]:
        self._last_poll_ts = int(time.time())
        if self._http_client is None and httpx is None:
            LOGGER.warning("httpx unavailable; Duo collector inactive")
            return []
        if not all([self.integration_key, self.secret_key]):
            LOGGER.warning("Duo credentials missing; collector inactive")
            return []
        params = {"limit": 300}
        if self._since_ts:
            params["mintime"] = self._since_ts
        url = f"{self.base_url.rstrip('/')}/admin/v1/logs/authentication"
        auth = (self.integration_key, self.secret_key)
        try:
            resp = await self._http_get(url, auth=auth, params=params)
            resp.raise_for_status()
            payload = resp.json()
            events = [self._normalize_event(item) for item in payload.get("authlogs") or payload.get("response", [])]
            if events:
                newest = max(e["timestamp"] for e in events if e.get("timestamp"))
                self._since_ts = newest
                self._store.save_cursor(self.tenant_id, "duo", "since_ts", str(newest))
            self._last_error = None
            self._record_metrics("poll", {"event_count": len(events), "status": "ok"})
            return events
        except Exception as exc:
            self._last_error = str(exc)
            LOGGER.exception("Duo poll failure")
            self._record_metrics("poll", {"event_count": 0, "status": "error"})
            return []

    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        base = os.getenv("API_BASE_URL", "http://localhost:8080")
        api_key = os.getenv("API_KEY")
        url = f"{base.rstrip('/')}/api/v1/iam/ingest/duo"
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}
        try:
            resp = await self._http_post(url, headers=headers, json={"events": events})
            if hasattr(resp, "raise_for_status"):
                resp.raise_for_status()
            count = len(events)
            self._last_forward_count = count
            self._record_metrics("forward", {"event_count": count, "status": "ok"})
            return count
        except Exception:
            self._last_error = "forward_failed"
            LOGGER.exception("Duo forward failure")
            self._record_metrics("forward", {"event_count": len(events), "status": "error"})
            return 0

    async def start_loop(self, interval_seconds: Optional[int] = None) -> None:
        interval = interval_seconds or int(os.getenv("DUO_POLL_INTERVAL", "600"))
        while True:
            try:
                events = await self.poll_events()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover
                LOGGER.exception("DuoCollector loop error")
            await asyncio.sleep(interval)

    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "since_ts": self._since_ts,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }

    @staticmethod
    def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": event.get("timestamp") or event.get("time"),
            "username": event.get("username"),
            "ip": event.get("ip_address"),
            "result": event.get("result"),
            "factor": event.get("factor") or event.get("auth_device"),
            "raw": event,
        }


__all__ = ["DuoCollector"]
