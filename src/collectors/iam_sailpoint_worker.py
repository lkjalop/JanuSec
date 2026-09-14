from __future__ import annotations

"""SailPoint IdentityNow connector."""

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


class SailPointCollector:
    def __init__(
        self,
        tenant_id: str,
        *,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        http_client: Optional[Any] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.base_url = base_url or os.getenv("SAILPOINT_BASE_URL")
        self.client_id = client_id or os.getenv("SAILPOINT_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("SAILPOINT_CLIENT_SECRET")
        self._store = tenant_store or TenantStore()
        self._http_client = http_client
        self._cursor = self._store.load_cursor(tenant_id, "sailpoint", "event_cursor")
        self._token: Optional[str] = None
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None
        self._metrics_path = Path(os.getenv("SAILPOINT_IAM_RUN_LOG", "logs/collectors/sailpoint_iam/run.log"))

    # ------------------------------------------------------------- HTTP helpers
    async def _http_post(self, url: str, **kwargs: Any):
        if self._http_client is not None:
            return await self._http_client.post(url, **kwargs)
        if httpx is None:
            raise RuntimeError("httpx_unavailable")
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.post(url, **kwargs)

    async def _http_get(self, url: str, **kwargs: Any):
        if self._http_client is not None:
            return await self._http_client.get(url, **kwargs)
        if httpx is None:
            raise RuntimeError("httpx_unavailable")
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.get(url, **kwargs)

    def _record_metrics(self, action: str, meta: Dict[str, Any]) -> None:
        payload = {"ts": int(time.time()), "tenant": self.tenant_id, "action": action, **meta}
        try:
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with self._metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload) + "\n")
        except Exception:
            LOGGER.debug("Failed to write SailPoint metrics", exc_info=True)

    # ------------------------------------------------------------------- token
    async def _ensure_token(self) -> Optional[str]:
        if self._token:
            return self._token
        if not all([self.base_url, self.client_id, self.client_secret]):
            return None
        token_url = f"{self.base_url.rstrip('/')}/oauth/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        resp = await self._http_post(token_url, data=data)
        resp.raise_for_status()
        payload = resp.json()
        self._token = payload.get("access_token")
        return self._token

    # ----------------------------------------------------------------- polling
    async def poll_events(self) -> List[Dict[str, Any]]:
        self._last_poll_ts = int(time.time())
        if self._http_client is None and httpx is None:
            LOGGER.warning("httpx not installed; SailPoint collector inactive")
            return []
        token = await self._ensure_token()
        if not token:
            LOGGER.warning("SailPoint credentials missing; collector inactive")
            return []
        params = {"limit": 200}
        if self._cursor:
            params["cursor"] = self._cursor
        url = f"{self.base_url.rstrip('/')}/beta/events"
        try:
            resp = await self._http_get(url, headers={"Authorization": f"Bearer {token}"}, params=params)
            resp.raise_for_status()
            payload = resp.json()
            events = [self._normalize_event(item) for item in payload.get("data", []) or []]
            next_cursor = payload.get("nextCursor")
            if next_cursor:
                self._cursor = next_cursor
                self._store.save_cursor(self.tenant_id, "sailpoint", "event_cursor", next_cursor)
            self._last_error = None
            self._record_metrics("poll", {"event_count": len(events), "status": "ok"})
            return events
        except Exception as exc:
            self._last_error = str(exc)
            LOGGER.exception("SailPoint poll failure")
            self._record_metrics("poll", {"event_count": 0, "status": "error"})
            return []

    # -------------------------------------------------------------- forwarding
    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        base = os.getenv("API_BASE_URL", "http://localhost:8080")
        api_key = os.getenv("API_KEY")
        url = f"{base.rstrip('/')}/api/v1/iam/ingest/sailpoint"
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
            LOGGER.exception("Failed to forward SailPoint events")
            self._record_metrics("forward", {"event_count": len(events), "status": "error"})
            return 0

    async def forward_to_stream(self, events: List[Dict[str, Any]]) -> int:
        """Emit events to the streaming ingest API when JANUSEC_STREAMING_MODE is active."""
        if not events:
            return 0
        try:
            from src.connectors.stream_emitter import emit_to_stream
            result = await emit_to_stream(events, source='sailpoint')
            count = result.get('accepted', 0)
            self._last_forward_count = count
            self._record_metrics("stream_forward", {"event_count": count, "status": "ok"})
            return count
        except Exception:
            self._last_error = "stream_forward_failed"
            LOGGER.exception("Failed to stream-forward SailPoint events")
            self._record_metrics("stream_forward", {"event_count": len(events), "status": "error"})
            return 0

    # ------------------------------------------------------------------- loop
    async def start_loop(self, interval_seconds: Optional[int] = None) -> None:
        interval = interval_seconds or int(os.getenv("SAILPOINT_POLL_INTERVAL", "600"))
        streaming = os.getenv('JANUSEC_STREAMING_MODE', '').lower() in ('1', 'true', 'yes')
        while True:
            try:
                events = await self.poll_events()
                if events:
                    if streaming:
                        await self.forward_to_stream(events)
                    else:
                        await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover
                LOGGER.exception("SailPointCollector loop error")
            await asyncio.sleep(interval)

    # ---------------------------------------------------------------- health
    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "base_url": self.base_url,
            "cursor": bool(self._cursor),
            "token_present": bool(self._token),
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }

    @staticmethod
    def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": event.get("created"),
            "eventType": event.get("type"),
            "actor": event.get("actor", {}).get("name"),
            "target": event.get("target", {}).get("name"),
            "operation": event.get("operation"),
            "raw": event,
        }


__all__ = ["SailPointCollector"]
