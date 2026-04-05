from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import List, Optional

from src.connectors.email.common import EmailConnectorError
from src.connectors.email.mimecast import MimecastConfig, MimecastConnector
from src.collectors.email.utils import forward_normalized_events
from src.integrations.auth.token_store import TokenStore
from src.integrations.tenant_store import TenantStore
from src.schemas.email import NormalizedEmailEvent

logger = logging.getLogger(__name__)


def _parse_cursor(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", ""))
    except Exception:
        return None


class MimecastCollector:
    """Background worker that reuses the async Mimecast connector and forwards results."""

    POLL_INTERVAL = int(os.getenv("MIMECAST_POLL_INTERVAL", "300"))

    def __init__(
        self,
        tenant_id: str,
        *,
        config: Optional[MimecastConfig] = None,
        token_store: Optional[TokenStore] = None,
        connector: Optional[MimecastConnector] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._store = tenant_store or TenantStore()
        self._token_store = token_store or TokenStore()
        self._cfg = config or MimecastConfig(
            base_url=os.getenv("MIMECAST_BASE_URL", MimecastConfig.base_url),
            token_endpoint=os.getenv("MIMECAST_TOKEN_ENDPOINT", MimecastConfig.token_endpoint),
            detections_endpoint=os.getenv("MIMECAST_DETECTIONS_ENDPOINT", MimecastConfig.detections_endpoint),
            client_id=os.getenv("MIMECAST_CLIENT_ID"),
            client_secret=os.getenv("MIMECAST_CLIENT_SECRET"),
        )
        self._connector = connector
        cursor = self._store.load_cursor(tenant_id, "mimecast", "sinceTime")
        self._cursor = _parse_cursor(cursor)
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None

    async def poll_detections(self) -> List[NormalizedEmailEvent]:
        if self._connector is None:
            if not (self._cfg.client_id and self._cfg.client_secret):
                raise EmailConnectorError("Mimecast client_id/client_secret must be configured")
            self._connector = MimecastConnector(self._cfg, self._token_store)
        since = self._cursor
        limit = int(os.getenv("MIMECAST_FETCH_LIMIT", "200"))
        try:
            events = await self._connector.fetch_detections(self.tenant_id, since=since, limit=limit)
            if events:
                latest = max(evt.timestamp for evt in events if isinstance(evt.timestamp, datetime))
                self._cursor = latest
                try:
                    self._store.save_cursor(self.tenant_id, "mimecast", "sinceTime", latest.isoformat())
                except Exception:
                    logger.debug("Failed to persist Mimecast cursor", exc_info=True)
            self._last_poll_ts = int(time.time())
            self._last_error = None
            return events
        except Exception as exc:  # pragma: no cover - network/runtime failure
            self._last_error = str(exc)
            logger.exception("Mimecast poll failure")
            return []

    async def forward_to_ingest(self, events: List[NormalizedEmailEvent]) -> int:
        sent = await forward_normalized_events(
            self.tenant_id,
            events,
            source="mimecast",
            batch_env_prefix="MIMECAST",
        )
        self._last_forward_count = sent
        return sent

    async def start_loop(self, interval: Optional[int] = None) -> None:
        poll_interval = interval or self.POLL_INTERVAL
        while True:
            try:
                events = await self.poll_detections()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover - guard against runaway loop failures
                logger.exception("Mimecast collector loop error")
            await asyncio.sleep(poll_interval)

    def health_snapshot(self) -> dict:
        return {
            "tenant": self.tenant_id,
            "cursor": self._cursor.isoformat() if self._cursor else None,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }


__all__ = ["MimecastCollector"]
