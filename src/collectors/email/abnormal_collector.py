from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import List, Optional

from src.collectors.email.utils import forward_normalized_events
from src.connectors.email.abnormal import AbnormalConfig, AbnormalConnector
from src.connectors.email.common import EmailConnectorError
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


class AbnormalCollector:
    POLL_INTERVAL = int(os.getenv("ABNORMAL_POLL_INTERVAL", "300"))

    def __init__(
        self,
        tenant_id: str,
        *,
        config: Optional[AbnormalConfig] = None,
        token_store: Optional[TokenStore] = None,
        connector: Optional[AbnormalConnector] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._store = tenant_store or TenantStore()
        self._token_store = token_store or TokenStore()
        self._cfg = config or AbnormalConfig(
            base_url=os.getenv("ABNORMAL_BASE_URL", AbnormalConfig.base_url),
            token_endpoint=os.getenv("ABNORMAL_TOKEN_ENDPOINT", AbnormalConfig.token_endpoint),
            alerts_endpoint=os.getenv("ABNORMAL_ALERTS_ENDPOINT", AbnormalConfig.alerts_endpoint),
            client_id=os.getenv("ABNORMAL_CLIENT_ID"),
            client_secret=os.getenv("ABNORMAL_CLIENT_SECRET"),
        )
        if connector is None:
            if not (self._cfg.client_id and self._cfg.client_secret):
                raise EmailConnectorError("Abnormal client_id/client_secret must be configured")
            self._connector = AbnormalConnector(self._cfg, self._token_store)
        else:
            self._connector = connector
        cursor = self._store.load_cursor(tenant_id, "abnormal", "createdAfter")
        self._cursor = _parse_cursor(cursor)
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None

    async def poll_alerts(self) -> List[NormalizedEmailEvent]:
        since = self._cursor
        severity = os.getenv("ABNORMAL_MIN_SEVERITY")
        try:
            alerts = await self._connector.fetch_alerts(
                self.tenant_id,
                since=since,
                limit=int(os.getenv("ABNORMAL_FETCH_LIMIT", "200")),
                severity=severity,
            )
            if alerts:
                latest = max(evt.timestamp for evt in alerts if isinstance(evt.timestamp, datetime))
                self._cursor = latest
                try:
                    self._store.save_cursor(self.tenant_id, "abnormal", "createdAfter", latest.isoformat())
                except Exception:
                    logger.debug("Failed to persist Abnormal cursor", exc_info=True)
            self._last_poll_ts = int(time.time())
            self._last_error = None
            return alerts
        except Exception as exc:  # pragma: no cover - network/runtime failure
            self._last_error = str(exc)
            logger.exception("Abnormal poll failure")
            return []

    async def forward_to_ingest(self, events: List[NormalizedEmailEvent]) -> int:
        sent = await forward_normalized_events(
            self.tenant_id,
            events,
            source="abnormal",
            batch_env_prefix="ABNORMAL",
        )
        self._last_forward_count = sent
        return sent

    async def start_loop(self, interval: Optional[int] = None) -> None:
        poll_interval = interval or self.POLL_INTERVAL
        while True:
            try:
                events = await self.poll_alerts()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover
                logger.exception("Abnormal collector loop error")
            await asyncio.sleep(poll_interval)

    def health_snapshot(self) -> dict:
        return {
            "tenant": self.tenant_id,
            "cursor": self._cursor.isoformat() if self._cursor else None,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }


__all__ = ["AbnormalCollector"]
