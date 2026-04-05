from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import List, Optional

from src.collectors.email.utils import forward_normalized_events
from src.connectors.email.common import EmailConnectorError
from src.connectors.email.microsoft_graph_defender import DefenderConnector, GraphConfig
from src.integrations.auth.token_store import TokenStore
from src.integrations.tenant_store import TenantStore
from src.schemas.email import NormalizedEmailEvent

logger = logging.getLogger(__name__)


class DefenderCollector:
    POLL_INTERVAL = int(os.getenv("DEFENDER_POLL_INTERVAL", "300"))

    def __init__(
        self,
        tenant_id: str,
        *,
        graph_config: Optional[GraphConfig] = None,
        token_store: Optional[TokenStore] = None,
        connector: Optional[DefenderConnector] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self._store = tenant_store or TenantStore()
        self._token_store = token_store or TokenStore()
        self._cfg = graph_config or self._config_from_env()
        if connector is None:
            self._connector = DefenderConnector(self._cfg, self._token_store)
        else:
            self._connector = connector
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None

    def _config_from_env(self) -> GraphConfig:
        tenant = os.getenv("DEFENDER_TENANT_ID")
        client_id = os.getenv("DEFENDER_CLIENT_ID")
        client_secret = os.getenv("DEFENDER_CLIENT_SECRET")
        if not (tenant and client_id and client_secret):
            raise EmailConnectorError("Defender tenant/client credentials must be configured")
        scope = os.getenv("DEFENDER_SCOPE", GraphConfig.scope)
        base = os.getenv("DEFENDER_GRAPH_BASE", GraphConfig.graph_base)
        cfg = GraphConfig(tenant_id=tenant, client_id=client_id, client_secret=client_secret, scope=scope, graph_base=base)
        return cfg

    async def poll_alerts(self) -> List[NormalizedEmailEvent]:
        filter_query = os.getenv("DEFENDER_FILTER_QUERY")
        top = int(os.getenv("DEFENDER_FETCH_LIMIT", "100"))
        try:
            alerts = await self._connector.fetch_security_alerts(
                self.tenant_id,
                top=top,
                filter_query=filter_query,
            )
            self._last_poll_ts = int(time.time())
            self._last_error = None
            return alerts
        except Exception as exc:  # pragma: no cover - network/runtime failure
            self._last_error = str(exc)
            logger.exception("Defender poll failure")
            return []

    async def forward_to_ingest(self, events: List[NormalizedEmailEvent]) -> int:
        sent = await forward_normalized_events(
            self.tenant_id,
            events,
            source="defender",
            batch_env_prefix="DEFENDER",
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
                logger.exception("Defender collector loop error")
            await asyncio.sleep(poll_interval)

    def health_snapshot(self) -> dict:
        return {
            "tenant": self.tenant_id,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }


__all__ = ["DefenderCollector"]
