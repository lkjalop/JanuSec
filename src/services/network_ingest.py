from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional

from src.api.runtime_state import EVENT_QUEUE, get_server_runtime_state
from src.collectors.netflow_listener import NetFlowListener
from src.collectors.syslog_listener import SyslogListener
from src.services.network_config import load_network_config
from src.services.network_highlights import get_network_highlights_aggregator

logger = logging.getLogger(__name__)


class NetworkIngestService:
    def __init__(self, app) -> None:
        self.app = app
        cfg = load_network_config()
        self.syslog_listener = SyslogListener(cfg.get('syslog'), event_callback=self._handle_syslog_event, health_callback=self._record_health)
        self.netflow_listener = NetFlowListener(cfg.get('netflow'), event_callback=self._handle_netflow_events, health_callback=self._record_health)
        self._tasks: List[asyncio.Task] = []
        self._highlights = get_network_highlights_aggregator()

    async def start(self) -> None:
        await self.syslog_listener.start()
        await self.netflow_listener.start()

    async def stop(self) -> None:
        await self.syslog_listener.stop()
        await self.netflow_listener.stop()

    def _record_health(self, tenant: str, connector: str, count: int) -> None:
        try:
            runtime = get_server_runtime_state(self.app)
            tmap = runtime.tenants.setdefault(tenant, {})
            health = tmap.setdefault('network_connector_health', {})
            entry = health.setdefault(connector, {'total_ingested': 0})
            entry['last_event_ts'] = time.time()
            entry['last_event_count'] = count
            entry['total_ingested'] = entry.get('total_ingested', 0) + count
            # Heartbeat: record freshness for netflow/syslog connectors
            try:
                from src.core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
            except Exception:
                try:
                    from core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
                except Exception:
                    _hb_update = None  # type: ignore
            if _hb_update and count:
                try:
                    cid = (connector or '').lower()
                    if 'netflow' in cid or 'ipfix' in cid:
                        _hb_update('netflow')
                    elif 'syslog' in cid:
                        _hb_update('firewall')
                except Exception:
                    pass
        except Exception:
            logger.exception('Failed to record network health for tenant=%s connector=%s', tenant, connector)

    def _handle_syslog_event(self, tenant: str, connector: str, normalized: Dict[str, Any], raw: Dict[str, Any]) -> None:
        try:
            self._highlights.add_syslog_event(tenant, normalized)
        except Exception:
            logger.exception('Failed to record syslog highlight for tenant=%s', tenant)
        event = {
            'type': 'network_syslog_event',
            'tenant': tenant,
            'source': connector,
            'domain': 'network',
            'event': normalized,
            'raw': raw,
            'persona_tags': ['soc_analyst', 'threat_hunter', 'executive'],
        }
        self._enqueue_event(event)

    def _handle_netflow_events(self, tenant: str, connector: str, flows: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
        for flow in flows:
            try:
                self._highlights.add_netflow_event(tenant, flow)
            except Exception:
                logger.exception('Failed to record netflow highlight for tenant=%s', tenant)
            event = {
                'type': 'network_flow_event',
                'tenant': tenant,
                'source': connector,
                'domain': 'network',
                'event': flow,
                'raw': meta,
                'persona_tags': ['soc_analyst', 'threat_hunter'],
            }
            self._enqueue_event(event)

    def _enqueue_event(self, payload: Dict[str, Any]) -> None:
        queue = EVENT_QUEUE
        try:
            if hasattr(queue, 'enqueue'):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(queue.enqueue(payload))
                except RuntimeError:
                    asyncio.run(queue.enqueue(payload))  # pragma: no cover
            elif hasattr(queue, 'enqueue_event'):
                queue.enqueue_event(payload)
            elif hasattr(queue, 'put_nowait'):
                queue.put_nowait(payload)
        except Exception:
            logger.exception('Failed to enqueue network payload')


def register_network_service(app) -> Optional[NetworkIngestService]:
    if os.getenv('ENABLE_NETWORK_LISTENERS', '0').lower() not in {'1', 'true', 'yes'}:
        return None
    service = NetworkIngestService(app)

    async def _start() -> None:
        await service.start()

    async def _stop() -> None:
        await service.stop()

    try:
        app.add_event_handler('startup', lambda: asyncio.create_task(_start()))
        app.add_event_handler('shutdown', lambda: asyncio.create_task(_stop()))
        logger.info('Network ingest service registered (listeners enabled)')
    except Exception:
        logger.exception('Failed to register network ingest service')
    return service


__all__ = ['NetworkIngestService', 'register_network_service']
