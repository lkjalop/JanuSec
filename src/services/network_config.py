from __future__ import annotations

import json
import ipaddress
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(os.getenv('NETWORK_SOURCES_PATH', 'artifacts/config/syslog_sources.json'))


def _default_config() -> Dict[str, Any]:
    return {
        'syslog': {
            'listeners': [{'host': '0.0.0.0', 'port': 514, 'protocol': 'udp'}],
            'sources': [{'tenant': 'default', 'cidrs': ['0.0.0.0/0'], 'connector_id': 'syslog_udp', 'eps_limit': 200, 'burst': 400}],
        },
        'netflow': {
            'listeners': [{'host': '0.0.0.0', 'port': 2055}],
            'sources': [{'tenant': 'default', 'cidrs': ['0.0.0.0/0'], 'connector_id': 'netflow', 'eps_limit': 1000, 'burst': 2000}],
        },
    }


def load_network_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return _default_config()
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return data
    except Exception:
        logger.warning('Failed to parse %s; falling back to default network config', CONFIG_PATH, exc_info=True)
    return _default_config()


@dataclass
class SourceEntry:
    tenant: str
    connector_id: str
    shared_secret: Optional[str]
    eps_limit: float
    burst: int
    extra: Dict[str, Any]
    network: ipaddress._BaseNetwork


class TenantSourceRegistry:
    def __init__(self, sources: Iterable[Dict[str, Any]], default_connector: str) -> None:
        self.entries: List[SourceEntry] = []
        for src in sources or []:
            tenant = src.get('tenant') or 'default'
            connector = src.get('connector_id') or default_connector
            shared_secret = src.get('shared_secret')
            eps_limit = float(src.get('eps_limit') or 200.0)
            burst = int(src.get('burst') or max(200, int(eps_limit * 2)))
            cidrs = src.get('cidrs') or []
            for raw in cidrs:
                try:
                    network = ipaddress.ip_network(raw, strict=False)
                except Exception:
                    logger.warning('Invalid CIDR %s for tenant %s connector %s', raw, tenant, connector)
                    continue
                entry = SourceEntry(
                    tenant=tenant,
                    connector_id=connector,
                    shared_secret=shared_secret,
                    eps_limit=eps_limit,
                    burst=burst,
                    extra={k: v for k, v in src.items() if k not in {'tenant', 'connector_id', 'shared_secret', 'eps_limit', 'burst', 'cidrs'}},
                    network=network,
                )
                self.entries.append(entry)
        if not self.entries:
            # ensure at least a default catch-all
            entry = SourceEntry(
                tenant='default',
                connector_id=default_connector,
                shared_secret=None,
                eps_limit=200.0,
                burst=400,
                extra={},
                network=ipaddress.ip_network('0.0.0.0/0'),
            )
            self.entries.append(entry)

    def match(self, ip: str) -> SourceEntry:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            addr = None
        for entry in self.entries:
            if addr is None or addr in entry.network:
                return entry
        return self.entries[0]


__all__ = ['CONFIG_PATH', 'load_network_config', 'TenantSourceRegistry', 'SourceEntry']
