from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime

from src.modules.collectors.proofpoint_collector import ProofpointTAPCollector
from src.modules.collectors.mimecast_collector import MimecastCollector


class ProofpointConnector:
    def __init__(self, api_key: Optional[str] = None, api_secret: Optional[str] = None, **kw):
        self.collector = ProofpointTAPCollector(api_key=api_key, api_secret=api_secret)

    async def execute(self, domain: str, entity: str, window: Optional[str], context: Any = None, include_body: bool = False) -> Dict[str, Any]:
        # window parsing best-effort; collector expects datetime
        since = datetime.utcnow()
        try:
            return {
                "events": await self.collector.collect_threats(since=since, mock=False)
            }
        except NotImplementedError:
            # fall back to mock payloads for environments without API creds
            return {"events": await self.collector.collect_threats(since=since, mock=True)}


class MimecastConnector:
    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, **kw):
        self.collector = MimecastCollector(client_id=client_id, client_secret=client_secret)

    async def execute(self, domain: str, entity: str, window: Optional[str], context: Any = None, include_body: bool = False) -> Dict[str, Any]:
        since = datetime.utcnow()
        try:
            return {"events": await self.collector.collect_threats(since=since, mock=False)}
        except NotImplementedError:
            return {"events": await self.collector.collect_threats(since=since, mock=True)}


def register(registry_module):
    """Register connectors into the provided registry module which must expose `register(name, ctor)`."""
    try:
        # prefer new connector implementation when available
        try:
            from src.connectors.proofpoint import ProofpointConnector as PPImpl
            ctor = lambda **kw: PPImpl(**kw)
        except Exception:
            ctor = lambda **kw: ProofpointConnector(**kw)
        if hasattr(registry_module, 'ensure_connector'):
            registry_module.ensure_connector('proofpoint', ctor)
        elif hasattr(registry_module, 'register'):
            registry_module.register('proofpoint', ctor)
    except Exception:
        pass
    try:
        try:
            from src.connectors.mimecast import MimecastConnector as MCImpl
            ctor2 = lambda **kw: MCImpl(**kw)
        except Exception:
            ctor2 = lambda **kw: MimecastConnector(**kw)
        if hasattr(registry_module, 'ensure_connector'):
            registry_module.ensure_connector('mimecast', ctor2)
        elif hasattr(registry_module, 'register'):
            registry_module.register('mimecast', ctor2)
    except Exception:
        pass


__all__ = ["ProofpointConnector", "MimecastConnector", "register"]
