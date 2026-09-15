"""CrowdStrike connector implementing ConnectorBase with stubbed flow.

Upgrade later to real OAuth token flow and detections API.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from .connector_base import ConnectorBase


class CrowdStrikeAdapter(ConnectorBase):
    def __init__(self, *, tenant: str | None = None):
        self._enabled = True
        self._last_sync = None
        self._error = None
        self._tenant = tenant or 'default'
        self._cursor = None

    async def connect(self) -> None:
        self._enabled = True

    async def fetch_since(self, cursor: str | None, *, limit: int = 200) -> Tuple[List[Dict[str, Any]], str | None]:
        now = time.time()
        ev = ConnectorBase.canonical_event(
            source='crowdstrike', tenant=self._tenant, event_type='detection',
            host='host-cs-1', user='alice', process_name='mimikatz.exe', raw={'id': 'cs-1'}
        )
        self._last_sync = now
        next_cursor = str(int(now)) if cursor != str(int(now)) else None
        return [ev], next_cursor

    async def ack(self, cursor: str) -> None:
        self._cursor = cursor

    async def health(self) -> Dict[str, Any]:
        return {
            'enabled': self._enabled,
            'last_sync': self._last_sync,
            'error': self._error,
            'cursor': self._cursor,
            'source': 'crowdstrike'
        }

    def supported_event_types(self) -> List[str]:
        return ['detection']
