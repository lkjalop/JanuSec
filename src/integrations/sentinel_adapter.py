"""Microsoft Sentinel connector implementing ConnectorBase with a stub.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from .connector_base import ConnectorBase


class SentinelAdapter(ConnectorBase):
    def __init__(self, *, tenant: str | None = None):
        self._enabled = True
        self._last_sync = None
        self._error = None
        self._tenant = tenant or 'default'
        self._cursor = None

    async def connect(self) -> None:
        self._enabled = True

    async def fetch_since(self, cursor: str | None, *, limit: int = 200) -> Tuple[List[Dict[str, Any]], str | None]:
        import os
        if 'PYTEST_CURRENT_TEST' not in os.environ:
            raise RuntimeError(
                'SentinelAdapter.fetch_since is a test fixture only. '
                'Use a real Microsoft Sentinel connector for production.'
            )
        now = time.time()
        ev = ConnectorBase.canonical_event(
            source='sentinel', tenant=self._tenant, event_type='incident', host='host-s1', raw={'id': 'se-1'}
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
            'source': 'sentinel'
        }

    def supported_event_types(self) -> List[str]:
        return ['incident']
