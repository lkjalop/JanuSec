"""Splunk connector implementing ConnectorBase with a stubbed polling flow.

This keeps the current deterministic event for tests while providing
cursor/health interfaces. Upgrade later to real HEC/SavedSearch integration.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from .connector_base import ConnectorBase


class SplunkAdapter(ConnectorBase):
    def __init__(self, *, tenant: str | None = None):
        self._enabled = True
        self._last_sync = None
        self._error = None
        self._tenant = tenant or 'default'
        self._cursor = None

    async def connect(self) -> None:
        # Stub: nothing to do yet
        self._enabled = True

    async def fetch_since(self, cursor: str | None, *, limit: int = 200) -> Tuple[List[Dict[str, Any]], str | None]:
        # Stubbed: return one synthetic event and advance cursor once
        now = time.time()
        ev = ConnectorBase.canonical_event(
            timestamp=None,
            source='splunk',
            tenant=self._tenant,
            event_type='notable',
            host='host-splunk-1',
            user='bob',
            process_name='cmd.exe',
            raw={'id': 'sp-1'}
        )
        self._last_sync = now
        next_cursor = str(int(now)) if cursor != str(int(now)) else None
        return [ev], next_cursor

    async def ack(self, cursor: str) -> None:
        # Record last acknowledged cursor
        self._cursor = cursor

    async def health(self) -> Dict[str, Any]:
        return {
            'enabled': self._enabled,
            'last_sync': self._last_sync,
            'error': self._error,
            'cursor': self._cursor,
            'source': 'splunk'
        }

    def supported_event_types(self) -> List[str]:
        return ['notable']
