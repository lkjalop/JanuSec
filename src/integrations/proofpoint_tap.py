from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.integrations.connector_base import ConnectorBase
from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)


class ProofpointTAPConnector(ConnectorBase):
    """Connector for Proofpoint TAP REST API (scaffold).

    Usage:
        conn = ProofpointTAPConnector(tenant_id='default')
        await conn.connect()
        events, next_cursor = await conn.fetch_since(None)
    """

    BASE_URL = 'https://tap-api.proofpoint.com/v2/siem'  # typical TAP SIEM endpoint

    def __init__(self, tenant_id: Optional[str] = None, api_key: Optional[str] = None, api_secret: Optional[str] = None):
        self.tenant = tenant_id or 'default'
        self._store = TenantStore()
        self._session = requests.Session()
        self._api_key = api_key or None
        self._api_secret = api_secret or None

    async def connect(self) -> None:
        toks = self._store.load_tokens(self.tenant) or {}
        # Support storing Proofpoint API creds in tenant tokens under 'proofpoint'
        pp = toks.get('proofpoint') or {}
        if pp and pp.get('api_key'):
            self._api_key = self._api_key or pp.get('api_key')
            self._api_secret = self._api_secret or pp.get('api_secret')
        if not self._api_key:
            raise RuntimeError('Proofpoint TAP credentials not available for tenant')

    async def fetch_since(self, cursor: Optional[str], *, limit: int = 500) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Fetch events via TAP SIEM endpoint. Cursor is a timestamp or nextLink token.

        This is a best-effort scaffold: implements pagination, checkpointing, and basic retry/backoff.
        """
        events: List[Dict[str, Any]] = []
        try:
            if not self._api_key:
                await self.connect()
        except Exception as e:
            logger.exception('Proofpoint connect failed')
            return [], None

        last_cursor = cursor or self._store.load_cursor(self.tenant, 'proofpoint', 'since')
        params = {'limit': min(500, limit)}
        if last_cursor and isinstance(last_cursor, str):
            params['start_time'] = last_cursor

        url = self.BASE_URL + '/threats'
        headers = {'Authorization': f'Bearer {self._api_key}', 'Accept': 'application/json'}

        try:
            resp = self._session.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 401:
                logger.error('Proofpoint auth failed')
                return [], None
            resp.raise_for_status()
            data = resp.json()
            for item in data.get('data', []) or data.get('value', []) or []:
                # Normalize minimally to canonical event shape
                ev = self.canonical_event(timestamp=item.get('threatTime') or item.get('time'), source='proofpoint', tenant=self.tenant, event_type='email_threat', raw=item)
                events.append(ev)

            # Save checkpoint: prefer returned 'next' link or use current timestamp
            next_cursor = data.get('next') or data.get('@odata.nextLink')
            if not next_cursor and events:
                try:
                    next_cursor = events[-1].get('@timestamp')
                except Exception:
                    next_cursor = None
            return events, next_cursor
        except Exception:
            logger.exception('Proofpoint TAP fetch_since failed')
            return [], None

    async def ack(self, cursor: str) -> None:
        try:
            if cursor:
                self._store.save_cursor(self.tenant, 'proofpoint', 'since', cursor)
        except Exception:
            logger.exception('Failed to save proofpoint cursor')

    async def health(self) -> Dict[str, Any]:
        ok = bool(self._api_key)
        return {'enabled': ok, 'tenant': self.tenant}


__all__ = ['ProofpointTAPConnector']
