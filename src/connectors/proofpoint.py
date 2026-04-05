from __future__ import annotations

import os
import time
import asyncio
from typing import Any, Dict, Optional, List

from src.connectors.sdk import BaseConnector, ConnectorContext, http_get, ConnectorError
from src.connectors.credentials_store import get_credentials, set_credentials
import httpx
import asyncio
import time as _time


class ProofpointConnector(BaseConnector):
    name = 'proofpoint'

    def __init__(self, api_key: Optional[str] = None, api_secret: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.api_key = api_key or os.environ.get('PROOFPOINT_API_KEY')
        self.api_secret = api_secret or os.environ.get('PROOFPOINT_API_SECRET')
        self._token = None
        self._token_expiry = 0

    async def _ensure_token(self) -> str:
        if self._token and _time.time() + 30 < self._token_expiry:
            return self._token
        # attempt to load per-tenant credentials
        try:
            creds = get_credentials('proofpoint', tenant=os.getenv('DEFAULT_TENANT') or None)
            if creds:
                # prefer stored token
                at = creds.get('access_token')
                exp = creds.get('expires_at')
                if at and exp and _time.time() + 30 < float(exp):
                    self._token = at
                    self._token_expiry = float(exp)
                    return self._token
        except Exception:
            pass
        # Fallback: environment token
        t = os.environ.get('PROOFPOINT_BEARER')
        if t:
            self._token = t
            self._token_expiry = _time.time() + 3600
            return t

        # If client id/secret available, perform client_credentials flow synchronously in executor
        cid = os.environ.get('PROOFPOINT_CLIENT_ID')
        csec = os.environ.get('PROOFPOINT_CLIENT_SECRET')
        token_url = os.environ.get('PROOFPOINT_TOKEN_URL')
        if cid and csec and token_url:
            def _get_token():
                try:
                    with httpx.Client(timeout=10) as c:
                        r = c.post(token_url, data={'grant_type': 'client_credentials'}, auth=(cid, csec))
                        if r.status_code == 200:
                            return r.json()
                except Exception:
                    return None
                return None
            data = await asyncio.get_event_loop().run_in_executor(None, _get_token)
            if data and isinstance(data, dict):
                at = data.get('access_token')
                expires = int(data.get('expires_in') or 3600)
                if at:
                    self._token = at
                    self._token_expiry = _time.time() + expires
                    try:
                        set_credentials('proofpoint', {'access_token': at, 'expires_at': self._token_expiry, 'client_id': cid}, tenant=os.getenv('DEFAULT_TENANT') or None)
                    except Exception:
                        pass
                    return self._token
        raise ConnectorError('Proofpoint credentials not configured')

    async def _fetch_paginated(self, url: str, headers: Dict[str, str], max_pages: int = 10) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        next_url = url
        pages = 0
        while next_url and pages < max_pages:
            status, body, resp_headers = await http_get(next_url, headers=headers, allow_hosts=None)
            pages += 1
            if status >= 400:
                raise ConnectorError(f'Proofpoint API error {status}')
            try:
                import json
                j = json.loads(body.decode('utf-8'))
                items = j.get('data') or j.get('items') or j
                if isinstance(items, list):
                    out.extend(items)
                # pagination: look for next link header or 'paging.next'
                next_url = None
                if isinstance(j, dict):
                    nxt = j.get('paging', {}).get('next')
                    if nxt:
                        next_url = nxt
            except Exception:
                break
        return out

    async def execute(self, domain: str, entity: str, window: Optional[str] = None, context: ConnectorContext | None = None) -> Dict[str, Any]:
        # Ensure token
        token = await self._ensure_token()
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        # Build a TAP threats URL; domain/entity/window guidance
        base = os.environ.get('PROOFPOINT_API_BASE', 'https://tap-api.proofpoint.com/v2/siem')
        url = f"{base}/threats"  # simplified
        items = []
        try:
            items = await self._fetch_paginated(url, headers)
        except Exception as e:
            raise ConnectorError(str(e))
        # Normalize to expected shape
        return {'events': items}


__all__ = ['ProofpointConnector']
