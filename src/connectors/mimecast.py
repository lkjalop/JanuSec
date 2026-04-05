from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional, List

from src.connectors.sdk import BaseConnector, ConnectorContext, http_get, ConnectorError
from src.connectors.credentials_store import get_credentials, set_credentials
import httpx
import asyncio
import time as _time


class MimecastConnector(BaseConnector):
    name = 'mimecast'

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.client_id = client_id or os.environ.get('MIMECAST_CLIENT_ID')
        self.client_secret = client_secret or os.environ.get('MIMECAST_CLIENT_SECRET')
        self._token = None
        self._token_expiry = 0

    async def _ensure_token(self) -> str:
        if self._token and _time.time() + 30 < self._token_expiry:
            return self._token
        # try credentials store
        try:
            creds = get_credentials('mimecast', tenant=os.getenv('DEFAULT_TENANT') or None)
            if creds:
                at = creds.get('access_token')
                exp = creds.get('expires_at')
                if at and exp and _time.time() + 30 < float(exp):
                    self._token = at
                    self._token_expiry = float(exp)
                    return self._token
        except Exception:
            pass
        t = os.environ.get('MIMECAST_BEARER')
        if t:
            self._token = t
            self._token_expiry = _time.time() + 3600
            return t
        cid = os.environ.get('MIMECAST_CLIENT_ID')
        csec = os.environ.get('MIMECAST_CLIENT_SECRET')
        token_url = os.environ.get('MIMECAST_TOKEN_URL')
        if cid and csec and token_url:
            def _get_token():
                try:
                    with httpx.Client(timeout=10) as c:
                        r = c.post(token_url, data={'grant_type':'client_credentials'}, auth=(cid, csec))
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
                        set_credentials('mimecast', {'access_token': at, 'expires_at': self._token_expiry, 'client_id': cid}, tenant=os.getenv('DEFAULT_TENANT') or None)
                    except Exception:
                        pass
                    return self._token
        raise ConnectorError('Mimecast credentials not configured')

    async def execute(self, domain: str, entity: str, window: Optional[str] = None, context: ConnectorContext | None = None) -> Dict[str, Any]:
        token = await self._ensure_token()
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        base = os.environ.get('MIMECAST_API_BASE', 'https://api.mimecast.com')
        url = f"{base}/api/siem/alerts"  # simplified
        try:
            status, body, _ = await http_get(url, headers=headers, allow_hosts=None)
            if status >= 400:
                raise ConnectorError(f'Mimecast API error {status}')
            import json
            j = json.loads(body.decode('utf-8'))
            items = j.get('data') or j.get('items') or j
            return {'events': items}
        except Exception as e:
            raise ConnectorError(str(e))


__all__ = ['MimecastConnector']
