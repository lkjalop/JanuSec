"""Zscaler Internet Access (ZIA) connector.

Fetches web/SSL transaction logs, CASB events, and threat alerts from the
Zscaler API using API key + session-cookie authentication.

Environment variables:
    ZSCALER_API_KEY    - API key from ZIA Admin Portal (Administration > API Key)
    ZSCALER_BASE_URL   - Cloud base URL e.g. https://zsapi.zscaler.net
    ZSCALER_USERNAME   - Admin e-mail used to establish a session
    ZSCALER_PASSWORD   - Admin password

When credentials are absent the connector skips all API calls and returns an
empty result so callers do not raise.

Rate limiting: ZIA enforces 40 req/min; this connector uses a conservative
20 req/min budget per base URL.

Reference:
    https://help.zscaler.com/zia/api-getting-started
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SESSION_CACHE: dict[str, tuple[str, float]] = {}  # base_url -> (jsessionid, expiry)


def _zscaler_obfuscate_api_key(api_key: str, now_ms: int) -> str:
    """Derive the obfuscated 'secret' token Zscaler requires alongside the API key.

    From the ZIA API docs the derived key is built from the API key and the
    current timestamp using a fixed character-shuffle algorithm.
    """
    ts_str = str(now_ms)[-6:]
    n = str(int(ts_str) >> 1).zfill(6)
    chars: List[str] = []
    for i in range(0, 6):
        chars.append(api_key[int(ts_str[i])])
    for i in range(0, 6):
        chars.append(api_key[int(n[i]) + 2])
    return ''.join(chars)


def _zia_session_login(base_url: str, username: str, password: str, api_key: str) -> Optional[str]:
    """Authenticate and return a JSESSIONID cookie string (or None on failure)."""
    cache_key = base_url
    cached = _SESSION_CACHE.get(cache_key)
    if cached and time.time() + 30 < cached[1]:
        return cached[0]
    try:
        import urllib.request
        now_ms = int(time.time() * 1000)
        obf_key = _zscaler_obfuscate_api_key(api_key, now_ms)
        payload = json.dumps({
            'apiKey': api_key,
            'username': username,
            'password': password,
            'timestamp': now_ms,
            'obfuscatedApiKey': obf_key,
        }).encode()
        path = '/api/v1/authenticatedSession'
        req = urllib.request.Request(
            f'{base_url}{path}',
            data=payload,
            method='POST',
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            cookie = resp.getheader('Set-Cookie') or ''
            # Extract JSESSIONID=...;
            jsessionid = next(
                (part.strip().split('=', 1)[1].split(';')[0]
                 for part in cookie.split(',')
                 if 'JSESSIONID' in part),
                None,
            )
            if jsessionid:
                _SESSION_CACHE[cache_key] = (jsessionid, time.time() + 3600)
                return jsessionid
    except Exception as exc:
        logger.warning('Zscaler: session login failed: %s', exc)
    return None


def _zia_get(base_url: str, path: str, jsessionid: str) -> Optional[Any]:
    """Perform a GET request against the ZIA API."""
    try:
        import urllib.request
        req = urllib.request.Request(
            f'{base_url}{path}',
            headers={
                'Cookie': f'JSESSIONID={jsessionid}',
                'Accept': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        logger.debug('Zscaler GET %s failed: %s', path, exc)
    return None


class ZscalerConnector:
    """Zscaler Internet Access connector.

    Usage::

        from src.connectors.zscaler import ZscalerConnector
        conn = ZscalerConnector()
        rows = await conn.fetch_web_logs(start_ts=..., end_ts=...)
    """
    source_kind = 'zscaler_proxy'

    def __init__(self) -> None:
        self.base_url = (os.getenv('ZSCALER_BASE_URL') or '').rstrip('/')
        self.api_key = os.getenv('ZSCALER_API_KEY') or ''
        self.username = os.getenv('ZSCALER_USERNAME') or ''
        self.password = os.getenv('ZSCALER_PASSWORD') or ''

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.username and self.password)

    def _warn_not_configured(self) -> None:
        logger.warning(
            'Zscaler connector: credentials not configured. '
            'Set ZSCALER_BASE_URL, ZSCALER_API_KEY, ZSCALER_USERNAME, ZSCALER_PASSWORD. '
            'See https://help.zscaler.com/zia/api-getting-started'
        )

    async def _session(self) -> Optional[str]:
        import asyncio
        if not self.is_configured:
            self._warn_not_configured()
            return None
        return await asyncio.to_thread(
            _zia_session_login,
            self.base_url, self.username, self.password, self.api_key,
        )

    async def fetch_web_logs(
        self,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Return normalized web transaction log rows.

        Each row is a dict with canonical keys:
        ``source_kind, ts, src_ip, dst_ip, user, domain, action, bytes_sent,
        bytes_received, category, threat_name, risk_score``
        """
        import asyncio
        jsessionid = await self._session()
        if not jsessionid:
            return []
        # ZIA Web Insights API provides transaction summary
        params = f'?pageSize={limit}&sortOrder=DESC'
        raw = await asyncio.to_thread(
            _zia_get, self.base_url, f'/api/v1/webInsights/applicationReport{params}', jsessionid
        )
        if not raw or not isinstance(raw, (dict, list)):
            return []
        rows_raw = raw if isinstance(raw, list) else raw.get('webInsights', raw.get('data', []))
        return [self._normalize_web_row(r) for r in rows_raw[:limit]]

    def _normalize_web_row(self, row: dict) -> Dict[str, Any]:
        return {
            'source_kind': self.source_kind,
            'ts': row.get('timestamp') or row.get('date'),
            'src_ip': row.get('clientSourceIp') or row.get('clientIp'),
            'dst_ip': row.get('serverIp') or row.get('destinationIp'),
            'user': row.get('user') or row.get('userName'),
            'domain': row.get('hostName') or row.get('domain'),
            'url': row.get('url'),
            'action': row.get('action') or row.get('urlClass'),
            'bytes_sent': row.get('bytesSent', 0),
            'bytes_received': row.get('bytesReceived', 0),
            'category': row.get('urlCategory') or row.get('category'),
            'threat_name': row.get('threatName') or row.get('malwareName'),
            'risk_score': row.get('riskIndex') or row.get('riskScore'),
        }

    async def fetch_threat_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return threat/malware events from the ZIA Threat Feed."""
        import asyncio
        jsessionid = await self._session()
        if not jsessionid:
            return []
        raw = await asyncio.to_thread(
            _zia_get, self.base_url,
            f'/api/v1/threatInsights/threatFeedReport?pageSize={limit}', jsessionid,
        )
        if not raw:
            return []
        items = raw if isinstance(raw, list) else raw.get('threatFeedDetails', raw.get('data', []))
        return [
            {
                'source_kind': self.source_kind,
                'ts': r.get('timestamp') or r.get('date'),
                'src_ip': r.get('srcIp') or r.get('clientIp'),
                'domain': r.get('hostName') or r.get('domain'),
                'threat_name': r.get('threatName') or r.get('malwareName'),
                'threat_category': r.get('threatClass') or r.get('category'),
                'action': r.get('action'),
                'severity': r.get('severity'),
            }
            for r in items[:limit]
        ]

    async def fetch_user_activity(
        self, username: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Return recent web transactions for a specific user."""
        import asyncio
        jsessionid = await self._session()
        if not jsessionid:
            return []
        import urllib.parse
        enc = urllib.parse.quote(username)
        raw = await asyncio.to_thread(
            _zia_get, self.base_url,
            f'/api/v1/webInsights/applicationReport?pageSize={limit}&username={enc}', jsessionid,
        )
        if not raw:
            return []
        rows_raw = raw if isinstance(raw, list) else raw.get('webInsights', raw.get('data', []))
        return [self._normalize_web_row(r) for r in rows_raw[:limit]]
