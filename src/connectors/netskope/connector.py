"""Netskope connector — REST API v2.

Fetches alert, event, and application-access logs from Netskope using an API
token.  Normalizes results to canonical flow rows compatible with the Janusec
session-envelope schema.

Environment variables:
    NETSKOPE_API_TOKEN    - REST API v2 token from Netskope Settings → API Tokens
    NETSKOPE_TENANT_HOST  - tenant hostname e.g. mycompany.goskope.com (no scheme)

When credentials are absent the connector skips all API calls and returns an
empty result.

Rate limit: Netskope enforces a burst limit; this connector sleeps between
paginated calls to stay within policy.

Reference:
    https://docs.netskope.com/en/rest-api-v2-overview.html
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_PAGE_SIZE = 500
_DEFAULT_LOOKBACK_SECONDS = 3600


class NetskopeConnector:
    """Netskope connector via REST API v2.

    Usage::

        from src.connectors.netskope import NetskopeConnector
        conn = NetskopeConnector()
        rows = await conn.fetch_alerts(lookback_seconds=3600)
    """
    source_kind = 'netskope_proxy'

    def __init__(self) -> None:
        self.token = os.getenv('NETSKOPE_API_TOKEN') or ''
        host = (os.getenv('NETSKOPE_TENANT_HOST') or '').rstrip('/')
        # Accept bare hostname or full URL
        if host.startswith('http'):
            self.base_url = host
        elif host:
            self.base_url = f'https://{host}'
        else:
            self.base_url = ''

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.base_url)

    def _warn_not_configured(self) -> None:
        logger.warning(
            'Netskope connector: credentials not configured. '
            'Set NETSKOPE_API_TOKEN and NETSKOPE_TENANT_HOST. '
            'See https://docs.netskope.com/en/rest-api-v2-overview.html'
        )

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[Any]:
        """Synchronous GET helper."""
        import urllib.request
        import urllib.parse
        url = f'{self.base_url}/api/v2{path}'
        if params:
            url = f'{url}?{urllib.parse.urlencode(params)}'
        req = urllib.request.Request(
            url,
            headers={
                'Netskope-Api-Token': self.token,
                'Accept': 'application/json',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            logger.debug('Netskope GET %s failed: %s', path, exc)
            return None

    async def _aget(self, path: str, params: Optional[dict] = None) -> Optional[Any]:
        import asyncio
        return await asyncio.to_thread(self._get, path, params)

    async def fetch_alerts(
        self,
        lookback_seconds: int = _DEFAULT_LOOKBACK_SECONDS,
        limit: int = _DEFAULT_PAGE_SIZE,
        alert_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return normalized alert rows.

        Each row contains canonical keys:
        ``source_kind, ts, user, src_ip, dst_ip, domain, app, alert_type,
        action, severity, policy``
        """
        if not self.is_configured:
            self._warn_not_configured()
            return []
        now = int(time.time())
        params: dict = {
            'limit': min(limit, _DEFAULT_PAGE_SIZE),
            'starttime': now - lookback_seconds,
            'endtime': now,
        }
        if alert_type:
            params['type'] = alert_type
        raw = await self._aget('/events/dataexport/alerts/all', params)
        if not raw or not isinstance(raw, dict):
            return []
        items = raw.get('result') or raw.get('data') or []
        return [self._normalize_alert(r) for r in items[:limit]]

    def _normalize_alert(self, r: dict) -> Dict[str, Any]:
        return {
            'source_kind': self.source_kind,
            'ts': r.get('timestamp') or r.get('_insertion_epoch_timestamp'),
            'user': r.get('user') or r.get('userkey'),
            'src_ip': r.get('srcip'),
            'dst_ip': r.get('dstip'),
            'domain': r.get('domain') or r.get('hostname'),
            'app': r.get('appsuite') or r.get('app'),
            'app_category': r.get('appcategory') or r.get('category'),
            'alert_type': r.get('alert_type') or r.get('type'),
            'action': r.get('action'),
            'severity': r.get('severity') or r.get('alert_severity'),
            'policy': r.get('policy'),
            'risk_level': r.get('risk_level') or r.get('ur_normalized'),
        }

    async def fetch_page_events(
        self,
        lookback_seconds: int = _DEFAULT_LOOKBACK_SECONDS,
        limit: int = _DEFAULT_PAGE_SIZE,
    ) -> List[Dict[str, Any]]:
        """Return page/URL access events (web traffic)."""
        if not self.is_configured:
            self._warn_not_configured()
            return []
        now = int(time.time())
        params = {
            'limit': min(limit, _DEFAULT_PAGE_SIZE),
            'starttime': now - lookback_seconds,
            'endtime': now,
        }
        raw = await self._aget('/events/dataexport/events/page', params)
        if not raw or not isinstance(raw, dict):
            return []
        items = raw.get('result') or raw.get('data') or []
        return [
            {
                'source_kind': self.source_kind,
                'ts': r.get('timestamp'),
                'user': r.get('user'),
                'src_ip': r.get('srcip'),
                'domain': r.get('domain') or r.get('hostname'),
                'url': r.get('url'),
                'app': r.get('appsuite') or r.get('app'),
                'action': r.get('action'),
                'bytes_sent': r.get('numbytes'),
                'category': r.get('category'),
            }
            for r in items[:limit]
        ]

    async def fetch_application_events(
        self,
        lookback_seconds: int = _DEFAULT_LOOKBACK_SECONDS,
        limit: int = _DEFAULT_PAGE_SIZE,
    ) -> List[Dict[str, Any]]:
        """Return application-layer events (SaaS/DLP activity)."""
        if not self.is_configured:
            self._warn_not_configured()
            return []
        now = int(time.time())
        params = {
            'limit': min(limit, _DEFAULT_PAGE_SIZE),
            'starttime': now - lookback_seconds,
            'endtime': now,
        }
        raw = await self._aget('/events/dataexport/events/application', params)
        if not raw or not isinstance(raw, dict):
            return []
        items = raw.get('result') or raw.get('data') or []
        return [
            {
                'source_kind': self.source_kind,
                'ts': r.get('timestamp'),
                'user': r.get('user'),
                'app': r.get('appsuite') or r.get('app'),
                'app_category': r.get('appcategory') or r.get('category'),
                'action': r.get('activity') or r.get('action'),
                'object_type': r.get('object_type'),
                'object_name': r.get('object') or r.get('object_name'),
                'severity': r.get('severity'),
                'dlp_rule': r.get('dlp_rule_name'),
            }
            for r in items[:limit]
        ]

    async def fetch_user_activity(
        self, username: str, lookback_seconds: int = _DEFAULT_LOOKBACK_SECONDS, limit: int = 200
    ) -> List[Dict[str, Any]]:
        """Return all events for a specific user."""
        if not self.is_configured:
            self._warn_not_configured()
            return []
        now = int(time.time())
        import urllib.parse
        params = {
            'limit': min(limit, _DEFAULT_PAGE_SIZE),
            'starttime': now - lookback_seconds,
            'endtime': now,
            'user': username,
        }
        raw = await self._aget('/events/dataexport/alerts/all', params)
        if not raw or not isinstance(raw, dict):
            return []
        items = raw.get('result') or raw.get('data') or []
        return [self._normalize_alert(r) for r in items[:limit]]
