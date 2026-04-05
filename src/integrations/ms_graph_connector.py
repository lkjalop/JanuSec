from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.integrations.connector_base import ConnectorBase
from src.integrations.tenant_store import TenantStore
from src.integrations.auth.msal_provider import MSALProvider

logger = logging.getLogger(__name__)


class MicrosoftGraphConnector(ConnectorBase):
    """Lightweight Microsoft Graph connector for audit/signin/security events.

    This scaffold implements token refresh, paginated fetch_since, and
    checkpointing via TenantStore. It focuses on auditLogs/signIns as a
    starting point; other Graph resources can be added similarly.
    """

    def __init__(self, tenant_id: Optional[str] = None, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self.tenant = tenant_id or "default"
        self._tenant_store = TenantStore()
        self._msal = MSALProvider(client_id or "", client_secret or "", tenant=self.tenant)
        self._access_token: Optional[str] = None
        self._session = requests.Session()

    async def connect(self) -> None:
        # Attempt to load persisted tokens and refresh if necessary
        toks = self._tenant_store.load_tokens(self.tenant) or {}
        now = int(time.time())
        if toks and toks.get('access_token') and toks.get('expires_at', 0) > now + 30:
            self._access_token = toks.get('access_token')
            return
        # Try tenant store refresh helper first
        refreshed = self._tenant_store.try_refresh_tokens(self.tenant)
        if refreshed:
            toks = self._tenant_store.load_tokens(self.tenant) or {}
            self._access_token = toks.get('access_token')
            return
        # Try MSAL provider refresh
        new = self._msal.refresh(self.tenant)
        if new and new.get('access_token'):
            self._access_token = new.get('access_token')
            try:
                self._tenant_store.save_tokens(self.tenant, new)
            except Exception:
                logger.debug('Failed to persist refreshed MS Graph tokens')
            return
        raise RuntimeError('No valid MS Graph tokens available for tenant')

    async def fetch_since(self, cursor: Optional[str], *, limit: int = 200) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        # Cursor here is an ISO 8601 datetime string or an odata nextLink. Use
        # tenant store cursor key 'msgraph_signins_cursor' when None.
        events: List[Dict[str, Any]] = []
        if not self._access_token:
            try:
                await self.connect()
            except Exception as e:
                logger.exception('msgraph connect failed')
                return [], None

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10), retry=retry_if_exception_type(Exception))
        def _safe_get(self, url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None):
            return self._session.get(url, headers=headers, params=params, timeout=20)

        async def fetch_security_alerts(self, cursor: Optional[str], *, limit: int = 200) -> Tuple[List[Dict[str, Any]], Optional[str]]:
            """Fetch security alerts from /security/alerts with pagination and checkpointing."""
            alerts: List[Dict[str, Any]] = []
            if not self._access_token:
                try:
                    await self.connect()
                except Exception:
                    logger.exception('msgraph connect failed')
                    return [], None

            last_cursor = cursor or self._tenant_store.load_cursor(self.tenant, 'msgraph', 'security_alerts')
            base_url = 'https://graph.microsoft.com/v1.0/security/alerts'
            params: Dict[str, Any] = {'$top': str(min(100, limit))}
            next_url = last_cursor or base_url
            headers = {'Authorization': f'Bearer {self._access_token}', 'Accept': 'application/json'}

            try:
                while next_url and len(alerts) < limit:
                    resp = None
                    try:
                        resp = self._safe_get(next_url, headers, params if next_url == base_url else None)
                    except Exception:
                        resp = self._session.get(next_url, headers=headers, params=params if next_url == base_url else None, timeout=20)
                    if resp is None:
                        break
                    if getattr(resp, 'status_code', 0) == 401:
                        new = self._msal.refresh(self.tenant)
                        if new and new.get('access_token'):
                            self._access_token = new.get('access_token')
                            headers['Authorization'] = f"Bearer {self._access_token}"
                            try:
                                self._tenant_store.save_tokens(self.tenant, new)
                            except Exception:
                                logger.debug('Failed to persist refreshed tokens after 401')
                            resp = self._session.get(next_url, headers=headers, timeout=20)
                        else:
                            break
                    if getattr(resp, 'status_code', 500) >= 400:
                        logger.error('MS Graph security alerts fetch failed: %s %s', getattr(resp, 'status_code', None), getattr(resp, 'text', None))
                        break
                    data = resp.json()
                    for item in data.get('value', []):
                        alerts.append({'raw': item, 'ingest_source': 'o365', 'event_type': 'security_alert'})
                        if len(alerts) >= limit:
                            break
                    next_url = data.get('@odata.nextLink')

                next_cursor: Optional[str]
                if next_url:
                    next_cursor = next_url
                elif alerts:
                    try:
                        latest = alerts[-1]['raw'].get('alertCreationTime') or alerts[-1]['raw'].get('createdDateTime')
                        next_cursor = latest
                    except Exception:
                        next_cursor = None
                else:
                    next_cursor = last_cursor
                return alerts, next_cursor
            except Exception:
                logger.exception('MS Graph fetch_security_alerts error')
                return [], None

        async def fetch_audit_logs(self, cursor: Optional[str], *, limit: int = 200) -> Tuple[List[Dict[str, Any]], Optional[str]]:
            """Fetch auditLogs/directoryAudits with pagination and checkpointing."""
            items: List[Dict[str, Any]] = []
            if not self._access_token:
                try:
                    await self.connect()
                except Exception:
                    logger.exception('msgraph connect failed')
                    return [], None

            last_cursor = cursor or self._tenant_store.load_cursor(self.tenant, 'msgraph', 'audit_logs')
            base_url = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'
            params: Dict[str, Any] = {'$top': str(min(100, limit))}
            next_url = last_cursor or base_url
            headers = {'Authorization': f'Bearer {self._access_token}', 'Accept': 'application/json'}

            try:
                while next_url and len(items) < limit:
                    resp = None
                    try:
                        resp = self._safe_get(next_url, headers, params if next_url == base_url else None)
                    except Exception:
                        resp = self._session.get(next_url, headers=headers, params=params if next_url == base_url else None, timeout=20)
                    if resp is None:
                        break
                    if getattr(resp, 'status_code', 0) == 401:
                        new = self._msal.refresh(self.tenant)
                        if new and new.get('access_token'):
                            self._access_token = new.get('access_token')
                            headers['Authorization'] = f"Bearer {self._access_token}"
                            try:
                                self._tenant_store.save_tokens(self.tenant, new)
                            except Exception:
                                logger.debug('Failed to persist refreshed tokens after 401')
                            resp = self._session.get(next_url, headers=headers, timeout=20)
                        else:
                            break
                    if getattr(resp, 'status_code', 500) >= 400:
                        logger.error('MS Graph audit logs fetch failed: %s %s', getattr(resp, 'status_code', None), getattr(resp, 'text', None))
                        break
                    data = resp.json()
                    for item in data.get('value', []):
                        items.append({'raw': item, 'ingest_source': 'o365', 'event_type': 'audit'})
                        if len(items) >= limit:
                            break
                    next_url = data.get('@odata.nextLink')

                next_cursor: Optional[str]
                if next_url:
                    next_cursor = next_url
                elif items:
                    try:
                        latest = items[-1]['raw'].get('activityDateTime') or items[-1]['raw'].get('createdDateTime')
                        next_cursor = latest
                    except Exception:
                        next_cursor = None
                else:
                    next_cursor = last_cursor
                return items, next_cursor
            except Exception:
                logger.exception('MS Graph fetch_audit_logs error')
                return [], None

        last_cursor = cursor or self._tenant_store.load_cursor(self.tenant, 'msgraph', 'signins')
        # If cursor looks like a nextLink, start there
        base_url = 'https://graph.microsoft.com/v1.0/auditLogs/signIns'
        params = {}
        if last_cursor and last_cursor.startswith('http'):
            next_url = last_cursor
        else:
            # If we have a timestamp cursor, filter by createdDateTime
            if last_cursor:
                params['$filter'] = f"createdDateTime ge {last_cursor}"
            params['$top'] = str(min(100, limit))
            next_url = base_url

        headers = {'Authorization': f'Bearer {self._access_token}', 'Accept': 'application/json'}

        try:
            while next_url and len(events) < limit:
                resp = self._session.get(next_url, headers=headers, params=params if next_url == base_url else None, timeout=15)
                if resp.status_code == 401:
                    # Try refresh once
                    try:
                        new = self._msal.refresh(self.tenant)
                        if new and new.get('access_token'):
                            self._access_token = new.get('access_token')
                            headers['Authorization'] = f"Bearer {self._access_token}"
                            try:
                                self._tenant_store.save_tokens(self.tenant, new)
                            except Exception:
                                logger.debug('Failed to persist refreshed tokens after 401')
                            resp = self._session.get(next_url, headers=headers, timeout=15)
                        else:
                            break
                    except Exception:
                        break
                if resp.status_code >= 400:
                    logger.error('MS Graph fetch failed: %s %s', resp.status_code, resp.text)
                    break
                data = resp.json()
                for item in data.get('value', []):
                    events.append({'raw': item, 'ingest_source': 'o365', 'event_type': 'signin'})
                    if len(events) >= limit:
                        break
                next_url = data.get('@odata.nextLink')
            # Determine new cursor: if nextLink exists, return it; otherwise use last item's createdDateTime
            next_cursor: Optional[str]
            if next_url:
                next_cursor = next_url
            elif events:
                # try to extract the newest createdDateTime
                try:
                    latest = events[-1]['raw'].get('createdDateTime')
                    next_cursor = latest
                except Exception:
                    next_cursor = None
            else:
                next_cursor = last_cursor
            return events, next_cursor
        except Exception:
            logger.exception('MS Graph fetch_since error')
            return [], None

    async def ack(self, cursor: str) -> None:
        try:
            if cursor:
                self._tenant_store.save_cursor(self.tenant, 'msgraph', 'signins', cursor)
        except Exception:
            logger.exception('Failed to save msgraph cursor')

    async def health(self) -> Dict[str, Any]:
        toks = self._tenant_store.load_tokens(self.tenant) or {}
        ok = bool(toks.get('access_token'))
        expires = toks.get('expires_at')
        return {'enabled': ok, 'tenant': self.tenant, 'expires_at': expires}


__all__ = ["MicrosoftGraphConnector"]
