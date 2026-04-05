from __future__ import annotations

"""Office 365 email collector using Microsoft Graph delta queries.

Safe defaults and lazy network imports. Designed for pilot ingestion.
"""

import asyncio
from datetime import datetime, timedelta
from typing import AsyncIterator, Dict, Any, Optional

import logging

from src.integrations.auth.oauth_providers import MSALProvider
from src.integrations.auth.token_store import TokenStore
from src.live.event_models import EmailEvent

logger = logging.getLogger(__name__)
try:
    from prometheus_client import Counter, Gauge
    _PROM_AVAILABLE = True
except Exception:
    _PROM_AVAILABLE = False

from src.integrations._backoff import retry_with_backoff
from src.integrations.tenant_store import TenantStore
try:
    from src.integrations.tenant_config import load_email_config
except Exception:
    load_email_config = None  # type: ignore

try:
    from aiolimiter import AsyncLimiter  # type: ignore
    _RL_AVAILABLE = True
except Exception:
    _RL_AVAILABLE = False


if _PROM_AVAILABLE:
    O365_POLL_SUCCESS = Counter('o365_poll_success_total', 'Office365 successful poll calls')
    O365_POLL_ERRORS = Counter('o365_poll_error_total', 'Office365 poll errors')
    O365_LAST_SUCCESS = Gauge('o365_last_success_timestamp', 'Last successful o365 poll timestamp')
    O365_RATE_LIMIT_HITS = Counter('o365_rate_limit_hits_total', 'Requests gated by rate limiter')


class Office365Collector:
    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    BATCH_SIZE = 100
    POLL_INTERVAL = 300  # seconds (override via env O365_POLL_INTERVAL)

    def __init__(self, tenant_id: str, oauth: MSALProvider, token_store: TokenStore):
        self.tenant_id = tenant_id
        self.oauth = oauth
        self.token_store = token_store
        self._delta_link: Optional[str] = None
        self._tenant_store = TenantStore()
        try:
            self._delta_link = self._tenant_store.load_cursor(self.tenant_id, 'office365', 'deltaLink')
        except Exception:
            self._delta_link = None
        self._rate_limiter = None
        if _RL_AVAILABLE:
            import os
            rate = int(os.getenv('O365_RATE_LIMIT_PER_SEC', '240'))
            try:
                self._rate_limiter = AsyncLimiter(max_rate=rate, time_period=1)
            except Exception:
                self._rate_limiter = None
        # Poll interval from tenant config if available
        try:
            if load_email_config:
                cfg = load_email_config()
                self.POLL_INTERVAL = int(cfg.get('poll', {}).get('o365', self.POLL_INTERVAL))
        except Exception:
            pass

    async def start_polling(self) -> AsyncIterator[EmailEvent]:
        while True:
            try:
                async for evt in self._poll_messages():
                    yield evt
            except Exception as exc:
                logger.error("Office365 polling error: %s", exc)
                await asyncio.sleep(60)
            import os
            interval = int(os.getenv('O365_POLL_INTERVAL', str(self.POLL_INTERVAL)))
            await asyncio.sleep(interval)

    async def _poll_messages(self) -> AsyncIterator[EmailEvent]:
        token = await self.oauth.get_access_token()
        # Persist token best-effort for rotation/inspection
        try:
            meta = self.oauth.get_token_meta()
            expiry = meta.get('expiry') or (datetime.utcnow())
            data = meta.get('data') or {}
            if isinstance(expiry, datetime) and self.token_store:
                await self.token_store.store_token(self.tenant_id, 'office365', data, expiry)
        except Exception:
            pass
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        if self._delta_link:
            url = self._delta_link
        else:
            filter_date = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            # Basic user messages endpoint; production would parameterize mailbox
            url = (
                f"{self.GRAPH_BASE}/users/delta?"
                f"$select=receivedDateTime,subject,from,toRecipients,hasAttachments,internetMessageHeaders"
                f"&$filter=receivedDateTime ge {filter_date}&$top={self.BATCH_SIZE}"
            )
        try:
            import httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                while url:
                    def _call():
                        import httpx as _sync_httpx
                        with _sync_httpx.Client(timeout=60.0) as _c:
                            return _c.get(url, headers=headers)
                    resp = await asyncio.to_thread(retry_with_backoff, _call)
                    resp.raise_for_status()
                    data = resp.json()
                    for msg in data.get("value", []):
                        evt = await self._parse_message(msg)
                        if evt:
                            yield evt
                    if "@odata.deltaLink" in data:
                        self._delta_link = data["@odata.deltaLink"]
                        try:
                            self._tenant_store.save_cursor(self.tenant_id, 'office365', 'deltaLink', str(self._delta_link))
                        except Exception:
                            pass
                        url = None
                    else:
                        url = data.get("@odata.nextLink")
                if _PROM_AVAILABLE:
                    O365_POLL_SUCCESS.inc()
                    O365_LAST_SUCCESS.set_to_current_time()
        except Exception as exc:
            logger.error("Graph API error: %s", exc)
            if _PROM_AVAILABLE:
                O365_POLL_ERRORS.inc()

    async def _parse_message(self, msg: Dict[str, Any]) -> Optional[EmailEvent]:
        try:
            received = msg.get("receivedDateTime") or None
            ts = None
            if received:
                try:
                    ts = datetime.fromisoformat(received.replace("Z", "+00:00")).timestamp()
                except Exception:
                    ts = None
            frm = msg.get("from", {}).get("emailAddress", {})
            to_addrs = [r.get("emailAddress", {}).get("address", "") for r in (msg.get("toRecipients") or [])]
            headers = {h.get("name"): h.get("value") for h in (msg.get("internetMessageHeaders") or [])}
            body_preview = msg.get("bodyPreview") or None
            ev = EmailEvent(
                timestamp=ts,
                tenant_id=self.tenant_id,
                source="office365",
                sender=frm.get("address"),
                sender_display_name=frm.get("name"),
                recipients=to_addrs,
                subject=msg.get("subject"),
                has_attachments=bool(msg.get("hasAttachments", False)),
                headers=headers,
                body_preview=body_preview,
                message_id=msg.get("id"),
                raw_event=msg,
            )
            return ev
        except Exception as exc:
            logger.error("Failed to parse Office365 message: %s", exc)
            return None

    async def list_all_users(self) -> List[str]:
        """Enumerate all mailboxes (user principal names)."""
        try:
            import httpx
            token = await self.oauth.get_access_token()
            headers = {"Authorization": f"Bearer {token}"}
            url = f"{self.GRAPH_BASE}/users?$select=userPrincipalName&$top=999"
            users: List[str] = []
            async with httpx.AsyncClient(timeout=60.0) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                for u in data.get('value', []):
                    upn = (u.get('userPrincipalName') or '').strip()
                    if upn:
                        users.append(upn)
            return users
        except Exception as exc:
            logger.error('Failed to list users: %s', exc)
            return []

    async def poll_mailbox(self, user_upn: str) -> AsyncIterator[EmailEvent]:
        """Poll a specific mailbox using delta queries, persisting per-user cursors."""
        token = await self.oauth.get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        cursor_key = f"deltaLink:{user_upn}"
        delta = self._tenant_store.load_cursor(self.tenant_id, 'office365', cursor_key)
        if delta:
            url = delta
        else:
            filter_date = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            url = (
                f"{self.GRAPH_BASE}/users/{user_upn}/messages/delta?"
                f"$select=receivedDateTime,subject,from,toRecipients,hasAttachments,internetMessageHeaders"
                f"&$filter=receivedDateTime ge {filter_date}&$top={self.BATCH_SIZE}"
            )
        import httpx
        async with httpx.AsyncClient(timeout=60.0) as client:
            while url:
                if self._rate_limiter is not None:
                    async with self._rate_limiter:
                        if _PROM_AVAILABLE:
                            O365_RATE_LIMIT_HITS.inc()
                        r = await client.get(url, headers=headers)
                else:
                    r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                for msg in data.get("value", []):
                    evt = await self._parse_message(msg)
                    if evt:
                        yield evt
                if "@odata.deltaLink" in data:
                    new_delta = data["@odata.deltaLink"]
                    try:
                        self._tenant_store.save_cursor(self.tenant_id, 'office365', cursor_key, str(new_delta))
                    except Exception:
                        pass
                    url = None
                else:
                    url = data.get("@odata.nextLink")

    async def poll_all_mailboxes(self, max_concurrency: int = 10) -> AsyncIterator[EmailEvent]:
        """Poll all mailboxes with bounded concurrency."""
        # Allow tuning via env knob O365_MAX_CONCURRENCY
        try:
            import os as _os
            env_cc = int(_os.getenv('O365_MAX_CONCURRENCY', str(max_concurrency)))
            max_concurrency = env_cc
        except Exception:
            pass
        users = await self.list_all_users()
        if not users:
            return
        sem = asyncio.Semaphore(max_concurrency)
        async def _poll_user(u: str):
            async with sem:
                async for evt in self.poll_mailbox(u):
                    yield evt
        # Gather tasks and yield events as they arrive
        tasks = []
        for u in users:
            tasks.append(_poll_user(u))
        for coro in tasks:
            async for evt in coro:
                yield evt


__all__ = ["Office365Collector"]