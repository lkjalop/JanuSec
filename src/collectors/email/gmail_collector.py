from __future__ import annotations

"""Gmail collector using history-based incremental sync.

Minimal, safe implementation emitting EmailEvent objects.
"""

import asyncio
from datetime import datetime, timedelta
from typing import AsyncIterator, Dict, Any, Optional

import logging

from src.integrations.auth.oauth_providers import GoogleOAuthProvider
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
    GMAIL_POLL_SUCCESS = Counter('gmail_poll_success_total', 'Gmail successful poll calls')
    GMAIL_POLL_ERRORS = Counter('gmail_poll_error_total', 'Gmail poll errors')
    GMAIL_LAST_SUCCESS = Gauge('gmail_last_success_timestamp', 'Last successful gmail poll timestamp')
    GMAIL_RATE_LIMIT_HITS = Counter('gmail_rate_limit_hits_total', 'Requests gated by rate limiter')


class GmailCollector:
    GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
    BATCH_SIZE = 100
    POLL_INTERVAL = 300  # seconds (override via env GMAIL_POLL_INTERVAL)

    def __init__(self, tenant_id: str, oauth: GoogleOAuthProvider, user_email: str, token_store: TokenStore | None = None):
        self.tenant_id = tenant_id
        self.oauth = oauth
        self.user_email = user_email
        self.token_store = token_store
        self._history_id: Optional[str] = None
        self._tenant_store = TenantStore()
        # Load persisted cursor if available
        try:
            self._history_id = self._tenant_store.load_cursor(self.tenant_id, 'gmail', 'historyId')
        except Exception:
            self._history_id = None
        # Rate limiter
        self._rate_limiter = None
        if _RL_AVAILABLE:
            import os
            rate = int(os.getenv('GMAIL_RATE_LIMIT_PER_SEC', '240'))
            try:
                self._rate_limiter = AsyncLimiter(max_rate=rate, time_period=1)
            except Exception:
                self._rate_limiter = None
        # Poll interval from tenant config if available
        try:
            if load_email_config:
                cfg = load_email_config()
                self.POLL_INTERVAL = int(cfg.get('poll', {}).get('gmail', self.POLL_INTERVAL))
        except Exception:
            pass

    async def start_polling(self) -> AsyncIterator[EmailEvent]:
        while True:
            try:
                async for evt in self._poll_messages():
                    yield evt
            except Exception as exc:
                logger.error("Gmail polling error: %s", exc)
                await asyncio.sleep(60)
            import os
            interval = int(os.getenv('GMAIL_POLL_INTERVAL', str(self.POLL_INTERVAL)))
            await asyncio.sleep(interval)

    async def _poll_messages(self) -> AsyncIterator[EmailEvent]:
        token = await self.oauth.get_access_token()
        # Persist token best-effort for rotation/inspection
        try:
            meta = self.oauth.get_token_meta()
            expiry = meta.get('expiry') or (datetime.utcnow())
            data = meta.get('data') or {}
            if isinstance(expiry, datetime) and self.token_store:
                await self.token_store.store_token(self.tenant_id, 'gmail', data, expiry)
        except Exception:
            pass
        headers = {"Authorization": f"Bearer {token}"}
        if self._history_id:
            url = f"{self.GMAIL_BASE}/users/{self.user_email}/history?startHistoryId={self._history_id}"
        else:
            since = int((datetime.utcnow() - timedelta(days=7)).timestamp())
            url = f"{self.GMAIL_BASE}/users/{self.user_email}/messages?q=after:{since}&maxResults={self.BATCH_SIZE}"
        try:
            import httpx
            async with httpx.AsyncClient(timeout=60.0) as client:
                def _call():
                    # synchronous wrapper for retry_with_backoff using httpx (sync) for robustness
                    import httpx as _sync_httpx
                    with _sync_httpx.Client(timeout=60.0) as _c:
                        return _c.get(url, headers=headers)
                # Use backoff helper to retry transient issues
                resp = await asyncio.to_thread(retry_with_backoff, _call)
                resp.raise_for_status()
                data = resp.json()
                for ref in data.get("messages", []):
                    msg_id = ref.get("id")
                    evt = await self._fetch_message(client, headers, msg_id)
                    if evt:
                        yield evt
                if "historyId" in data:
                    self._history_id = data["historyId"]
                    # persist cursor
                    try:
                        self._tenant_store.save_cursor(self.tenant_id, 'gmail', 'historyId', str(self._history_id))
                    except Exception:
                        pass
                if _PROM_AVAILABLE:
                    GMAIL_POLL_SUCCESS.inc()
                    GMAIL_LAST_SUCCESS.set_to_current_time()
        except Exception as exc:
            logger.error("Gmail API error: %s", exc)
            if _PROM_AVAILABLE:
                GMAIL_POLL_ERRORS.inc()

    async def _fetch_message(self, client, headers: Dict[str, str], msg_id: str | None) -> Optional[EmailEvent]:
        if not msg_id:
            return None
        url = f"{self.GMAIL_BASE}/users/{self.user_email}/messages/{msg_id}?format=full"
        try:
            if self._rate_limiter is not None:
                async with self._rate_limiter:
                    if _PROM_AVAILABLE:
                        GMAIL_RATE_LIMIT_HITS.inc()
                    resp = await client.get(url, headers=headers)
            else:
                resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            msg = resp.json()
            hdrs_list = msg.get("payload", {}).get("headers", [])
            headers = {h.get("name"): h.get("value") for h in hdrs_list if isinstance(h, dict)}
            subject = headers.get("Subject")
            frm = headers.get("From")
            to = headers.get("To")
            ts = None
            try:
                date_hdr = headers.get("Date")
                if date_hdr:
                    ts = datetime.fromisoformat(date_hdr.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = None
            ev = EmailEvent(
                timestamp=ts,
                tenant_id=self.tenant_id,
                source="gmail",
                sender=frm,
                sender_display_name=(frm.split('<')[0].strip() if frm else None),
                recipients=[to] if to else [],
                subject=subject,
                has_attachments=bool(msg.get("payload", {}).get("parts")),
                headers=headers,
                body_preview=None,
                message_id=msg.get("id"),
                raw_event=msg,
            )
            return ev
        except Exception as exc:
            logger.error("Failed to fetch Gmail message %s: %s", msg_id, exc)
            return None


__all__ = ["GmailCollector"]