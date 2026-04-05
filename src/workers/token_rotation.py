"""Background worker that scans stored oauth tokens and proactively refreshes them."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from src.integrations.auth.token_store import TokenStore
from src.integrations.tenant_store import TenantStore
from src.integrations.auth.google_oauth_provider import GoogleOAuthProvider
from src.integrations.auth.msal_provider import MSALProvider

logger = logging.getLogger(__name__)


class TokenRotationWorker:
    def __init__(self, interval: int = 60 * 5):
        self.interval = interval
        self._running = False
        self._store = TokenStore()
        self._tenant = TenantStore()

    async def _refresh_token_record(self, rec: dict[str, Any]):
        tenant = rec.get('tenant_id')
        provider = rec.get('provider')
        try:
            # Only attempt if expiry within next 10 minutes
            exp = float(rec.get('expiry') or 0)
            if exp <= 0:
                return
            now = datetime.now(timezone.utc).timestamp()
            if exp - now > 600:
                return
            logger.info('Refreshing token for %s/%s', tenant, provider)
            if provider.lower().startswith('gmail') or provider.lower().startswith('google'):
                p = GoogleOAuthProvider('', '')
                p.refresh(tenant)
            elif provider.lower().startswith('office') or provider.lower().startswith('msgraph'):
                p = MSALProvider('', '', tenant='common')
                p.refresh(tenant)
        except Exception:
            logger.exception('Rotation refresh failed for %s/%s', tenant, provider)

    async def run(self):
        self._running = True
        while self._running:
            try:
                tokens = await self._store.list_tokens()
                for rec in tokens:
                    await self._refresh_token_record(rec)
            except Exception:
                logger.exception('Token rotation scan failed')
            await asyncio.sleep(self.interval)

    def stop(self):
        self._running = False


__all__ = ['TokenRotationWorker']
