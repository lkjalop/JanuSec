from __future__ import annotations

"""Google OAuth provider wrapper for authorization URL, token exchange and refresh.

This is a thin wrapper that uses TenantStore for persistence and TokenStore for optional encrypted caching.
"""
from typing import Dict, Any, Optional
import logging
import time
from urllib.parse import urlencode

from src.integrations.tenant_store import TenantStore
from src.integrations.auth.token_store import TokenStore
try:
    import requests
except Exception:
    requests = None

logger = logging.getLogger(__name__)


class GoogleOAuthProvider:
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str = ''):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._tenant_store = TenantStore()
        self._token_store = TokenStore()

    def get_authorization_url(self, scope: str = 'https://www.googleapis.com/auth/gmail.readonly', state: Optional[str] = None) -> str:
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': scope,
            'access_type': 'offline',
            'prompt': 'consent',
        }
        if state:
            params['state'] = state
        return f"{self.AUTH_URL}?{urlencode(params)}"

    def exchange_code(self, code: str, tenant_id: str = 'default') -> Dict[str, Any]:
        if requests is None:
            raise RuntimeError('requests library required for Google OAuth exchange')

        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code',
        }
        r = requests.post(self.TOKEN_URL, data=data, timeout=15)
        r.raise_for_status()
        token = r.json()
        # persist tokens under tenant
        try:
            token['client_id'] = self.client_id
            token['client_secret'] = self.client_secret
            self._tenant_store.save_tokens(tenant_id, token)
        except Exception:
            logger.debug('Failed to persist google tenant token')
        return token

    def refresh(self, tenant_id: str = 'default') -> Optional[Dict[str, Any]]:
        toks = self._tenant_store.load_tokens(tenant_id) or {}
        refresh = toks.get('refresh_token')
        if not refresh:
            return None
        data = {
            'refresh_token': refresh,
            'client_id': toks.get('client_id') or self.client_id,
            'client_secret': toks.get('client_secret') or self.client_secret,
            'grant_type': 'refresh_token',
        }
        if requests is None:
            logger.error('requests library not available for token refresh')
            return None
        try:
            r = requests.post(self.TOKEN_URL, data=data, timeout=15)
            r.raise_for_status()
            new = r.json()
            if new.get('expires_in'):
                new['expires_at'] = int(time.time()) + int(new.get('expires_in'))
            new['client_id'] = data['client_id']
            new['client_secret'] = data['client_secret']
            self._tenant_store.save_tokens(tenant_id, new)
            return new
        except Exception:
            logger.exception('Google refresh failed')
            return None

    def revoke(self, tenant_id: str) -> None:
        try:
            self._tenant_store.delete_tokens(tenant_id)
        except Exception:
            logger.debug('Failed to delete google tenant tokens')


__all__ = ["GoogleOAuthProvider"]
