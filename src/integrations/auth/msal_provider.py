from __future__ import annotations

"""Interactive MSAL provider for delegated user flows and token management.

This module provides a thin wrapper around MSAL (if available) to produce
authorization URLs, exchange codes, and refresh/revoke tokens while using
TokenStore/TenantStore for persistence.
"""
from typing import Dict, Any, Optional
import logging
import time
from urllib.parse import urlencode

from src.integrations.tenant_store import TenantStore
from src.integrations.auth.token_store import TokenStore
try:
    import msal
except Exception:
    msal = None

logger = logging.getLogger(__name__)


class MSALProvider:
    AUTH_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    def __init__(self, client_id: str, client_secret: str, tenant: str = 'common', redirect_uri: str = ''):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant = tenant
        self.redirect_uri = redirect_uri
        self._token_store = TokenStore()
        self._tenant_store = TenantStore()
        self._app = None
        if msal is not None:
            try:
                self._app = msal.ConfidentialClientApplication(
                    client_id=self.client_id,
                    client_credential=self.client_secret,
                    authority=f"https://login.microsoftonline.com/{self.tenant}"
                )
            except Exception:
                self._app = None

    def get_authorization_url(self, scope: str = 'offline_access openid profile Mail.Read', state: Optional[str] = None) -> str:
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'response_mode': 'query',
            'scope': scope,
        }
        if state:
            params['state'] = state
        return f"{self.AUTH_URL.format(tenant=self.tenant)}?{urlencode(params)}"

    def exchange_code(self, code: str) -> Dict[str, Any]:
        # Prefer MSAL library exchange when available
        token = None
        if self._app is not None and msal is not None:
            try:
                result = self._app.acquire_token_by_authorization_code(code, scopes=["offline_access", "openid", "profile", "Mail.Read"], redirect_uri=self.redirect_uri)
                token = result
            except Exception:
                token = None
        if token is None:
            import requests
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': code,
                'redirect_uri': self.redirect_uri,
                'grant_type': 'authorization_code',
            }
            url = self.TOKEN_URL.format(tenant=self.tenant)
            r = requests.post(url, data=data, timeout=15)
            r.raise_for_status()
            token = r.json()
        # Persist tenant tokens
        tenant_id = token.get('tenant') or token.get('id_token') or 'unknown'
        try:
            self._tenant_store.save_tokens(tenant_id, token)
        except Exception:
            logger.debug('Failed to persist tenant tokens')
        return token

    def refresh(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        toks = self._tenant_store.load_tokens(tenant_id) or {}
        refresh = toks.get('refresh_token')
        if not refresh:
            return None
        # Use per-tenant client creds if present
        client_id = toks.get('client_id') or self.client_id
        client_secret = toks.get('client_secret') or self.client_secret
        # Attempt MSAL refresh if library available and an app was constructed
        if msal is not None and self._app is not None:
            try:
                res = self._app.acquire_token_by_refresh_token(refresh, scopes=["https://graph.microsoft.com/.default"])
                if res and res.get('access_token'):
                    # Persist
                    if res.get('expires_in'):
                        res['expires_at'] = int(time.time()) + int(res.get('expires_in'))
                    res['client_id'] = client_id
                    res['client_secret'] = client_secret
                    try:
                        self._tenant_store.save_tokens(tenant_id, res)
                    except Exception:
                        logger.debug('Failed to persist refreshed tokens')
                    return res
            except Exception:
                logger.debug('MSAL library refresh attempt failed; falling back to token endpoint')

        # Fallback to raw token endpoint
        try:
            import requests
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh,
                'grant_type': 'refresh_token',
            }
            url = self.TOKEN_URL.format(tenant=self.tenant)
            r = requests.post(url, data=data, timeout=15)
            r.raise_for_status()
            new = r.json()
            if new.get('expires_in'):
                new['expires_at'] = int(time.time()) + int(new.get('expires_in'))
            new['client_id'] = client_id
            new['client_secret'] = client_secret
            self._tenant_store.save_tokens(tenant_id, new)
            return new
        except Exception:
            logger.exception('MSAL refresh failed')
            return None

    def revoke(self, tenant_id: str) -> None:
        try:
            self._tenant_store.delete_tokens(tenant_id)
        except Exception:
            logger.debug('Failed to delete tenant tokens')


__all__ = ["MSALProvider"]

