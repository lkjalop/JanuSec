from __future__ import annotations

"""OAuth 2.0 provider helpers for Email and IAM integrations.

This module provides minimal, safe implementations that avoid heavy imports
at import time. Network clients are created inside methods.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import logging

logger = logging.getLogger(__name__)


class OAuthProvider:
    """Base class for OAuth providers with simple token caching.

    Implementations should override `get_access_token()`.
    """

    def __init__(self, client_id: str, client_secret: str, tenant_id: str | None = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id or ''
        self._token_cache: Optional[Dict[str, Any]] = None
        self._token_expiry: Optional[datetime] = None

    async def get_access_token(self) -> str:
        raise NotImplementedError

    async def _is_token_valid(self) -> bool:
        if not self._token_cache or not self._token_expiry:
            return False
        # refresh 5 minutes before expiry
        return datetime.utcnow() < (self._token_expiry - timedelta(minutes=5))

    def get_token_meta(self) -> Dict[str, Any]:
        """Return current cached token metadata for persistence layers.

        Includes `expiry` (datetime) and raw `data` as provided by provider.
        May be empty if no token is cached yet.
        """
        return {
            'expiry': self._token_expiry,
            'data': self._token_cache or {},
        }


class MSALProvider(OAuthProvider):
    """Microsoft Graph client-credentials helper.

    Uses the client credentials flow with `.default` scope.
    """

    AUTHORITY_URL = "https://login.microsoftonline.com/{tenant_id}"
    GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

    async def get_access_token(self) -> str:
        if await self._is_token_valid():
            return str(self._token_cache.get("access_token"))
        token_url = f"{self.AUTHORITY_URL.format(tenant_id=self.tenant_id)}/oauth2/v2.0/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(self.GRAPH_SCOPE),
            "grant_type": "client_credentials",
        }
        try:
            import httpx  # imported lazily
            async with httpx.AsyncClient() as client:
                resp = await client.post(token_url, data=data, timeout=30.0)
                resp.raise_for_status()
                token_data = resp.json()
                self._token_cache = token_data
                self._token_expiry = datetime.utcnow() + timedelta(seconds=float(token_data.get("expires_in", 3600)))
                return str(token_data.get("access_token"))
        except Exception as exc:
            logger.error("MSAL token acquisition failed: %s", exc)
            raise


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth helper that uses refresh tokens.

    This minimal implementation expects a pre-stored refresh token.
    """

    TOKEN_URL = "https://oauth2.googleapis.com/token"

    def __init__(self, client_id: str, client_secret: str, refresh_token: str):
        super().__init__(client_id, client_secret, tenant_id=None)
        self._refresh_token = refresh_token

    async def get_access_token(self) -> str:
        if await self._is_token_valid():
            return str(self._token_cache.get("access_token"))
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        }
        try:
            import httpx  # imported lazily
            async with httpx.AsyncClient() as client:
                resp = await client.post(self.TOKEN_URL, data=payload, timeout=30.0)
                resp.raise_for_status()
                token_data = resp.json()
                self._token_cache = token_data
                self._token_expiry = datetime.utcnow() + timedelta(seconds=float(token_data.get("expires_in", 3600)))
                return str(token_data.get("access_token"))
        except Exception as exc:
            logger.error("Google OAuth token acquisition failed: %s", exc)
            raise


__all__ = ["OAuthProvider", "MSALProvider", "GoogleOAuthProvider"]