"""Mock MSAL-like client for tests.

Provides `acquire_token_silent`/`acquire_token_by_refresh_token` semantics.
"""

import time
from typing import Dict, Any, Optional
from .http_exceptions import RefreshTokenRevoked, HTTPRetryError


class MSALMock:
    def __init__(self, client_id: str, client_secret: str, initial_refresh_token: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token = None
        self._access_expiry = 0
        self._refresh_token = initial_refresh_token or f"refresh-{client_id}-init"

    def acquire_token_silent(self, scopes: list[str]) -> Optional[Dict[str, Any]]:
        now = time.time()
        if self._access_token and now < self._access_expiry:
            return {"access_token": self._access_token, "expires_in": int(self._access_expiry - now)}
        return None

    def acquire_token_by_refresh_token(self, refresh_token: str, scopes: list[str]) -> Dict[str, Any]:
        # Simulate revoked token
        if refresh_token == 'revoked':
            raise RefreshTokenRevoked('Refresh token revoked')
        # Simulate backend 401 on certain token
        if refresh_token == 'bad-401':
            raise HTTPRetryError('Unauthorized', retry_after=None, status_code=401)
        now = time.time()
        self._access_token = f"msal-at-{int(now)}"
        self._access_expiry = now + 5  # short expiry for tests
        # rotate refresh token occasionally
        self._refresh_token = f"refresh-{int(now)}"
        return {"access_token": self._access_token, "expires_in": 5, "refresh_token": self._refresh_token}

    def get_refresh_token(self) -> str:
        return self._refresh_token
