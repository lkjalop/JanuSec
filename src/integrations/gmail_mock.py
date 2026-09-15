"""Mock Gmail OAuth client for tests (refresh token + access token semantics)."""

import time
from typing import Dict, Any, Optional
from .http_exceptions import RefreshTokenRevoked, HTTPRetryError


class GmailMock:
    def __init__(self, client_id: str, client_secret: str, initial_refresh_token: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self._refresh_token = initial_refresh_token or f"gmail-refresh-{client_id}"
        self._access_token = None
        self._expiry = 0

    def refresh(self) -> Dict[str, Any]:
        if self._refresh_token == 'revoked':
            raise RefreshTokenRevoked('Refresh token revoked')
        if self._refresh_token == 'bad-401':
            raise HTTPRetryError('Unauthorized', retry_after=None, status_code=401)
        now = time.time()
        self._access_token = f"gmail-at-{int(now)}"
        self._expiry = now + 5
        # Rotate refresh token
        self._refresh_token = f"gmail-refresh-{int(now)}"
        return {"access_token": self._access_token, "expires_in": 5, "refresh_token": self._refresh_token}

    def access_token(self) -> Optional[str]:
        now = time.time()
        if self._access_token and now < self._expiry:
            return self._access_token
        return None

    def force_revoke_refresh(self):
        self._refresh_token = 'revoked'
        # Clear any existing access token so next fetch will attempt refresh
        self._access_token = None
        self._expiry = 0
