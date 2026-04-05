"""Simple OAuth token manager for unit tests.

Provides deterministic token issuance and refresh semantics. Tests can
manipulate time by patching `time.time()` if needed.
"""

import time
from typing import Dict, Any, Optional


class OAuthTokenManager:
    def __init__(self, client_id: str, client_secret: str, expires_in: int = 3600):
        self.client_id = client_id
        self.client_secret = client_secret
        self.expires_in = expires_in
        self._token: Optional[str] = None
        self._expiry: float = 0.0

    def get_token(self) -> Dict[str, Any]:
        now = time.time()
        if not self._token or now >= self._expiry:
            self._token = f"token-{self.client_id}-{int(now)}"
            self._expiry = now + self.expires_in
        return {"access_token": self._token, "expires_in": int(self._expiry - now)}

    def force_expire(self) -> None:
        self._expiry = 0
