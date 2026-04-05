"""OAuth transport scaffolds for M365 (Graph/EWS) and Gmail.

These are lightweight, test-friendly classes that don't perform real network
IO. In production they should be subclassed or replaced with real HTTP clients.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import time

try:
    from .oauth_mock import OAuthTokenManager
except Exception:
    OAuthTokenManager = None  # type: ignore


@dataclass
class OAuthConfig:
    client_id: str
    client_secret: str
    tenant: Optional[str] = None
    scopes: Optional[List[str]] = None


class BaseTransport:
    def __init__(self, config: OAuthConfig):
        self.config = config
        self._token = None
        self._expiry = 0
        self._token_mgr = None
        if OAuthTokenManager is not None:
            try:
                self._token_mgr = OAuthTokenManager(config.client_id, config.client_secret)
            except Exception:
                self._token_mgr = None

    def ensure_token(self):
        now = time.time()
        if self._token_mgr:
            tk = self._token_mgr.get_token()
            self._token = tk.get("access_token")
            self._expiry = now + int(tk.get("expires_in", 3600))
            return self._token
        if not self._token or now >= self._expiry:
            self._token = f"fake-token-{int(now)}"
            self._expiry = now + 3600
        return self._token

    def token_expires_in(self) -> int:
        now = time.time()
        return max(0, int(self._expiry - now))

    def list_messages(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        raise NotImplementedError()


class M365GraphTransport(BaseTransport):
    def list_messages(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        # deterministic synthetic messages for unit tests
        base = int(since or int(time.time()) - 300)
        return [
            {
                "id": f"m365-{base + i}",
                "ts": base + i,
                "from": "alice@example.com",
                "to": ["bob@example.com"],
                "subject": "Test",
                "body": "Hello",
            }
            for i in range(2)
        ]


class EwsTransport(BaseTransport):
    def list_messages(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        base = int(since or int(time.time()) - 300)
        return [
            {
                "id": f"ews-{base + i}",
                "ts": base + i,
                "from": "service@example.com",
                "to": ["ops@example.com"],
                "subject": "EWS Test",
                "body": "World",
            }
            for i in range(2)
        ]


class GmailTransport(BaseTransport):
    def list_messages(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        base = int(since or int(time.time()) - 300)
        return [
            {
                "id": f"gmail-{base + i}",
                "ts": base + i,
                "from": "charlie@gmail.com",
                "to": ["dave@gmail.com"],
                "subject": "Gmail Test",
                "body": "Hi",
            }
            for i in range(2)
        ]
