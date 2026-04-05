"""Minimal IAM adapter scaffold used by unit tests.

Provides a small, deterministic surface: async `fetch_since`, `ack`, and a
`canonical_event` mapper. This keeps tests fast and avoids external
dependencies. Real providers should subclass and implement network logic.
"""

from dataclasses import dataclass
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    name: str
    settings: Dict[str, Any]


class IAMAdapter:
    """Simple IAM adapter scaffold.

    Methods:
    - `fetch_since`: async generator style fetch returning (events, new_cursor)
    - `ack`: persist cursor (no-op in tests)
    - `canonical_event`: normalize event dicts
    """

    def __init__(self, provider: str = "okta", config: Optional[Dict[str, Any]] = None):
        self.provider = provider.lower()
        self.config = ProviderConfig(name=self.provider, settings=config or {})
        self._cursor: Optional[str] = None
        self._token: Optional[str] = None
        self._token_expiry_ts: int = int(time.time()) + 3600

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Return a small deterministic batch of synthetic events and a new cursor."""
        effective = since or self._cursor or str(int(time.time()) - 300)
        start = int(effective)
        events: List[Dict[str, Any]] = []
        for i in range(3):
            ts = start + i
            raw = {
                "actor": f"user_{self.provider}_{i}",
                "action": "LoginSuccess" if i % 2 == 0 else "LoginFailure",
                "resource": "portal" if self.provider == "azure" else ("okta.app" if self.provider == "okta" else "aws.console"),
                "result": "success" if i % 2 == 0 else "failure",
                "ip": f"192.0.2.{10+i}",
                "user_agent": "unit-test-agent",
                "ts": ts,
            }
            events.append(self.canonical_event(raw))
        new_cursor = str(start + 3)
        return events, new_cursor

    async def connect(self) -> bool:
        # In test mode simply report connected
        # simulate token acquisition
        self._token = f"fake-iam-token-{int(time.time())}"
        self._token_expiry_ts = int(time.time()) + 3600
        return True

    async def health(self) -> Dict[str, Any]:
        now = int(time.time())
        if not self._token or now >= getattr(self, '_token_expiry_ts', 0):
            # refresh token
            self._token = f"fake-iam-token-{now}"
            self._token_expiry_ts = now + 3600
        return {"connected": True, "provider": self.provider, "authenticated": True, "token_expires_in": max(0, self._token_expiry_ts - now)}

    async def ack(self, cursor: Optional[str]) -> bool:
        if cursor:
            self._cursor = cursor
        return True

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "actor": raw.get("actor"),
            "action": raw.get("action"),
            "resource": raw.get("resource"),
            "result": raw.get("result"),
            "ip": raw.get("ip"),
            "user_agent": raw.get("user_agent"),
            "ts": raw.get("ts"),
            "provider": self.provider,
        }

    # Mapping helpers retained for tests that validate provider fixtures.
    def map_cloudtrail_to_canonical(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": event.get("eventID"),
            "ts": event.get("eventTime"),
            "principal": event.get("userIdentity", {}).get("arn"),
            "action": event.get("eventName"),
            "source_ip": event.get("sourceIPAddress"),
            "resource": event.get("resources", []),
            "raw": event,
        }

    def map_okta_event(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": evt.get("eventId"),
            "ts": evt.get("published"),
            "principal": evt.get("actor", {}).get("alternateId"),
            "action": evt.get("action"),
            "source_ip": evt.get("requestContext", {}).get("ipAddress"),
            "raw": evt,
        }

    def map_azure_signin(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": rec.get("id"),
            "ts": rec.get("createdDateTime"),
            "principal": rec.get("userPrincipalName"),
            "action": rec.get("status", {}).get("errorCode", "signIn"),
            "source_ip": rec.get("ipAddress"),
            "raw": rec,
        }

