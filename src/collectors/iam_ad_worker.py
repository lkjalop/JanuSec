from __future__ import annotations

"""Active Directory event collector.

Polls LDAP DirSync feeds for object changes and forwards normalized events
into the IAM ingest API. The implementation mirrors the other IAM workers:
cursor persistence via TenantStore, optional dependency injection for tests,
and structured metrics/health snapshots for the Multi-Domain Health panel.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.integrations.tenant_store import TenantStore

try:  # pragma: no cover - real LDAP only available in production envs
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:  # pragma: no cover
    from ldap3 import ALL, Connection, Server  # type: ignore

    _LDAP_AVAILABLE = True
except Exception:  # pragma: no cover
    Connection = None  # type: ignore
    Server = None  # type: ignore
    _LDAP_AVAILABLE = False

LOGGER = logging.getLogger(__name__)


class ActiveDirectoryCollector:
    """Poll Active Directory change logs and forward IAM events."""

    def __init__(
        self,
        tenant_id: str,
        *,
        server_url: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        base_dn: Optional[str] = None,
        connection_factory: Optional[Callable[[], Any]] = None,
        http_client: Optional[Any] = None,
        tenant_store: Optional[TenantStore] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.server_url = server_url or os.getenv("AD_SERVER_URL")
        self.user = user or os.getenv("AD_BIND_USER")
        self.password = password or os.getenv("AD_BIND_PASSWORD")
        self.base_dn = base_dn or os.getenv("AD_BASE_DN")
        self._store = tenant_store or TenantStore()
        self._connection_factory = connection_factory or self._default_connection_factory
        self._http_client = http_client

        self._cookie = self._store.load_cursor(tenant_id, "ad", "dirsync_cookie")
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None
        self._metrics_path = Path(os.getenv("AD_IAM_RUN_LOG", "logs/collectors/ad_iam/run.log"))

    # ---------------------------------------------------------------- helpers
    def _default_connection_factory(self) -> Optional[Any]:
        if not _LDAP_AVAILABLE or not all([self.server_url, self.user, self.password, self.base_dn]):
            return None
        try:
            server = Server(self.server_url, get_info=ALL)  # type: ignore
            return Connection(server, user=self.user, password=self.password, authentication="SIMPLE", auto_bind=True)  # type: ignore
        except Exception:  # pragma: no cover - live LDAP misconfig
            LOGGER.exception("Failed to bind Active Directory connection")
            return None

    def _record_metrics(self, action: str, meta: Dict[str, Any]) -> None:
        payload = {
            "ts": int(time.time()),
            "tenant": self.tenant_id,
            "server_url": self.server_url,
            "action": action,
            **meta,
        }
        try:
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with self._metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload) + "\n")
        except Exception:
            LOGGER.debug("Failed to write AD IAM metrics", exc_info=True)

    @staticmethod
    def _entry_to_dict(entry: Any) -> Dict[str, Any]:
        if hasattr(entry, "entry_to_json"):
            try:
                return json.loads(entry.entry_to_json())
            except Exception:
                return {}
        if isinstance(entry, dict):
            return entry
        return {}

    # ---------------------------------------------------------------- polling
    async def poll_changes(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        self._last_poll_ts = int(time.time())
        conn = self._connection_factory()
        if conn is None:
            LOGGER.warning("ActiveDirectoryCollector inactive (deps/creds missing)")
            return events

        try:
            controls = {"dirSync": {"flags": 0, "maxBytes": 0, "cookie": self._cookie}}
            extend = getattr(conn, "extend", None)
            if extend and hasattr(extend, "microsoft_dir_sync"):
                extend.microsoft_dir_sync(  # type: ignore[attr-defined]
                    self.base_dn,
                    ["whenChanged", "userPrincipalName", "memberOf"],
                    controls=controls,
                )
            for entry in getattr(conn, "entries", []):
                raw = self._entry_to_dict(entry)
                events.append(
                    {
                        "timestamp": self._parse_dt(getattr(getattr(entry, "whenChanged", None), "value", None)),
                        "user": getattr(entry, "userPrincipalName", None),
                        "groups": list(getattr(entry, "memberOf", []) or []),
                        "raw": raw or {"dn": getattr(entry, "entry_dn", None)},
                    }
                )
            cookie = None
            result = getattr(conn, "result", None)
            if isinstance(result, dict):
                cookie = result.get("controls", {}).get("dirSync", {}).get("value", {}).get("cookie")
            if cookie:
                self._cookie = cookie
                self._store.save_cursor(self.tenant_id, "ad", "dirsync_cookie", cookie)
            if hasattr(conn, "unbind"):
                conn.unbind()
            self._last_error = None
            self._record_metrics("poll", {"event_count": len(events), "status": "ok"})
        except Exception as exc:  # pragma: no cover - LDAP instrumentation
            self._last_error = str(exc)
            LOGGER.exception("ActiveDirectoryCollector poll failed")
            self._record_metrics("poll", {"event_count": len(events), "status": "error"})
        return events

    # --------------------------------------------------------------- ingestion
    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0

        base = os.getenv("API_BASE_URL", "http://localhost:8080")
        api_key = os.getenv("API_KEY")
        url = f"{base.rstrip('/')}/api/v1/iam/ingest/ad"
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}

        try:
            if self._http_client is not None:
                resp = await self._http_client.post(url, headers=headers, json={"events": events})
            else:
                if httpx is None:
                    LOGGER.warning("httpx unavailable; skipping AD IAM forward")
                    return 0
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(url, headers=headers, json={"events": events})
            if hasattr(resp, "raise_for_status"):
                resp.raise_for_status()
            count = len(events)
            self._last_forward_count = count
            self._record_metrics("forward", {"event_count": count, "status": "ok"})
            return count
        except Exception:
            self._last_error = "forward_failed"
            LOGGER.exception("Failed to forward AD IAM events")
            self._record_metrics("forward", {"event_count": len(events), "status": "error"})
            return 0

    # ----------------------------------------------------------------- loop
    async def start_loop(self, interval_seconds: Optional[int] = None) -> None:
        interval = interval_seconds or int(os.getenv("AD_IAM_POLL_INTERVAL", "600"))
        while True:
            try:
                events = await self.poll_changes()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover - guardrails
                LOGGER.exception("ActiveDirectoryCollector loop error")
            await asyncio.sleep(interval)

    # ---------------------------------------------------------------- health
    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "server_url": self.server_url,
            "base_dn": self.base_dn,
            "cookie_present": bool(self._cookie),
            "ldap_available": _LDAP_AVAILABLE,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "last_error": self._last_error,
        }

    @staticmethod
    def _parse_dt(value: Any) -> Optional[str]:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return value
        return None


__all__ = ["ActiveDirectoryCollector"]
