from __future__ import annotations

"""GCP IAM Audit Log worker."""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)

try:  # pragma: no cover - dependency injection handles tests
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:  # pragma: no cover - dependency injection handles tests
    from google.cloud import logging as gcp_logging  # type: ignore

    _GCP_AVAILABLE = True
except Exception:  # pragma: no cover
    gcp_logging = None  # type: ignore
    _GCP_AVAILABLE = False


class GCPIAMCollector:
    """Poll GCP Cloud Logging for IAM events and forward to ingest API."""

    def __init__(
        self,
        tenant_id: str,
        project_id: Optional[str] = None,
        *,
        logging_client_factory: Optional[Callable[[], Any]] = None,
        http_client: Optional[Any] = None,
        tenant_store: Optional[TenantStore] = None,
        page_size: Optional[int] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.project_id = project_id or os.getenv("GCP_PROJECT")
        self._store = tenant_store or TenantStore()
        self._client_factory = logging_client_factory or self._default_client_factory
        self._http_client = http_client
        self._page_size = page_size or int(os.getenv("GCP_IAM_PAGE_SIZE", "200"))

        self._page_token: Optional[str] = self._store.load_cursor(tenant_id, "gcp", "auditPageToken")
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None
        self._metrics_path = Path(os.getenv("GCP_IAM_RUN_LOG", "logs/collectors/gcp_iam/run.log"))

    # ------------------------------------------------------------------ helpers
    def _default_client_factory(self) -> Optional[Any]:
        if not _GCP_AVAILABLE or gcp_logging is None:
            return None
        try:
            return gcp_logging.Client(project=self.project_id)  # type: ignore
        except Exception:  # pragma: no cover - credential misconfig
            logger.exception("Failed to build GCP logging client")
            return None

    @staticmethod
    def _entry_to_dict(entry: Any) -> Dict[str, Any]:
        if hasattr(entry, "to_api_repr"):
            return entry.to_api_repr()
        if isinstance(entry, dict):
            return entry
        if hasattr(entry, "payload"):
            payload = entry.payload
            if hasattr(payload, "to_api_repr"):
                return payload.to_api_repr()
            if isinstance(payload, dict):
                return payload
        return {}

    def _normalize_entry(self, source: Dict[str, Any]) -> Dict[str, Any]:
        proto = source.get("protoPayload") or {}
        return {
            "timestamp": source.get("timestamp") or proto.get("timestamp"),
            "methodName": proto.get("methodName"),
            "serviceName": proto.get("serviceName"),
            "authenticationInfo": proto.get("authenticationInfo"),
            "resourceName": proto.get("resourceName") or source.get("resource", {}).get("name"),
            "severity": source.get("severity"),
            "raw": source,
        }

    def _record_metrics(self, action: str, meta: Dict[str, Any]) -> None:
        payload = {
            "ts": int(time.time()),
            "tenant": self.tenant_id,
            "project_id": self.project_id,
            "action": action,
            **meta,
        }
        try:
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with self._metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload) + "\n")
        except Exception:
            logger.debug("Failed to write GCP IAM metrics", exc_info=True)

    # ------------------------------------------------------------------ polling
    async def poll_audit_logs(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        self._last_poll_ts = int(time.time())
        client = self._client_factory()
        if client is None:
            logger.warning("GCPIAMCollector inactive (gcp logging unavailable)")
            return events

        query = os.getenv("GCP_IAM_FILTER", 'protoPayload.serviceName="iam.googleapis.com"')
        kwargs = {
            "filter_": query,
            "max_results": self._page_size,
        }
        if self._page_token:
            kwargs["page_token"] = self._page_token

        try:
            iterator: Iterable[Any] = client.list_entries(**kwargs)  # type: ignore
            for entry in iterator:
                payload = self._entry_to_dict(entry)
                events.append(self._normalize_entry(payload))
            token = getattr(iterator, "next_page_token", None)  # type: ignore
            if token:
                self._page_token = token
                self._store.save_cursor(self.tenant_id, "gcp", "auditPageToken", token)
            else:
                self._page_token = None
                self._store.save_cursor(self.tenant_id, "gcp", "auditPageToken", "")
            self._last_error = None
            self._record_metrics("poll", {"event_count": len(events), "status": "ok"})
        except Exception as exc:  # pragma: no cover - gcp instrumentation
            self._last_error = str(exc)
            logger.exception("GCP Audit Logs polling failed")
            self._record_metrics("poll", {"event_count": len(events), "status": "error"})
        return events

    # ---------------------------------------------------------------- ingestion
    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0

        base = os.getenv("API_BASE_URL", "http://localhost:8080")
        api_key = os.getenv("API_KEY")
        url = f"{base.rstrip('/')}/api/v1/iam/ingest/gcp"
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}

        try:
            if self._http_client is not None:
                resp = await self._http_client.post(url, headers=headers, json={"events": events})
            else:
                if httpx is None:
                    logger.warning("httpx unavailable; skipping GCP IAM forward")
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
            logger.exception("failed to forward GCP IAM events")
            self._record_metrics("forward", {"event_count": len(events), "status": "error"})
            return 0

    # ----------------------------------------------------------------- loop
    async def start_loop(self, interval_sec: Optional[int] = None) -> None:
        """Background loop: poll Audit Logs and forward to ingest periodically."""
        interval = interval_sec or int(os.getenv("GCP_IAM_POLL_INTERVAL", "300"))
        while True:
            try:
                events = await self.poll_audit_logs()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover - loop guard
                logger.exception("GCPIAMCollector loop error")
            await asyncio.sleep(interval)

    # ---------------------------------------------------------------- health
    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "project_id": self.project_id,
            "page_token": self._page_token,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "gcp_logging_available": _GCP_AVAILABLE,
            "last_error": self._last_error,
        }


__all__ = ["GCPIAMCollector"]
