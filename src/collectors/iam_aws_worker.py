from __future__ import annotations

"""AWS IAM CloudTrail worker.

This worker polls CloudTrail for IAM events, persists pagination/state cursors,
and forwards normalized payloads to the IAM ingest API.  It is intentionally
defensive so that missing AWS dependencies never crash the wider platform.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.integrations.tenant_store import TenantStore

logger = logging.getLogger(__name__)

try:  # pragma: no cover - exercised via dependency injection in tests
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:  # pragma: no cover - exercised via dependency injection in tests
    import boto3  # type: ignore

    _BOTO_AVAILABLE = True
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    _BOTO_AVAILABLE = False


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1]
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        return None


class AWSIAMCollector:
    """Poll AWS CloudTrail for IAM events and forward to ingest API."""

    def __init__(
        self,
        tenant_id: str,
        region: Optional[str] = None,
        *,
        client_factory: Optional[Callable[[], Any]] = None,
        http_client: Optional[Any] = None,
        tenant_store: Optional[TenantStore] = None,
        max_events: Optional[int] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.region = region or os.getenv("AWS_REGION") or "us-east-1"
        self._store = tenant_store or TenantStore()
        self._client_factory = client_factory or self._default_client_factory
        self._http_client = http_client
        self._max_events = max_events or int(os.getenv("AWS_IAM_MAX_EVENTS", "1000"))

        self._next_token: Optional[str] = self._store.load_cursor(tenant_id, "aws", "cloudtrailNextToken")
        self._last_ts_cursor: Optional[str] = self._store.load_cursor(tenant_id, "aws", "cloudtrailLastTs")
        self._last_poll_ts: Optional[int] = None
        self._last_forward_count: int = 0
        self._last_error: Optional[str] = None
        self._metrics_path = Path(os.getenv("AWS_IAM_RUN_LOG", "logs/collectors/aws_iam/run.log"))

    # ------------------------------------------------------------------ helpers
    def _default_client_factory(self) -> Optional[Any]:
        if not _BOTO_AVAILABLE or boto3 is None:
            return None
        try:
            return boto3.client("cloudtrail", region_name=self.region)  # type: ignore
        except Exception:  # pragma: no cover - boto misconfig
            logger.exception("Failed to build CloudTrail client")
            return None

    def _normalize_event(self, payload: Dict[str, Any], outer: Dict[str, Any]) -> Dict[str, Any]:
        event_time = payload.get("eventTime") or outer.get("EventTime")
        if isinstance(event_time, datetime):
            event_time = event_time.isoformat()
        user_identity = payload.get("userIdentity") or outer.get("Username")
        normalized = {
            "eventTime": event_time,
            "eventName": payload.get("eventName") or outer.get("EventName"),
            "eventSource": payload.get("eventSource") or outer.get("EventSource"),
            "awsRegion": payload.get("awsRegion") or outer.get("AwsRegion") or self.region,
            "userIdentity": user_identity,
            "sourceIp": payload.get("sourceIPAddress") or outer.get("SourceIPAddress"),
            "requestParameters": payload.get("requestParameters") or outer.get("RequestParameters"),
            "responseElements": payload.get("responseElements") or outer.get("ResponseElements"),
            "raw": payload or outer,
        }
        return normalized

    def _record_metrics(self, action: str, meta: Dict[str, Any]) -> None:
        payload = {
            "ts": int(time.time()),
            "tenant": self.tenant_id,
            "region": self.region,
            "action": action,
            **meta,
        }
        try:
            self._metrics_path.parent.mkdir(parents=True, exist_ok=True)
            with self._metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload) + "\n")
        except Exception:
            logger.debug("Failed to write AWS IAM metrics", exc_info=True)

    # ------------------------------------------------------------------ polling
    async def poll_cloudtrail(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        self._last_poll_ts = int(time.time())
        client = self._client_factory()
        if client is None:
            logger.warning("AWSIAMCollector inactive (boto3 client unavailable)")
            return events

        kwargs: Dict[str, Any] = {"MaxResults": min(self._max_events, 50)}
        if self._next_token:
            kwargs["NextToken"] = self._next_token
        elif self._last_ts_cursor:
            start = _parse_iso(self._last_ts_cursor)
            if start:
                kwargs["StartTime"] = start

        fetched = 0
        newest_ts: Optional[str] = None
        try:
            while True:
                resp = client.lookup_events(**kwargs)
                for item in resp.get("Events", []):
                    detail = item.get("CloudTrailEvent")
                    if isinstance(detail, str):
                        try:
                            payload = json.loads(detail)
                        except json.JSONDecodeError:
                            payload = {}
                    else:
                        payload = detail or {}
                    normalized = self._normalize_event(payload, item)
                    events.append(normalized)
                    fetched += 1
                    ts = normalized.get("eventTime")
                    if isinstance(ts, str):
                        newest_ts = ts
                    if fetched >= self._max_events:
                        break
                if fetched >= self._max_events:
                    break
                next_token = resp.get("NextToken")
                if not next_token:
                    self._next_token = None
                    break
                self._next_token = next_token
                kwargs = {"NextToken": next_token, "MaxResults": min(self._max_events - fetched, 50)}

            if self._next_token:
                self._store.save_cursor(self.tenant_id, "aws", "cloudtrailNextToken", self._next_token)
            if newest_ts:
                self._last_ts_cursor = newest_ts
                self._store.save_cursor(self.tenant_id, "aws", "cloudtrailLastTs", newest_ts)
            self._last_error = None
            self._record_metrics("poll", {"event_count": len(events), "status": "ok"})
        except Exception as exc:  # pragma: no cover - boto instrumentation
            self._last_error = str(exc)
            logger.exception("AWS CloudTrail lookup failed")
            self._record_metrics("poll", {"event_count": len(events), "status": "error"})
        return events

    # ---------------------------------------------------------------- ingestion
    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        """Forward normalized events to IAM ingest API."""
        if not events:
            return 0

        base = os.getenv("API_BASE_URL", "http://localhost:8080")
        api_key = os.getenv("API_KEY")
        url = f"{base.rstrip('/')}/api/v1/iam/ingest/aws"
        headers = {"x-api-key": api_key, "Content-Type": "application/json"}

        try:
            if self._http_client is not None:
                resp = await self._http_client.post(url, headers=headers, json={"events": events})
            else:
                if httpx is None:
                    logger.warning("httpx unavailable; skipping AWS IAM forward")
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
            logger.exception("failed to forward AWS IAM events")
            self._record_metrics("forward", {"event_count": len(events), "status": "error"})
            return 0

    # ----------------------------------------------------------------- loop
    async def start_loop(self, interval_sec: Optional[int] = None) -> None:
        """Background loop: poll CloudTrail and forward to ingest periodically."""
        interval = interval_sec or int(os.getenv("AWS_IAM_POLL_INTERVAL", "300"))
        while True:
            try:
                events = await self.poll_cloudtrail()
                if events:
                    await self.forward_to_ingest(events)
            except Exception:  # pragma: no cover - loop guard
                logger.exception("AWSIAMCollector loop error")
            await asyncio.sleep(interval)

    # ---------------------------------------------------------------- health
    def health_snapshot(self) -> Dict[str, Any]:
        return {
            "tenant": self.tenant_id,
            "region": self.region,
            "next_token": self._next_token,
            "last_ts_cursor": self._last_ts_cursor,
            "last_poll_ts": self._last_poll_ts,
            "last_forward_count": self._last_forward_count,
            "boto_available": _BOTO_AVAILABLE,
            "last_error": self._last_error,
        }


__all__ = ["AWSIAMCollector"]
