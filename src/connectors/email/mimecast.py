from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.connectors.email.common import (
    EmailConnectorError,
    HttpClientProtocol,
    RateLimitError,
    ensure_async_client,
    extract_domain,
    json_or_error,
    parse_timestamp,
    with_retry,
)
from src.integrations.auth.token_store import TokenStore
from src.schemas.email import NormalizedEmailEvent, UrlInfo

TOKEN_PROVIDER = "email:mimecast"


@dataclass
class MimecastConfig:
    base_url: str = "https://api.mimecast.com"
    token_endpoint: str = "/oauth/token"
    detections_endpoint: str = "/api/siem/email/detections"
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class MimecastConnector:
    """Production-ready Mimecast connector with OAuth, pagination, and normalization."""

    def __init__(
        self,
        cfg: MimecastConfig,
        token_store: TokenStore,
        *,
        http_client: Optional[HttpClientProtocol] = None,
        timeout: float = 30.0,
    ) -> None:
        self.cfg = cfg
        self.token_store = token_store
        self._client = http_client or ensure_async_client(cfg.base_url)
        self._owns_client = http_client is None
        self._timeout = timeout

        if not (cfg.client_id and cfg.client_secret):
            raise EmailConnectorError("MimecastConnector requires client_id and client_secret")

    async def close(self) -> None:
        if self._owns_client and hasattr(self._client, "aclose"):
            await self._client.aclose()  # type: ignore[attr-defined]

    async def fetch_detections(
        self,
        tenant_id: str,
        *,
        since: Optional[datetime] = None,
        limit: int = 200,
    ) -> List[NormalizedEmailEvent]:
        """Fetch recent detections and normalize into `NormalizedEmailEvent`."""
        token = await self._ensure_token(tenant_id)
        params: Dict[str, Any] = {"limit": max(1, min(limit, 500))}
        if since:
            params["since"] = since.isoformat() + "Z"

        events: List[NormalizedEmailEvent] = []
        next_cursor: Optional[str] = None

        while len(events) < limit:
            if next_cursor:
                params["cursor"] = next_cursor
            payload = await self._request_json(
                "GET",
                self.cfg.detections_endpoint,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
            raw_events = payload.get("data") or []
            for item in raw_events:
                events.append(self._normalize_event(item))
                if len(events) >= limit:
                    break
            next_cursor = payload.get("paging", {}).get("next")
            if not next_cursor or not raw_events:
                break

        return events

    async def _ensure_token(self, tenant_id: str) -> str:
        cached = await self.token_store.get_token(tenant_id, TOKEN_PROVIDER)
        if cached:
            expires_at = cached.get("expires_at")
            if isinstance(expires_at, (int, float)) and expires_at - datetime.utcnow().timestamp() > 60:
                token = cached.get("access_token")
                if token:
                    return token

        new_token = await self._exchange_client_credentials()
        access_token = new_token.get("access_token")
        if not access_token:
            raise EmailConnectorError("Mimecast token response missing access_token")
        expires_in = int(new_token.get("expires_in", 3600))
        expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        record = dict(new_token)
        record["expires_at"] = expiry.timestamp()
        await self.token_store.store_token(tenant_id, TOKEN_PROVIDER, record, expiry)
        return access_token

    async def _exchange_client_credentials(self) -> Dict[str, Any]:
        form = {
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
        }

        return await self._request_json("POST", self.cfg.token_endpoint, data=form)

    def _normalize_event(self, payload: Dict[str, Any]) -> NormalizedEmailEvent:
        urls = [
            UrlInfo(url=str(item.get("url") or ""), domain=extract_domain(item.get("url") or item.get("domain")))
            for item in payload.get("urls", []) or []
            if item
        ]
        attachments = payload.get("attachments") or []
        ts = parse_timestamp(payload.get("timestamp") or payload.get("receivedAt"))
        sender = payload.get("sender") or payload.get("from")
        recipient = payload.get("recipient") or payload.get("to")

        return NormalizedEmailEvent(
            event_id=str(payload.get("id") or payload.get("messageId") or f"mimecast-{int(ts.timestamp())}"),
            event_type=str(payload.get("eventType") or "mimecast_detection"),
            timestamp=ts,
            source_platform="mimecast",
            message_id=payload.get("messageId"),
            sender=sender,
            sender_domain=extract_domain(sender),
            recipient=recipient,
            subject=payload.get("subject"),
            body_preview=(payload.get("snippet") or payload.get("body") or "")[:500],
            urls=urls,
            url_count=len(urls),
            attachments=attachments,
            attachment_count=len(attachments),
            spf_result=(payload.get("spf") or {}).get("result"),
            dkim_result=(payload.get("dkim") or {}).get("result"),
            dmarc_result=(payload.get("dmarc") or {}).get("result"),
            verdict=str(payload.get("verdict") or "unknown"),
            threat_type=str(payload.get("threatType") or "phishing"),
            threat_score=float(payload.get("threatScore") or 0.0),
            raw_event=payload,
        )

    async def _request_json(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        async def _call():
            resp = await self._client.request(method, url, timeout=self._timeout, **kwargs)
            return await json_or_error(resp)

        return await with_retry(_call)


__all__ = ["MimecastConnector", "MimecastConfig"]
