from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.connectors.email.common import (
    EmailConnectorError,
    HttpClientProtocol,
    ensure_async_client,
    extract_domain,
    json_or_error,
    parse_timestamp,
    with_retry,
)
from src.integrations.auth.token_store import TokenStore
from src.schemas.email import NormalizedEmailEvent, UrlInfo

TOKEN_PROVIDER = "email:abnormal"


@dataclass
class AbnormalConfig:
    base_url: str = "https://api.abnormalsecurity.com"
    token_endpoint: str = "/oauth/token"
    alerts_endpoint: str = "/v1/alerts"
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class AbnormalConnector:
    """Abnormal Security connector with OAuth, pagination, and normalization."""

    def __init__(
        self,
        cfg: AbnormalConfig,
        token_store: TokenStore,
        *,
        http_client: Optional[HttpClientProtocol] = None,
        timeout: float = 30.0,
    ) -> None:
        if not (cfg.client_id and cfg.client_secret):
            raise EmailConnectorError("AbnormalConnector requires client credentials")
        self.cfg = cfg
        self.token_store = token_store
        self._client = http_client or ensure_async_client(cfg.base_url)
        self._owns_client = http_client is None
        self._timeout = timeout

    async def close(self) -> None:
        if self._owns_client and hasattr(self._client, "aclose"):
            await self._client.aclose()  # type: ignore[attr-defined]

    async def fetch_alerts(
        self,
        tenant_id: str,
        *,
        since: Optional[datetime] = None,
        limit: int = 100,
        severity: Optional[str] = None,
    ) -> List[NormalizedEmailEvent]:
        token = await self._ensure_token(tenant_id)
        params: Dict[str, Any] = {"limit": max(1, min(limit, 200))}
        if since:
            params["createdAfter"] = since.isoformat() + "Z"
        if severity:
            params["severity"] = severity

        alerts: List[NormalizedEmailEvent] = []
        next_cursor: Optional[str] = None

        while len(alerts) < limit:
            if next_cursor:
                params["pageToken"] = next_cursor
            payload = await self._request_json(
                "GET",
                self.cfg.alerts_endpoint,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
            raw_alerts = payload.get("alerts") or []
            for alert in raw_alerts:
                alerts.append(self._normalize_alert(alert))
                if len(alerts) >= limit:
                    break
            next_cursor = payload.get("nextPageToken")
            if not next_cursor or not raw_alerts:
                break

        return alerts

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
            raise EmailConnectorError("Abnormal token response missing access_token")
        expires_in = int(new_token.get("expires_in", 3600))
        expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        record = dict(new_token)
        record["expires_at"] = expiry.timestamp()
        await self.token_store.store_token(tenant_id, TOKEN_PROVIDER, record, expiry)
        return access_token

    async def _exchange_client_credentials(self) -> Dict[str, Any]:

        return await self._request_json(
            "POST",
            self.cfg.token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
            },
        )

    def _normalize_alert(self, alert: Dict[str, Any]) -> NormalizedEmailEvent:
        email_data = alert.get("email", {})
        ts = parse_timestamp(email_data.get("receivedAt") or alert.get("createdAt"))
        sender = email_data.get("sender")
        urls = [
            UrlInfo(url=str(item.get("url") or ""), domain=extract_domain(item.get("url")))
            for item in (email_data.get("urls") or [])
            if item
        ]
        attachments = email_data.get("attachments") or []

        return NormalizedEmailEvent(
            event_id=str(alert.get("id") or f"abnormal-{int(ts.timestamp())}"),
            event_type="abnormal_alert",
            timestamp=ts,
            source_platform="abnormal",
            message_id=email_data.get("messageId"),
            sender=sender,
            sender_domain=extract_domain(sender),
            recipient=email_data.get("recipient"),
            subject=email_data.get("subject"),
            body_preview=(email_data.get("snippet") or email_data.get("body") or "")[:500],
            urls=urls,
            url_count=len(urls),
            attachments=attachments,
            attachment_count=len(attachments),
            spf_result=email_data.get("spfResult"),
            dkim_result=email_data.get("dkimResult"),
            dmarc_result=email_data.get("dmarcResult"),
            triage_status=alert.get("status"),
            triage_verdict=alert.get("verdict"),
            triage_timestamp=parse_timestamp(alert.get("updatedAt")) if alert.get("updatedAt") else None,
            triage_analyst=alert.get("assignedTo"),
            threat_type=str(alert.get("threatType") or "phishing").lower(),
            threat_score=float(alert.get("confidence") or 0.0),
            was_reported=bool(alert.get("userReported")),
            raw_event=alert,
        )

    async def _request_json(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        async def _call():
            resp = await self._client.request(method, url, timeout=self._timeout, **kwargs)
            return await json_or_error(resp)

        return await with_retry(_call)


__all__ = ["AbnormalConnector", "AbnormalConfig"]
