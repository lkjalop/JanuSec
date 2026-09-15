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

TOKEN_PROVIDER = "email:defender"


@dataclass
class GraphConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    scope: str = "https://graph.microsoft.com/.default"
    graph_base: str = "https://graph.microsoft.com"

    @property
    def token_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"


class DefenderConnector:
    """Microsoft Defender for O365 connector leveraging Microsoft Graph."""

    def __init__(
        self,
        cfg: GraphConfig,
        token_store: TokenStore,
        *,
        http_client: Optional[HttpClientProtocol] = None,
        timeout: float = 30.0,
    ) -> None:
        self.cfg = cfg
        self.token_store = token_store
        self._client = http_client or ensure_async_client(cfg.graph_base)
        self._owns_client = http_client is None
        self._timeout = timeout

    async def close(self) -> None:
        if self._owns_client and hasattr(self._client, "aclose"):
            await self._client.aclose()  # type: ignore[attr-defined]

    async def fetch_security_alerts(
        self,
        tenant_id: str,
        *,
        top: int = 100,
        filter_query: Optional[str] = None,
    ) -> List[NormalizedEmailEvent]:
        token = await self._ensure_token(tenant_id)
        params: Dict[str, Any] = {"$top": max(1, min(top, 200))}
        if filter_query:
            params["$filter"] = filter_query

        payload = await self._request_json(
            "GET",
            "/v1.0/security/alerts",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        alerts = payload.get("value") or []
        return [self._normalize_alert(alert) for alert in alerts]

    async def _ensure_token(self, tenant_id: str) -> str:
        cached = await self.token_store.get_token(tenant_id, TOKEN_PROVIDER)
        if cached:
            expires_at = cached.get("expires_at")
            if isinstance(expires_at, (int, float)) and expires_at - datetime.utcnow().timestamp() > 60:
                token = cached.get("access_token")
                if token:
                    return token
        data = await self._exchange_client_credentials()
        access_token = data.get("access_token")
        if not access_token:
            raise EmailConnectorError("Graph token response missing access_token")
        expires_in = int(data.get("expires_in", 3600))
        expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        record = dict(data)
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
                "scope": self.cfg.scope,
            },
        )

    def _normalize_alert(self, alert: Dict[str, Any]) -> NormalizedEmailEvent:
        entities = alert.get("entities") or []
        email_entity = next(
            (
                e
                for e in entities
                if any(keyword in str(e.get("@odata.type", "")).lower() for keyword in ("mailbox", "email", "emailentity"))
            ),
            {},
        )

        sender = email_entity.get("sender") or email_entity.get("from")
        recipient = email_entity.get("recipient") or email_entity.get("to")
        urls = [
            UrlInfo(url=str(u.get("url") or ""), domain=extract_domain(u.get("url")))
            for u in (email_entity.get("urls") or [])
            if u
        ]
        attachments = email_entity.get("attachments") or []

        return NormalizedEmailEvent(
            event_id=str(alert.get("id") or email_entity.get("networkMessageId") or f"defender-{alert.get('createdDateTime')}"),
            event_type=str(alert.get("category") or "defender_alert"),
            timestamp=parse_timestamp(alert.get("createdDateTime")),
            source_platform="defender_o365",
            message_id=email_entity.get("networkMessageId"),
            sender=sender,
            sender_domain=extract_domain(sender),
            recipient=recipient,
            subject=email_entity.get("subject") or alert.get("title"),
            body_preview=(alert.get("description") or email_entity.get("snippet") or "")[:500],
            urls=urls,
            url_count=len(urls),
            attachments=attachments,
            attachment_count=len(attachments),
            triage_status=alert.get("status"),
            triage_verdict=alert.get("severity"),
            triage_timestamp=parse_timestamp(alert.get("lastModifiedDateTime")) if alert.get("lastModifiedDateTime") else None,
            triage_analyst=alert.get("assignedTo"),
            threat_type=str(alert.get("threatDisplayName") or "phishing").lower(),
            threat_score=float(alert.get("riskScore") or 0.0),
            raw_event=alert,
        )

    async def _request_json(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        async def _call():
            resp = await self._client.request(method, url, timeout=self._timeout, **kwargs)
            return await json_or_error(resp)

        return await with_retry(_call)


__all__ = ["GraphConfig", "DefenderConnector"]
