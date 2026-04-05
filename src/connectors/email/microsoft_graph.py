from __future__ import annotations
from typing import Any, Dict, List, Optional
from datetime import datetime

from src.schemas.email import NormalizedEmailEvent


class GraphConfig:
    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id


class MicrosoftGraphConnector:
    """Connector scaffold for Microsoft Graph (Defender O365 signals).

    This scaffold intentionally avoids heavy imports. Implement token
    management and subscription handling in production.
    """

    def __init__(self, cfg: GraphConfig):
        self.cfg = cfg

    async def fetch_security_events(self, since: Optional[datetime] = None) -> List[NormalizedEmailEvent]:
        return []

    async def execute(self, domain: str, entity: str, window: Optional[str] = None, context: Any | None = None, include_body: bool = False) -> Dict[str, Any]:
        """SDK-compatible execute wrapper.

        Returns a dict compatible with telemetry worker expectations. If
        `include_body` is False, avoid returning full message bodies to
        reduce accidental egress of PII. Connectors should respect tenant
        policies in real deployments.
        """
        events = await self.fetch_security_events()
        # Map to lightweight response
        out: Dict[str, Any] = {"enrichment": {}, "latency_ms": 0, "cost_usd": 0.0, "domain": domain, "entity": entity}
        if not events:
            return out
        # Take first event as representative
        ev = events[0]
        try:
            # pydantic model -> dict
            evd = ev.model_dump() if hasattr(ev, 'model_dump') else ev.dict()
        except Exception:
            evd = {}
        out['enrichment'] = {
            'message_id': evd.get('message_id'),
            'subject': evd.get('subject'),
            'sender': evd.get('sender'),
        }
        # Optional metadata to help SPF/DMARC evaluation
        if evd.get('sender'):
            out['envelope_from'] = evd.get('sender')
        if evd.get('raw_event') and isinstance(evd.get('raw_event'), dict):
            # connectors that provide origin IP in their raw event can set it
            out['origin_ip'] = evd.get('raw_event').get('origin_ip')
        if include_body:
            # Provide a safe body string if requested
            body = evd.get('raw_event') or evd.get('body_preview') or ''
            out['message'] = body
        return out
