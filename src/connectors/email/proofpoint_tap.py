from __future__ import annotations

"""Proofpoint TAP connector (clean minimal implementation)."""
from typing import List, Dict, Any
import time
import hmac
import hashlib
import base64
from src.schemas.email import NormalizedEmailEvent
from src.enrichment.email_auth import enrich_email_auth
from src.enrichment.url_normalizer import enrich_urls
from src.enrichment.sandbox_enrichment import enrich_sandbox


class ProofpointTapConnector:
    """Lightweight TAP connector used in tests.

    - verify_signature(payload_bytes, signature_header)
    - parse_events(json_payload) -> List[NormalizedEmailEvent]
    """

    def __init__(self, secret: str | None = None, base_url: str = "https://tap-api-v2.proofpoint.com"):
        self.secret = secret.encode("utf-8") if secret else None
        self.base_url = base_url

    def verify_signature(self, payload: bytes, signature_header: str) -> bool:
        if not self.secret:
            return True
        if not signature_header:
            return False
        try:
            expected = hmac.new(self.secret, payload, hashlib.sha256).digest()
            expected_b64 = base64.b64encode(expected).decode()
            return hmac.compare_digest(expected_b64, signature_header)
        except Exception:
            return False

    def parse_events(self, payload: Dict[str, Any]) -> List[NormalizedEmailEvent]:
        events: List[NormalizedEmailEvent] = []
        for item in payload.get("messages", []) or []:
            ne = NormalizedEmailEvent(
                event_id=item.get("id") or f"pp-{int(time.time()*1000)}",
                event_type=item.get("type") or "gateway_delivery",
                timestamp=item.get("time") or time.time(),
                source_platform="proofpoint",
                message_id=item.get("message_id"),
                sender=item.get("from"),
                sender_domain=(item.get("from") or "").split("@")[-1],
                recipient=item.get("to"),
                subject=item.get("subject"),
                body_preview=(item.get("body") or "")[:512],
                urls=item.get("urls", []),
                url_count=len(item.get("urls", []) or []),
                attachments=item.get("attachments", []),
                attachment_count=len(item.get("attachments", []) or []),
                raw_event=item,
            )
            try:
                enrich_email_auth(ne)
                enrich_urls(ne)
                enrich_sandbox(ne)
            except Exception:
                pass
            events.append(ne)
        return events

    def fetch_events(self, since_ts: float | None = None) -> List[Dict[str, Any]]:
        """Scaffold; in production implement REST polling.
        Returns a list of raw message dicts.
        """
        return []


__all__ = ["ProofpointTapConnector"]
