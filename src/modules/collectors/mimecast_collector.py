from datetime import datetime
from typing import List, Dict, Optional


class MimecastCollector:
    """Collector for Mimecast alerts (mockable).

    Similar to Proofpoint collector, returns normalized JanuSec events in mock mode.
    """

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret

    async def collect_threats(self, since: datetime, mock: bool = True) -> List[Dict]:
        if mock:
            return [self._normalize_mimecast_alert(a) for a in self._sample_payloads()]

        # TODO: Implement real Mimecast API integration
        raise NotImplementedError("Mimecast API integration not implemented; set mock=True for tests")

    def _normalize_mimecast_alert(self, alert: Dict) -> Dict:
        factors = ["email:mimecast_threat_detected", alert.get("category", "email:unknown")]
        return {
            "event_type": "email_threat",
            "source": "mimecast",
            "timestamp": alert.get("time"),
            "severity": alert.get("severity", "medium"),
            "from_address": alert.get("from"),
            "to_address": alert.get("to"),
            "message_id": alert.get("message_id"),
            "threat_type": alert.get("category"),
            "factors": factors,
            "enrichment": alert.get("meta", {}),
        }

    def _sample_payloads(self) -> List[Dict]:
        now = datetime.utcnow().isoformat() + "Z"
        return [
            {
                "category": "impostor",
                "time": now,
                "severity": "high",
                "from": "ceo@fakecorp.com",
                "to": "finance@example.com",
                "message_id": "<mime-123@example.com>",
                "meta": {"impersonation_type": "display_name"},
            }
        ]


__all__ = ["MimecastCollector"]
