from datetime import datetime, timedelta
from typing import List, Dict, Optional


class ProofpointTAPCollector:
    """Collector for Proofpoint TAP (simulated/mock mode).

    Methods:
    - collect_threats(since, mock=True): returns list of normalized events

    In production, implement API auth and pagination. For now, mock mode
    returns sample Proofpoint payloads normalized to JanuSec event schema.
    """

    def __init__(self, api_key: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_key = api_key
        self.api_secret = api_secret

    async def collect_threats(self, since: datetime, mock: bool = True) -> List[Dict]:
        if mock:
            return [self._normalize_proofpoint_threat(p) for p in self._sample_payloads()]

        # TODO: Implement real API calls to Proofpoint TAP here.
        raise NotImplementedError("Proofpoint API integration not implemented; set mock=True for tests")

    def _normalize_proofpoint_threat(self, threat: Dict) -> Dict:
        classification_mapping = {
            "phish": "email:phishing",
            "malware": "email:malware_attachment",
            "impostor": "email:impostor_sender",
            "spam": "email:spam",
        }

        factors = [
            "email:proofpoint_threat_detected",
            classification_mapping.get(threat.get("classification"), "email:unknown_threat"),
        ]

        if threat.get("threatStatus") == "active":
            factors.append("email:active_threat")

        return {
            "event_type": "email_threat",
            "source": "proofpoint_tap",
            "timestamp": threat.get("threatTime"),
            "severity": threat.get("severity", "medium"),
            "from_address": threat.get("sender"),
            "to_address": threat.get("recipient"),
            "message_id": threat.get("messageID"),
            "threat_type": threat.get("threatType"),
            "threat_url": threat.get("threatUrl"),
            "campaign_id": threat.get("campaignID"),
            "factors": factors,
            "enrichment": {
                "proofpoint_classification": threat.get("classification"),
                "proofpoint_threat_status": threat.get("threatStatus"),
                "proofpoint_campaign": threat.get("campaignID"),
            },
        }

    def _sample_payloads(self) -> List[Dict]:
        now = datetime.utcnow().isoformat() + "Z"
        return [
            {
                "threatType": "url",
                "threatStatus": "active",
                "classification": "phish",
                "threatUrl": "http://evil.example/phish",
                "recipient": "victim@example.com",
                "sender": "attacker@evil.com",
                "messageID": "<msg-abc@example.com>",
                "threatTime": now,
                "campaignID": "campaign_456",
                "severity": "high",
            }
        ]


__all__ = ["ProofpointTAPCollector"]
