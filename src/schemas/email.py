from __future__ import annotations
from datetime import datetime
import uuid
from typing import List, Optional, Any, Union
from pydantic import BaseModel, Field, model_validator


class EmailVerdict(str):
    UNKNOWN = "unknown"
    DELIVERED = "delivered"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


class ThreatType(str):
    PHISHING = "phishing"
    BEC = "bec"
    MALWARE = "malware"
    SUPPLY_CHAIN = "supply_chain"


class UrlInfo(BaseModel):
    url: str
    domain: Optional[str] = None
    verdict: Optional[str] = None


class NormalizedEmailEvent(BaseModel):
    """Canonical email event used by connectors and correlation engine.

    Clean, single implementation aligned with ADVANCED_EMAIL_THREAT_DETECTION_v2.md.
    Includes a validator to normalize timestamps passed as str/float.
    """

    # Core
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    event_type: str = "email"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_platform: Optional[str] = None

    # Message
    message_id: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    body_preview: Optional[str] = None

    # URLs and attachments
    urls: List[UrlInfo] = Field(default_factory=list)
    url_count: int = 0
    attachments: List[dict] = Field(default_factory=list)
    attachment_count: int = 0

    # Auth results
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None

    # Human signal fields
    was_reported: bool = False
    reported_by: Optional[str] = None
    report_timestamp: Optional[datetime] = None
    reporter_comment: Optional[str] = None
    triage_status: Optional[str] = None
    triage_verdict: Optional[str] = None
    triage_analyst: Optional[str] = None
    triage_timestamp: Optional[datetime] = None
    human_reported: bool = False
    human_confidence_boost: float = 0.0
    cluster_id: Optional[str] = None
    similar_reports_count: int = 0

    # Supply chain indicators
    targets_developer: bool = False
    developer_role_detected: Optional[str] = None
    references_package_registry: bool = False
    package_registries_mentioned: List[str] = Field(default_factory=list)
    references_code_platform: bool = False
    code_platforms_mentioned: List[str] = Field(default_factory=list)
    references_cicd: bool = False
    cicd_platforms_mentioned: List[str] = Field(default_factory=list)
    oauth_consent_attempted: bool = False
    oauth_scopes_requested: List[str] = Field(default_factory=list)
    supply_chain_risk_score: float = 0.0

    # Correlation fields
    affected_user_id: Optional[str] = None
    affected_user_roles: List[str] = Field(default_factory=list)
    affected_endpoint: Optional[str] = None
    related_repositories: List[str] = Field(default_factory=list)
    related_packages: List[str] = Field(default_factory=list)
    attack_chain_id: Optional[str] = None
    attack_chain_stage: Optional[int] = None

    # Classification
    verdict: str = EmailVerdict.UNKNOWN
    threat_type: str = ThreatType.PHISHING
    threat_score: float = 0.0

    raw_event: Optional[Any] = None

    @model_validator(mode="before")
    def _normalize_timestamp(cls, values: Any):  # type: ignore[override]
        try:
            ts = values.get("timestamp")
            if isinstance(ts, (int, float)):
                values["timestamp"] = datetime.fromtimestamp(ts)
            elif isinstance(ts, str):
                try:
                    # Accept ISO 8601 or similar; strip trailing Z
                    values["timestamp"] = datetime.fromisoformat(ts.replace("Z", ""))
                except Exception:
                    pass
        except Exception:
            pass
        return values

    def calculate_supply_chain_risk(self) -> float:
        score = 0.0
        if self.targets_developer:
            score += 0.3
        if self.references_package_registry:
            score += 0.2
        if self.references_code_platform:
            score += 0.2
        if self.references_cicd:
            score += 0.2
        if self.oauth_consent_attempted:
            score += 0.3

        spf = (self.spf_result or "").lower()
        dmarc = (self.dmarc_result or "").lower()
        if spf == "fail" or dmarc == "fail":
            score += 0.1

        self.supply_chain_risk_score = min(score, 1.0)
        return self.supply_chain_risk_score


__all__ = ["NormalizedEmailEvent", "UrlInfo", "EmailVerdict", "ThreatType"]
