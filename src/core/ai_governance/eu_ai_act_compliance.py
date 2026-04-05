from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import logging


logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


@dataclass
class AIRiskAssessment:
    risk_id: str
    risk_name: str
    risk_level: RiskLevel
    likelihood: str
    impact: str
    affected_groups: List[str]

    mitigation_measures: List[str] = field(default_factory=list)
    residual_risk_level: Optional[RiskLevel] = None
    assessed_by: str = "system"
    assessed_date: str = ""
    next_review_date: str = ""
    status: str = "active"  # active | mitigated | accepted | transferred
    related_incidents: List[str] = field(default_factory=list)
    related_vulnerabilities: List[str] = field(default_factory=list)


class EUAIActRiskManagement:
    """Minimal EU AI Act Article 9 risk management register."""

    def __init__(self) -> None:
        self.risks: Dict[str, AIRiskAssessment] = {}
        self._load_baseline_risks()

    def _load_baseline_risks(self) -> None:
        now = datetime.now()
        review = (now + timedelta(days=90)).isoformat()
        self.risks = {
            "AI-RISK-001": AIRiskAssessment(
                risk_id="AI-RISK-001",
                risk_name="Prompt Injection Attack",
                risk_level=RiskLevel.HIGH,
                likelihood="high",
                impact="major",
                affected_groups=["end_users", "operators", "data_subjects"],
                mitigation_measures=[
                    "Input sanitization",
                    "Model output validation",
                    "Audit logging of prompts",
                ],
                residual_risk_level=RiskLevel.LIMITED,
                assessed_date=now.isoformat(),
                next_review_date=review,
                status="active",
            ),
            "AI-RISK-002": AIRiskAssessment(
                risk_id="AI-RISK-002",
                risk_name="Bias & Fairness",
                risk_level=RiskLevel.LIMITED,
                likelihood="medium",
                impact="moderate",
                affected_groups=["data_subjects"],
                mitigation_measures=["Dataset card review", "Bias tests"],
                residual_risk_level=RiskLevel.LIMITED,
                assessed_date=now.isoformat(),
                next_review_date=review,
                status="active",
            ),
        }

    def get_risk_register(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in self.risks.values():
            out.append(
                {
                    "risk_id": r.risk_id,
                    "risk_name": r.risk_name,
                    "risk_level": r.risk_level.value,
                    "likelihood": r.likelihood,
                    "impact": r.impact,
                    "affected_groups": list(r.affected_groups),
                    "mitigation_measures": list(r.mitigation_measures),
                    "residual_risk_level": r.residual_risk_level.value if r.residual_risk_level else None,
                    "assessed_by": r.assessed_by,
                    "assessed_date": r.assessed_date,
                    "next_review_date": r.next_review_date,
                    "status": r.status,
                    "related_incidents": list(r.related_incidents),
                    "related_vulnerabilities": list(r.related_vulnerabilities),
                }
            )
        return out

    def assess_event_risk(self, event_id: str, decision_factors: List[str]) -> Optional[str]:
        """Naive factor->risk linking for register traceability."""
        triggers = {
            "AI-RISK-001": ["prompt_injection_detected", "llm_anomaly"],
            "AI-RISK-002": ["bias_flag", "demographic_disparity"],
        }
        for rid, pats in triggers.items():
            if any(p in (decision_factors or []) for p in pats):
                if rid in self.risks:
                    self.risks[rid].related_incidents.append(event_id)
                    return rid
        return None

    def generate_article_9_report(self) -> Dict[str, Any]:
        now = datetime.now()
        high = [r for r in self.risks.values() if r.risk_level == RiskLevel.HIGH]
        mitigated = [r for r in self.risks.values() if r.status == "mitigated"]
        overdue = [
            r
            for r in self.risks.values()
            if (r.next_review_date and datetime.fromisoformat(r.next_review_date) < now)
        ]
        next_review = None
        try:
            next_review = min(r.next_review_date for r in self.risks.values() if r.next_review_date)
        except Exception:
            next_review = None
        return {
            "compliance_article": "EU AI Act - Article 9",
            "assessment_date": now.isoformat(),
            "total_risks_identified": len(self.risks),
            "high_risks": len(high),
            "mitigated_risks": len(mitigated),
            "overdue_reviews": len(overdue),
            "next_required_review": next_review,
            "risk_register": self.get_risk_register(),
        }


__all__ = [
    "RiskLevel",
    "AIRiskAssessment",
    "EUAIActRiskManagement",
]

