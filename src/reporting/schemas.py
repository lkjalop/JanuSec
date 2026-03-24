from __future__ import annotations
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from enum import Enum
import hashlib

from pydantic import BaseModel, Field, field_validator


class PersonaType(str, Enum):
    EXECUTIVE = "executive"
    SOC_ANALYST = "soc_analyst"
    COMPLIANCE = "compliance"
    THREAT_HUNTER = "threat_hunter"
    MSSP = "mssp"


class ExplainabilityLevel(str, Enum):
    MINIMAL = "minimal"
    SUMMARY = "summary"
    DETAILED = "detailed"


class ActionUrgency(str, Enum):
    IMMEDIATE = "immediate"
    URGENT = "urgent"
    NORMAL = "normal"
    LOW = "low"


class DecisionType(str, Enum):
    APPROVE_BUDGET = "approve_budget"
    ESCALATE = "escalate"
    CONTAIN = "contain"
    INVESTIGATE = "investigate"
    REMEDIATE = "remediate"
    NOTIFY = "notify"
    DEFER = "defer"


class EvidenceType(str, Enum):
    LOG_LINE = "log_line"
    FACTOR_EMISSION = "factor"
    GRAPH_EDGE = "graph_edge"
    THREAT_INTEL = "threat_intel"
    BASELINE_DEVIATION = "baseline"
    PIPELINE_STAGE = "pipeline_stage"
    ANALYST_NOTE = "analyst_note"
    HUMAN_CORRECTION = "human_correction"


class Evidence(BaseModel):
    evidence_id: str = Field(..., description="Unique evidence id")
    evidence_type: EvidenceType
    timestamp: datetime
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    raw_content: str
    sha256_hash: str
    extracted_iocs: Dict[str, List[str]] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    tags: List[str] = Field(default_factory=list)
    human_verified: bool = False
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    correction_applied: Optional[str] = None

    @field_validator('sha256_hash')
    def sha_len(cls, v: str) -> str:
        if not isinstance(v, str) or len(v) != 64:
            raise ValueError('sha256_hash must be a 64-char hex string')
        return v.lower()

    def compute_hash(self) -> str:
        return hashlib.sha256(self.raw_content.encode('utf-8')).hexdigest()


class FactorContribution(BaseModel):
    factor_name: str
    factor_category: str
    weight: float
    evidence_count: int
    evidence_refs: List[str]
    contribution_score: float
    reasoning: str
    mitre_techniques: List[str] = Field(default_factory=list)
    confidence_interval: Tuple[float, float] = (0.0, 1.0)
    human_readable_explanation: Optional[str] = None
    analogy: Optional[str] = None

    def get_explanation(self, level: ExplainabilityLevel) -> str:
        if level == ExplainabilityLevel.MINIMAL:
            return self.human_readable_explanation or (self.reasoning.split('.')[0] if self.reasoning else '')
        if level == ExplainabilityLevel.SUMMARY:
            return f"{self.human_readable_explanation or self.reasoning} (confidence: {self.contribution_score:.0%})"
        # detailed
        return (
            f"{self.reasoning}\n"
            f"  Weight: {self.weight:.2f}, Contribution: {self.contribution_score:.2f}\n"
            f"  Evidence: {self.evidence_count} items\n"
            f"  95% CI: [{self.confidence_interval[0]:.2f}, {self.confidence_interval[1]:.2f}]\n"
            f"  MITRE: {', '.join(self.mitre_techniques) or 'N/A'}"
        )


class DecisionGate(BaseModel):
    gate_id: str
    decision_type: DecisionType
    persona: PersonaType
    urgency: ActionUrgency
    question: str
    context: str
    options: List[Dict[str, Any]]
    recommended_option: Optional[str] = None
    recommendation_confidence: float = 0.0
    recommendation_reasoning: str = ""
    action_endpoint: Optional[str] = None
    action_payload_template: Optional[Dict[str, Any]] = None
    deadline: Optional[datetime] = None
    auto_action_if_no_response: Optional[str] = None
    presented_at: datetime = Field(default_factory=datetime.utcnow)
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    decision_made: Optional[str] = None

    def _legacy_type(self) -> str:
        mapping = {
            DecisionType.APPROVE_BUDGET: "budget_approval",
            DecisionType.CONTAIN: "containment_isolation",
            DecisionType.REMEDIATE: "blocklist_update",
            DecisionType.NOTIFY: "disclosure_notification",
            DecisionType.ESCALATE: "investigation_escalation",
            DecisionType.INVESTIGATE: "investigation_escalation",
            DecisionType.DEFER: "defer",
        }
        return mapping.get(self.decision_type, str(self.decision_type.value))

    def __getitem__(self, key: str) -> Any:
        if key == "type":
            return self._legacy_type()
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


class ToolIntegration(BaseModel):
    tool_id: str
    tool_name: str
    action_type: str
    endpoint: str
    method: str = "POST"
    auth_type: str = "api_key"
    payload_template: Dict[str, Any]
    required_fields: List[str] = Field(default_factory=list)
    button_label: str = "Action"
    button_icon: str = "shield"
    confirm_required: bool = True
    success_message: str = "Success"
    failure_message: str = "Failure"
    rollback_endpoint: Optional[str] = None


class RecommendedAction(BaseModel):
    action_id: str
    persona: PersonaType
    urgency: ActionUrgency
    sla_deadline: Optional[datetime] = None
    primary_action: str
    secondary_actions: List[str] = Field(default_factory=list)
    playbook_id: Optional[str] = None
    playbook_steps: List[str] = Field(default_factory=list)
    notify_roles: List[str] = Field(default_factory=list)
    estimated_effort_hours: Optional[float] = None
    estimated_cost_usd: Optional[int] = None
    tool_integrations: List[ToolIntegration] = Field(default_factory=list)
    requires_approval: bool = False
    decision_gate: Optional[DecisionGate] = None


class FeedbackCapture(BaseModel):
    feedback_id: str
    report_id: str
    analyst_id: str
    captured_at: datetime = Field(default_factory=datetime.utcnow)
    correction_type: str
    original_value: Any
    corrected_value: Any
    correction_reasoning: str
    suggested_weight_adjustment: Optional[Dict[str, float]] = None
    suggested_rule_addition: Optional[str] = None
    validated_by_senior: bool = False
    validation_notes: str = ""


class AIDecisionExplanation(BaseModel):
    final_verdict: str
    final_confidence: float = Field(ge=0.0, le=1.0)
    factor_contributions: List[FactorContribution] = Field(default_factory=list)
    summary: Optional[str] = None
    persona_level: ExplainabilityLevel = ExplainabilityLevel.SUMMARY


__all__ = [
    'PersonaType', 'ExplainabilityLevel', 'ActionUrgency', 'DecisionType', 'EvidenceType',
    'Evidence', 'FactorContribution', 'DecisionGate', 'ToolIntegration', 'RecommendedAction',
    'FeedbackCapture', 'AIDecisionExplanation'
]
