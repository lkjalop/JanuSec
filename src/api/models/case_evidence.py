"""Stable, versioned case-workspace API boundaries.

V2 deliberately separates observations, model-authored narrative, analyst
decisions, and GRC control-impact assertions.  The UI may render these objects;
it must not infer them from raw rows.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="allow")


class CaseMeta(_Model):
    id: str
    tenant_id: str
    status: str
    stage: str
    percent: int = Field(ge=0, le=100)
    created_at: Any = None
    updated_at: Any = None


class BreachSummary(_Model):
    headline: str
    what_happened: str
    supporting_evidence_ids: list[str]
    coverage_gaps: list[Any]
    status: Literal["supported", "provisional"]
    generated_by: str


class EvidenceCollection(_Model):
    rows: list[dict[str, Any]]
    returned: int = Field(ge=0)
    total: int = Field(ge=0)
    truncated: bool


class GraphView(_Model):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    excluded_edges: list[dict[str, Any]] = Field(default_factory=list)
    edge_policy: Literal["typed_backend_edges_only"]


class CaseEvidenceViewModelV1(_Model):
    schema_version: Literal["janusec.case-evidence-view/v1"]
    case: CaseMeta
    posture: dict[str, Any]
    breach_summary: BreachSummary
    claims: list[dict[str, Any]]
    evidence: EvidenceCollection
    graph: GraphView
    timeline: list[dict[str, Any]]
    retrieval_trace: list[dict[str, Any]]
    coverage_gaps: list[Any]
    analyst: dict[str, Any]
    execution: dict[str, Any]


class ReportContext(_Model):
    report_id: str
    generated_at: Any
    as_known_at: Any = None
    evidence_pack_hash: str | None = None
    graph_projection_id: str | None = None
    graph_receipt_hash: str | None = None
    graph_ledger_head_hash: str | None = None
    graph_clock_calibration_hash: str | None = None
    graph_projection_status: Literal["current", "stale", "unavailable", "unrecorded", "rebuilding"] = "unrecorded"
    graph_staleness_reasons: list[str] = Field(default_factory=list)
    review_status: str = "unreviewed"
    evidence_pack_receipts: list[dict[str, Any]] = Field(default_factory=list)
    infrastructure_truth: dict[str, dict[str, Any]] = Field(default_factory=dict)
    acceptance_truth: dict[str, Any] = Field(default_factory=dict)
    quality_metrics: dict[str, Any] = Field(default_factory=dict)


class ModelExecution(_Model):
    mode: str = "deterministic_only"
    provider: str = "deterministic"
    model: str = "janusec"
    run_id: str | None = None
    external_data_transfer: bool = False
    immutable: bool = True
    fallback_applied: bool = False


class AttackMilestone(_Model):
    id: str
    phase_id: str | None = None
    phase: str
    title: str
    occurred_at: Any = None
    ended_at: Any = None
    time_basis: str = "unknown"
    time_uncertainty_seconds: float = 0.0
    status: Literal["observed", "inferred", "suspected", "attempted", "denied", "unknown"] = "unknown"
    summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    source_domains: list[str] = Field(default_factory=list)
    event_count: int = 0
    raw_milestone_ids: list[str] = Field(default_factory=list)
    episode_ids: list[str] = Field(default_factory=list)


class AttackStory(_Model):
    entry_vector: dict[str, Any] | None = None
    propagation_path: list[dict[str, Any]] = Field(default_factory=list)
    persistence: list[dict[str, Any]] = Field(default_factory=list)
    impact_mechanism: list[dict[str, Any]] = Field(default_factory=list)
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    milestones: list[AttackMilestone] = Field(default_factory=list)
    event_drilldown: list[AttackMilestone] = Field(default_factory=list)


class BusinessServiceImpact(_Model):
    id: str
    name: str
    status: str = "not_assessed"
    criticality: str = "unknown"
    impact: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    owner: str | None = None
    mapping_source: str = "unmapped"


class AuthorizationPath(_Model):
    id: str
    principal: str
    action: str
    resource: str
    outcome: str = "unknown"
    roles: list[str] = Field(default_factory=list)
    policies: list[str] = Field(default_factory=list)
    conditions: dict[str, Any] = Field(default_factory=dict)
    status: str = "observed"
    evidence_ids: list[str] = Field(default_factory=list)


class DecisionItem(_Model):
    id: str
    decision: str
    priority: str = "review"
    rationale: str = ""
    owner_role: str | None = None
    deadline: str | None = None
    approval_status: str = "pending"
    verification: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ControlImpact(_Model):
    id: str
    framework: str
    control_id: str
    title: str = ""
    assertion_status: Literal[
        "observed_control_failure",
        "possible_control_weakness",
        "substantiated_control_failure",
        "formal_nonconformity",
        "control_effectiveness_unconfirmed",
        "insufficient_grc_evidence",
        "reviewed_nonconformity",
    ] = "insufficient_grc_evidence"
    basis: str = ""
    confidence: float | None = Field(default=None, ge=0, le=1)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reviewer_status: str = "unreviewed"


class ActionPlanItem(_Model):
    id: str
    horizon: Literal["now", "24_hours", "7_days", "30_90_days"]
    action_type: Literal[
        "containment", "eradication", "recovery", "scoping_and_investigation",
        "legal_privacy_assessment", "control_correction", "effectiveness_review",
        "evidence_collection",
    ]
    title: str
    exact_action: str
    why: str
    owner_role: str
    accountable_approver_role: str
    priority: Literal["critical", "high", "medium", "review", "low"]
    due_within: str
    status: str
    recommendation_status: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    verification_procedure: str
    required_closure_evidence: list[str] = Field(default_factory=list)
    before_evidence_ids: list[str] = Field(default_factory=list)
    after_evidence_ids: list[str] = Field(default_factory=list)
    verification_evidence_ids: list[str] = Field(default_factory=list)
    workflow_receipt_hash: str | None = None


class CaseActionPlan(_Model):
    schema_version: Literal["janusec.case-action-plan/v1"]
    case_id: str
    content_hash: str
    actions: list[ActionPlanItem] = Field(default_factory=list)
    decisions_required: list[dict[str, Any]] = Field(default_factory=list)
    governance_boundary: str


class CaseEvidenceViewModelV2(CaseEvidenceViewModelV1):
    schema_version: Literal["janusec.case-evidence-view/v2"]
    report_context: ReportContext
    model_execution: ModelExecution
    source_domains: list[dict[str, Any]] = Field(default_factory=list)
    attack_story: AttackStory
    business_impact: list[BusinessServiceImpact] = Field(default_factory=list)
    authorization_paths: list[AuthorizationPath] = Field(default_factory=list)
    containment: list[dict[str, Any]] = Field(default_factory=list)
    immediate_decisions: list[DecisionItem] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    control_impacts: list[ControlImpact] = Field(default_factory=list)
    grc_assignments: list[dict[str, Any]] = Field(default_factory=list)
    corrective_actions: list[dict[str, Any]] = Field(default_factory=list)
    grc_workflow: list[dict[str, Any]] = Field(default_factory=list)
    action_plan: CaseActionPlan
    compliance_obligations: dict[str, Any] = Field(default_factory=dict)


__all__ = ["CaseEvidenceViewModelV1", "CaseEvidenceViewModelV2"]
