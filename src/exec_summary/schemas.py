"""Pydantic schemas for the executive summary pipeline.

These enforce contracts between extraction, synthesis, and validation layers.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class TimeRange(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None


class ClusterScope(BaseModel):
    """Boundary of a single threat case cluster."""
    cluster_id: str
    threat_case_id: Optional[str] = None
    evidence_row_ids: List[int] = Field(default_factory=list)
    entities: dict[str, List[str]] = Field(default_factory=dict)
    valid_time_window: TimeRange = Field(default_factory=TimeRange)
    phase_count: int = 0
    telemetry_sources: List[str] = Field(default_factory=list)
    verdict: str = 'UNCERTAIN'
    confidence: Optional[float] = None
    incident_name: str = ''
    row_count: int = 0


class BeliefTransition(BaseModel):
    """A single classification change in a cluster's history."""
    transaction_time: str
    prior_classification: Optional[str] = None
    new_classification: str
    prior_confidence: Optional[float] = None
    new_confidence: Optional[float] = None
    triggering_evidence_ids: List[int] = Field(default_factory=list)
    triggering_reason: str = ''


class BeliefTrajectory(BaseModel):
    """Ordered sequence of classification transitions for a cluster."""
    cluster_id: str
    transitions: List[BeliefTransition] = Field(default_factory=list)
    current_classification: str = 'UNCERTAIN'
    current_confidence: Optional[float] = None
    data_available: bool = False


class EvidenceSnippet(BaseModel):
    """A single retrieved evidence row for context injection."""
    entity: Optional[str] = None
    severity: Optional[str] = None
    description: str = ''
    ts: Optional[str] = None
    source: Optional[str] = None
    row_index: Optional[int] = None


class EvidenceFrame(BaseModel):
    """TemporalRAG-bounded evidence for a cluster."""
    cluster_id: str
    rag_available: bool = False
    neighbour_count: int = 0
    window_seconds: int = 7200
    snippets: List[EvidenceSnippet] = Field(default_factory=list)
    summary_hint: str = ''


class Claim(BaseModel):
    """A single factual claim in a narrative, with citation."""
    text: str
    evidence_row_ids: List[int] = Field(default_factory=list)
    valid_time: Optional[str] = None
    grounded: bool = False


class ClusterNarrative(BaseModel):
    """Per-cluster narrative output from synthesis."""
    cluster_id: str
    incident_name: str = ''
    verdict: str = 'UNCERTAIN'
    summary_paragraph: str = ''
    belief_trajectory_oneliner: str = ''
    verdict_confidence_sentence: str = ''
    evidence_quality: str = ''
    counter_hypotheses: List[str] = Field(default_factory=list)
    confirming_evidence: List[str] = Field(default_factory=list)
    grader_composite: Optional[float] = None
    grader_caveats: List[str] = Field(default_factory=list)
    key_decisions_required: List[str] = Field(default_factory=list)
    claims: List[Claim] = Field(default_factory=list)
    temporal_context: str = ''
    deterministic_fallback: bool = False
    provenance: str = 'deterministic'


class PersonaNarrative(BaseModel):
    """A cluster narrative reframed for a specific audience."""
    persona: str
    cluster_id: str
    framing: str = ''
    emphasis: str = ''
    summary: str = ''
    # Phase 1 — compliance persona payload (empty for non-compliance personas)
    control_failures: List[dict] = Field(default_factory=list)
    cross_framework_evidence: dict = Field(default_factory=dict)
    regulatory_triggers: List[dict] = Field(default_factory=list)
    cve_context: dict = Field(default_factory=dict)
    auditor_insights: List[str] = Field(default_factory=list)
    remediation_roadmap: dict = Field(default_factory=dict)


class ExecSummaryResult(BaseModel):
    """Full structured output of the executive summary pipeline."""
    assessment_id: str
    cluster_narratives: List[ClusterNarrative] = Field(default_factory=list)
    rollup_summary: str = ''
    rollup_provenance: str = 'deterministic'
    persona_summaries: dict[str, List[PersonaNarrative]] = Field(default_factory=dict)
    generated_at: int = 0
