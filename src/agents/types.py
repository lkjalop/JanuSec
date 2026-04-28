"""
Shared data types for the agentic investigation loop.

Kept separate so every agent module can import without circular deps.
"""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Zone classification ──────────────────────────────────────────────────────

class ActionZone(enum.IntEnum):
    """Autonomy boundary classification."""
    BLOCKED  = 0   # never allowed
    AUTO     = 1   # read-only, executed immediately
    PROPOSE  = 2   # requires human approval before execution
    ESCALATE = 3   # human must execute; agent can only draft


# ── Investigation context ────────────────────────────────────────────────────

@dataclass
class InvestigationContext:
    """Immutable-ish context that scopes one investigation run."""
    assessment_id: str
    tenant_id: str = "default"
    initial_hypothesis: str = ""
    max_cycles: int = 10
    max_tokens: int = 50_000
    max_queries: int = 200
    autonomy_overrides: Dict[str, int] = field(default_factory=dict)

    # populated at runtime
    investigation_id: str = field(default_factory=lambda: f"inv-{uuid.uuid4().hex[:12]}")
    created_ts: float = field(default_factory=time.time)


# ── Plan / step / finding ────────────────────────────────────────────────────

@dataclass
class PlanStep:
    """One step the Planner asks the Investigator to execute."""
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    zone: ActionZone = ActionZone.AUTO


@dataclass
class Gap:
    """Typed data gap — drives four distinct UI states."""
    description: str
    type: str = "unknown_source"  # auto_fetchable | connector_disabled | unknown_source | cross_domain
    source_type: str = ""         # zeek | okta | cloudtrail | s3_access | ...
    confidence_cap: float = 1.0   # if unresolved, max confidence this gap allows
    suggested_fields: List[str] = field(default_factory=list)  # for unknown_source uploads
    impact: str = ""              # human-readable: "cannot determine credential origin"


@dataclass
class InvestigationPlan:
    """Structured output of the Planner agent."""
    cycle: int
    hypothesis: str
    steps: List[PlanStep] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)


@dataclass
class RawFinding:
    """Unverified finding produced by the Investigator."""
    step_index: int
    tool: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    source_count: int = 1
    data_volume_bytes: int = 0


@dataclass
class RejectionReason:
    """Structured rejection — prevents substring-match suppression of real findings."""
    type: str = ""          # engagement_scope | known_fp | single_source | canary_failure | no_corroboration | contradiction
    actor: str = ""
    ip: str = ""
    phase: str = ""         # scanning | escalation | lateral | exfil | ...
    detail: str = ""


@dataclass
class VerifiedFinding:
    """Finding that passed the Verifier's checks."""
    raw: RawFinding
    confidence: float = 0.0
    dread_score: float = 0.0
    compliance_controls: List[Dict[str, str]] = field(default_factory=list)
    rejection_reason: Optional[RejectionReason] = None   # None = accepted
    weak: bool = False                        # True = single-source
    reverification: Dict[str, Any] = field(default_factory=dict)  # independent re-derivation metadata


# ── Cycle result ─────────────────────────────────────────────────────────────

@dataclass
class AgentCycle:
    """Result of one complete Plan → Investigate → Verify → Narrate loop."""
    cycle: int
    plan: Optional[InvestigationPlan] = None
    raw_findings: List[RawFinding] = field(default_factory=list)
    verified: List[VerifiedFinding] = field(default_factory=list)
    rejected: List[VerifiedFinding] = field(default_factory=list)
    weak: List[VerifiedFinding] = field(default_factory=list)
    narrative_delta: str = ""
    tokens_used: int = 0
    queries_used: int = 0
    should_continue: bool = True
    close_reason: Optional[str] = None


# ── Proposed action (Zone 2 / Zone 3) ───────────────────────────────────────

@dataclass
class ProposedAction:
    """Action queued for human approval (Zone 2) or human execution (Zone 3)."""
    action_id: str = field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")
    zone: ActionZone = ActionZone.PROPOSE
    action_type: str = ""          # e.g. "block_ip", "disable_user", "notify_soc"
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    evidence_count: int = 0
    compliance_controls: List[Dict[str, str]] = field(default_factory=list)
    status: str = "pending"        # pending | approved | rejected | expired
    created_ts: float = field(default_factory=time.time)
    approval_token: Optional[str] = None
    # Stakeholder routing (Fix 1)
    recipient: str = ""            # iam_team | platform_sre | legal_privacy | ciso | soc_team | exec | engagement_lead | hr
    recipient_evidence: str = ""   # human-readable prose for the UI row
    deadline_hours: int = 0        # 0 = no deadline
    citation: str = ""             # framework reference for the deadline


# ── Audit record ─────────────────────────────────────────────────────────────

@dataclass
class AgentAuditRecord:
    """One auditable agent action with compliance tags."""
    audit_id: str = field(default_factory=lambda: f"agt-{uuid.uuid4().hex[:12]}")
    timestamp: float = field(default_factory=time.time)
    investigation_id: str = ""
    assessment_id: str = ""
    tenant_id: str = ""
    actor_type: str = "agent"
    actor_id: str = ""              # e.g. "planner-v1", "investigator-v1"
    agent_cycle: int = 0
    agent_step: int = 0
    action: str = ""                # tool name or meta-action
    action_zone: int = 1
    params: Dict[str, Any] = field(default_factory=dict)
    result_summary: str = ""
    data_volume_bytes: int = 0
    planner_hypothesis: str = ""
    planner_reason: str = ""
    compliance_controls: List[Dict[str, str]] = field(default_factory=list)
    pii_redacted: bool = False
    prompt_injection_check: str = "pass"
    cumulative_scope_pct: float = 0.0
    approval_id: Optional[str] = None
    approval_status: Optional[str] = None
