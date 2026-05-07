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


# ── Context Engineering: Write primitive ─────────────────────────────────────

@dataclass
class MemoryArtifact:
    """One structured discovery written by the Investigator during a cycle.

    artifact_type values:
      ioc             — confirmed indicator (IP, hash, domain, user, process)
      ttp             — confirmed technique (maps to MITRE)
      timeline_anchor — a time-anchored event in the attack sequence
      attribution     — threat actor or campaign attribution claim
    """
    artifact_type: str           # "ioc" | "ttp" | "timeline_anchor" | "attribution"
    content: str                 # human-readable description
    confidence: float = 0.0
    cycle: int = 0               # which cycle produced this
    actor: str = ""
    timestamp: str = ""          # ISO-8601 event timestamp if applicable
    mitre_techniques: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)   # source telemetry types
    evidence_row_ids: List[str] = field(default_factory=list)


@dataclass
class InvestigationMemory:
    """Structured artifact store for the entire investigation.

    Implements the Write and Compress context engineering primitives.
    Write: agents call memory.write() to persist any discovery beyond the current cycle.
    Compress: at cycle 4+, memory.compress() produces a structured digest that replaces
              the raw all_verified[-20:] slice in the Planner prompt.
    """
    artifacts: List[MemoryArtifact] = field(default_factory=list)

    def write(self, artifact: MemoryArtifact) -> None:
        """Persist a structured discovery (the Write primitive)."""
        self.artifacts.append(artifact)

    def write_from_findings(self, findings: List[Any], cycle: int) -> None:
        """Extract and write MemoryArtifacts from a list of VerifiedFindings."""
        for vf in findings:
            summary = getattr(getattr(vf, "raw", None), "summary", "") or ""
            summary_lower = summary.lower()
            actor = (vf.raw.evidence or {}).get("user") or (vf.raw.evidence or {}).get("actor") or "" if isinstance(getattr(vf.raw, "evidence", None), dict) else ""
            mitre = [
                t for t in (
                    (vf.raw.evidence or {}).get("mitre_techniques", [])
                    or [vf.raw.evidence.get("mitre_technique", "")]
                    if isinstance(getattr(vf.raw, "evidence", None), dict) else []
                )
                if t
            ]

            # Classify artifact type from summary keywords
            atype = "ttp"
            if any(k in summary_lower for k in ["ip ", "hash", "domain", "user ", "process "]):
                atype = "ioc"
            elif any(k in summary_lower for k in ["at ", "utc", "2024", "2025", "2026", "timestamp"]):
                atype = "timeline_anchor"
            elif any(k in summary_lower for k in ["apt", "actor", "group", "campaign", "threat intel"]):
                atype = "attribution"

            self.write(MemoryArtifact(
                artifact_type=atype,
                content=summary[:300],
                confidence=vf.confidence,
                cycle=cycle,
                actor=actor,
                mitre_techniques=mitre,
                sources=[getattr(vf.raw, "tool", "")],
                evidence_row_ids=list(
                    (vf.raw.evidence or {}).get("row_ids", [])
                    or (vf.raw.evidence or {}).get("sample_row_ids", [])
                    if isinstance(getattr(vf.raw, "evidence", None), dict) else []
                ),
            ))

    def compress(self, up_to_cycle: int) -> str:
        """Compress artifacts from cycles 1..up_to_cycle into a structured digest
        (the Compress primitive). Frees LLM context window for new evidence."""
        prior = [a for a in self.artifacts if a.cycle <= up_to_cycle]
        if not prior:
            return ""

        iocs = [a for a in prior if a.artifact_type == "ioc"]
        ttps = [a for a in prior if a.artifact_type == "ttp"]
        anchors = sorted(
            [a for a in prior if a.artifact_type == "timeline_anchor"],
            key=lambda x: x.timestamp,
        )
        attributions = [a for a in prior if a.artifact_type == "attribution"]
        actors = list({a.actor for a in prior if a.actor})

        lines = [f"## Prior Investigation Summary (Cycles 1\u2013{up_to_cycle}; DO NOT RE-INVESTIGATE)"]

        if actors:
            lines.append(f"Confirmed actors: {', '.join(actors[:8])}")

        if iocs:
            lines.append(f"Confirmed IOCs ({len(iocs)}):")
            for a in iocs[:12]:
                lines.append(f"  [{a.confidence:.2f}] {a.content[:120]}")

        if ttps:
            lines.append(f"Confirmed TTPs ({len(ttps)}):")
            for a in ttps[:10]:
                mitre_str = ", ".join(a.mitre_techniques[:3]) if a.mitre_techniques else "N/A"
                lines.append(f"  [{a.confidence:.2f}] {a.content[:120]} (MITRE: {mitre_str})")

        if anchors:
            lines.append("Attack timeline:")
            for a in anchors[:8]:
                lines.append(f"  {a.timestamp or 'unknown time'}: {a.content[:120]}")

        if attributions:
            lines.append(f"Attribution: {'; '.join(a.content[:100] for a in attributions[:3])}")

        lines.append(
            f"\nTotal artifacts: {len(prior)} across {up_to_cycle} cycles. "
            f"Focus the next cycle on NEW leads only."
        )
        return "\n".join(lines)

    def recent_snapshot(self, limit: int = 20) -> List[dict]:
        """Return the most recent artifacts as dicts for prompt injection."""
        import dataclasses as _dc
        return [_dc.asdict(a) for a in self.artifacts[-limit:]]

