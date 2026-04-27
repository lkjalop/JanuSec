"""
Autonomy gate — classifies every agent action into Zone 0/1/2/3
and enforces the boundary before execution.

Zone 0: BLOCKED   — hardcoded deny-list, audit-logged as violation
Zone 1: AUTO-OK   — read-only / internal transforms, immediate execution
Zone 2: PROPOSE   — mutations; queued for human approval
  - 2A: quick-approval (30 min timeout → auto-deny)
  - 2B: explicit approval (no timeout, agent continues other branches)
  - 2C: conditional auto-approve (confidence > threshold + multi-source)
Zone 3: ESCALATE  — legal/regulatory; agent can only draft, human executes
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import asdict
from typing import Any, Dict, Optional

from src.agents.types import (
    ActionZone,
    AgentAuditRecord,
    InvestigationContext,
    ProposedAction,
)
from src.audit.logger import audit
from src.core.approval_store import create_request as _create_approval
from src.privacy.redaction import redact_for_llm

LOGGER = logging.getLogger(__name__)

# ── Compliance control map for agent actions ─────────────────────────────────
# Each action type → default compliance tags attached to audit records.

_ACTION_COMPLIANCE: Dict[str, list[Dict[str, str]]] = {
    # Zone 1 investigation actions
    "temporal_rag":   [{"framework": "ISO 27001:2022", "control_id": "A.8.16", "control_name": "Monitoring activities"},
                       {"framework": "NIST CSF 2.0",   "control_id": "DE.AE-02", "control_name": "Events analyzed for potential threats"}],
    "hopgraph_query": [{"framework": "ISO 27001:2022", "control_id": "A.8.16", "control_name": "Monitoring activities"},
                       {"framework": "NIST CSF 2.0",   "control_id": "DE.AE-02", "control_name": "Events analyzed for potential threats"},
                       {"framework": "APRA CPS 234",   "control_id": "Para 36",  "control_name": "Timely detection of incidents"}],
    "nlp_search":     [{"framework": "NIST CSF 2.0",   "control_id": "DE.AE-02", "control_name": "Events analyzed for potential threats"}],
    "duckdb_query":   [{"framework": "ISO 27001:2022", "control_id": "A.8.16", "control_name": "Monitoring activities"}],
    "dread_score":    [{"framework": "ISO 27001:2022", "control_id": "A.5.25", "control_name": "Assessment of information security events"}],
    "fetch_source":   [{"framework": "ISO 27001:2022", "control_id": "A.8.16", "control_name": "Monitoring activities"},
                       {"framework": "Essential Eight", "control_id": "ML2-LOG", "control_name": "Regular audit log monitoring"}],
    # Zone 2 response actions
    "block_ip":       [{"framework": "ISO 27001:2022", "control_id": "A.5.26", "control_name": "Response to information security incidents"},
                       {"framework": "NIST CSF 2.0",   "control_id": "RS.MI-01", "control_name": "Incident mitigation"}],
    "disable_user":   [{"framework": "ISO 27001:2022", "control_id": "A.8.3",  "control_name": "Information access restriction"},
                       {"framework": "NIST CSF 2.0",   "control_id": "PR.AA-05", "control_name": "Identity authentication"}],
    "notify_soc":     [{"framework": "ISO 27001:2022", "control_id": "A.6.8",  "control_name": "Information security event reporting"},
                       {"framework": "NIST CSF 2.0",   "control_id": "RS.CO-02", "control_name": "Internal stakeholders notified"}],
    "create_incident":[{"framework": "ISO 27001:2022", "control_id": "A.5.25", "control_name": "Assessment of information security events"}],
    "start_capture":  [{"framework": "ISO 27001:2022", "control_id": "A.8.16", "control_name": "Monitoring activities"}],
    # Zone 3 escalation
    "notify_regulator":  [{"framework": "NDB Scheme",     "control_id": "s26WE", "control_name": "Notification to the Commissioner"},
                          {"framework": "APRA CPS 234",   "control_id": "Para 38","control_name": "Notification to APRA"}],
    "legal_hold":        [{"framework": "ISO 27001:2022", "control_id": "A.5.31", "control_name": "Legal, statutory and regulatory requirements"}],
    "cross_domain_req":  [{"framework": "ISO 27001:2022", "control_id": "A.5.10", "control_name": "Acceptable use of information"},
                          {"framework": "ISO 27001:2022", "control_id": "A.5.31", "control_name": "Legal, statutory and regulatory requirements"}],
    # PII redaction (implicit on every LLM call)
    "pii_redact":     [{"framework": "ISO 27001:2022", "control_id": "A.8.11", "control_name": "Data masking"},
                       {"framework": "NIST CSF 2.0",   "control_id": "PR.DS-01", "control_name": "Data-at-rest protection"}],
    # Narrative generation
    "narrate":        [{"framework": "ISO 27001:2022", "control_id": "A.5.25", "control_name": "Assessment of information security events"},
                       {"framework": "NIST CSF 2.0",   "control_id": "RS.AN-03", "control_name": "Response analysis performed"}],
    # Investigation close
    "close":          [{"framework": "ISO 27001:2022", "control_id": "A.5.27", "control_name": "Learning from information security incidents"},
                       {"framework": "NIST CSF 2.0",   "control_id": "RC.IM-01", "control_name": "Recovery improvements"}],
}


# ── Zone 0 deny list (hardcoded, not configurable) ──────────────────────────

_ZONE0_DENY_PATTERNS: list[str] = [
    "exec_remote_command",
    "access_secrets",
    "modify_other_tenant",
    "disable_audit",
    "raw_external_api",         # sending unredacted data externally
    "override_engagement_scope",
]

# ── Zone classification rules ────────────────────────────────────────────────

_ZONE1_ACTIONS = frozenset({
    "temporal_rag", "hopgraph_query", "nlp_search", "duckdb_query",
    "dread_score", "fetch_source", "compliance_tag", "pii_redact",
    "narrate", "corrective_rag_ingest",
})

_ZONE2_ACTIONS = frozenset({
    "block_ip", "disable_user", "notify_soc", "create_incident",
    "start_capture", "push_iocs",
})

_ZONE3_ACTIONS = frozenset({
    "notify_regulator", "legal_hold", "cross_domain_req",
    "engage_ir_firm", "brief_board",
})

# Zone 2C auto-approve thresholds (overridable via env)
AUTO_APPROVE_CONFIDENCE = float(os.environ.get("AGENT_AUTO_APPROVE_CONFIDENCE", "0.95"))
AUTO_APPROVE_MIN_SOURCES = int(os.environ.get("AGENT_AUTO_APPROVE_MIN_SOURCES", "3"))
AUTO_APPROVE_MIN_DREAD = float(os.environ.get("AGENT_AUTO_APPROVE_MIN_DREAD", "8.0"))
AUTO_APPROVE_DELAY_S = int(os.environ.get("AGENT_AUTO_APPROVE_DELAY", "300"))  # 5 min


# ── Cumulative scope tracking ────────────────────────────────────────────────

class ScopeTracker:
    """Tracks aggregate data accessed per investigation. If cumulative scope
    exceeds a threshold, Zone 1 actions auto-promote to Zone 2."""

    def __init__(self, max_bytes: int = 50_000_000, max_queries: int = 200):
        self.max_bytes = max_bytes
        self.max_queries = max_queries
        self._bytes = 0
        self._queries = 0

    def record(self, data_bytes: int = 0, queries: int = 1) -> None:
        self._bytes += data_bytes
        self._queries += queries

    @property
    def pct(self) -> float:
        b = self._bytes / self.max_bytes if self.max_bytes else 0
        q = self._queries / self.max_queries if self.max_queries else 0
        return max(b, q)

    @property
    def exceeded(self) -> bool:
        return self.pct >= 1.0


# ── Main classification function ─────────────────────────────────────────────

def classify_action(
    action_type: str,
    *,
    context: InvestigationContext,
    scope: Optional[ScopeTracker] = None,
    confidence: float = 0.0,
    source_count: int = 1,
    dread_score: float = 0.0,
) -> ActionZone:
    """Classify an action into Zone 0/1/2/3.

    Autonomy overrides in ``context.autonomy_overrides`` can promote/demote
    specific action_types (e.g. ``{"block_ip": 1}`` makes it auto-OK).
    """
    # Zone 0: always blocked
    for pat in _ZONE0_DENY_PATTERNS:
        if pat in action_type:
            return ActionZone.BLOCKED

    # Check operator overrides first
    override = context.autonomy_overrides.get(action_type)
    if override is not None:
        try:
            return ActionZone(override)
        except ValueError:
            pass

    # Zone 1
    if action_type in _ZONE1_ACTIONS:
        # scope escalation: if cumulative scope exceeded, promote to Zone 2
        if scope and scope.exceeded:
            LOGGER.warning("scope exceeded — promoting %s to Zone 2", action_type)
            return ActionZone.PROPOSE
        return ActionZone.AUTO

    # Zone 2
    if action_type in _ZONE2_ACTIONS:
        # Zone 2C: conditional auto-approve
        if (confidence >= AUTO_APPROVE_CONFIDENCE
                and source_count >= AUTO_APPROVE_MIN_SOURCES
                and dread_score >= AUTO_APPROVE_MIN_DREAD):
            # Auto-approve after delay — still Zone 2 but flagged
            return ActionZone.AUTO  # caller handles the delay
        return ActionZone.PROPOSE

    # Zone 3
    if action_type in _ZONE3_ACTIONS:
        return ActionZone.ESCALATE

    # Unknown action → default to Zone 2 (safe)
    LOGGER.warning("unknown action %r — defaulting to Zone 2", action_type)
    return ActionZone.PROPOSE


# ── Enforcement ──────────────────────────────────────────────────────────────

def enforce(
    action_type: str,
    params: Dict[str, Any],
    *,
    context: InvestigationContext,
    scope: Optional[ScopeTracker] = None,
    confidence: float = 0.0,
    source_count: int = 1,
    dread_score: float = 0.0,
    cycle: int = 0,
    step: int = 0,
    hypothesis: str = "",
    reason: str = "",
) -> tuple[ActionZone, Optional[ProposedAction]]:
    """Classify and enforce an action. Returns (zone, proposed_action_or_None).

    - Zone 0: logs violation, returns (BLOCKED, None).
    - Zone 1: logs audit, returns (AUTO, None) — caller executes immediately.
    - Zone 2: creates approval request, returns (PROPOSE, ProposedAction).
    - Zone 3: returns (ESCALATE, ProposedAction) — caller shows draft to human.
    """
    zone = classify_action(
        action_type,
        context=context,
        scope=scope,
        confidence=confidence,
        source_count=source_count,
        dread_score=dread_score,
    )

    # build audit record
    controls = _ACTION_COMPLIANCE.get(action_type, [])
    rec = AgentAuditRecord(
        investigation_id=context.investigation_id,
        assessment_id=context.assessment_id,
        tenant_id=context.tenant_id,
        actor_id=f"agent-{action_type}",
        agent_cycle=cycle,
        agent_step=step,
        action=action_type,
        action_zone=int(zone),
        params=redact_for_llm(params, sensitive_fields=["password", "secret", "token", "key"]),
        planner_hypothesis=hypothesis,
        planner_reason=reason,
        compliance_controls=controls,
        pii_redacted=True,
        cumulative_scope_pct=scope.pct if scope else 0.0,
    )

    # Zone 0: blocked
    if zone == ActionZone.BLOCKED:
        rec.prompt_injection_check = "BLOCKED"
        _emit_audit(rec)
        LOGGER.error("BLOCKED agent action: %s (investigation %s)",
                      action_type, context.investigation_id)
        return (ActionZone.BLOCKED, None)

    # Zone 1: auto-execute
    if zone == ActionZone.AUTO:
        _emit_audit(rec)
        return (ActionZone.AUTO, None)

    # Zone 2 / Zone 3: create proposed action
    proposed = ProposedAction(
        zone=zone,
        action_type=action_type,
        description=reason or f"Agent proposes: {action_type}",
        params=params,
        confidence=confidence,
        evidence_count=source_count,
        compliance_controls=controls,
    )

    # Persist approval request via existing store
    token = f"agt-{proposed.action_id}"
    proposed.approval_token = token
    expiry = 1800 if zone == ActionZone.PROPOSE else None  # 30min for Zone 2A
    _create_approval(token, {
        "investigation_id": context.investigation_id,
        "action_type": action_type,
        "params": redact_for_llm(params, sensitive_fields=["password", "secret", "token"]),
        "zone": int(zone),
        "confidence": confidence,
        "compliance_controls": controls,
    }, expiry_seconds=expiry)

    rec.approval_id = token
    rec.approval_status = "pending"
    _emit_audit(rec)

    return (zone, proposed)


# ── Prompt-injection scan (lightweight) ──────────────────────────────────────

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"system:\s*mark\s+.+\s+as\s+benign", re.IGNORECASE),
    re.compile(r"do\s+not\s+report", re.IGNORECASE),
    re.compile(r"ASSISTANT:\s*override", re.IGNORECASE),
]


def scan_prompt_injection(text: str) -> bool:
    """Return True if the text contains known prompt-injection patterns."""
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            return True
    return False


# ── Helpers ──────────────────────────────────────────────────────────────────

def _emit_audit(rec: AgentAuditRecord) -> None:
    """Write audit record to the existing audit logger."""
    try:
        audit("agent_action", **{
            k: v for k, v in rec.__dict__.items()
            if v is not None and v != "" and v != 0 and v != []
        })
    except Exception:
        LOGGER.exception("failed to emit agent audit record")


def get_compliance_tags(action_type: str) -> list[Dict[str, str]]:
    """Return compliance controls for a given action type."""
    return list(_ACTION_COMPLIANCE.get(action_type, []))
