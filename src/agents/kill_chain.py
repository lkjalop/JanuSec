"""Compatibility adapter for the authoritative case chronology compiler."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.agents.types import VerifiedFinding
from src.core.evidence_contract.chronology import compile_case_chronology, parse_event_time


@dataclass
class KillChainPhase:
    """Legacy presentation shape; causal truth comes from typed relations."""

    phase: str = ""
    timestamp: Optional[datetime] = None
    actor: str = ""
    action: str = ""
    evidence_row_ids: List[int] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    candidate_mitre_techniques: List[str] = field(default_factory=list)
    enables_phase_id: Optional[str] = None
    relation_to_next: Optional[str] = None
    actor_role: str = "actor"
    actor_basis: str = "unknown"
    action_outcome: str = "unknown"
    action_direction: Optional[str] = None
    original_timestamp: Optional[str] = None
    source_timezone: Optional[str] = None
    time_precision: str = "unknown"
    clock_uncertainty_seconds: float = 0.0
    phase_id: str = ""


def _extract_timestamp(evidence: Dict[str, Any]) -> Optional[datetime]:
    """Return aware UTC or ``None``; never invent a sentinel timestamp."""

    for key in ("occurred_at", "timestamp", "ts", "event_time", "created_at", "time"):
        parsed = parse_event_time(evidence.get(key)).get("occurred_at")
        if parsed:
            return datetime.fromisoformat(str(parsed).replace("Z", "+00:00"))
    return None


def _extract_actor(evidence: Dict[str, Any], summary: str) -> str:
    for key in ("principal_id", "user_sid", "user_canonical", "user", "actor", "principal", "src_ip", "source_ip"):
        value = evidence.get(key)
        if value:
            return str(value)
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", summary)
    return match.group() if match else "unknown"


def _extract_row_ids(evidence: Dict[str, Any]) -> List[int]:
    for key in ("row_refs", "sample_row_ids", "row_ids", "event_ids"):
        value = evidence.get(key)
        if isinstance(value, list):
            return [int(item) for item in value if str(item).isdigit()][:10]
    return []


def _link_causal_pairs(phases: List[KillChainPhase]) -> None:
    """Record ordering only. Proximity or a shared actor is not causality."""

    for current, following in zip(phases, phases[1:]):
        if current.timestamp is not None and following.timestamp is not None:
            current.relation_to_next = "temporal_precedes"


def extract_kill_chain(verified: List[VerifiedFinding]) -> List[KillChainPhase]:
    """Compile verified findings through the shared, evidence-safe chronology."""

    if not verified:
        return []
    rows: list[dict[str, Any]] = []
    for index, finding in enumerate(verified):
        evidence = dict(finding.raw.evidence) if isinstance(finding.raw.evidence, dict) else {}
        evidence.setdefault("summary", finding.raw.summary)
        evidence.setdefault("row_index", index)
        rows.append(evidence)
    chronology = compile_case_chronology(
        tenant_id="agent",
        assessment_id="agent-investigation",
        case_id="agent-investigation",
        rows=rows,
    )
    ordered = list(chronology["milestones"]) + list(chronology["unsequenced"])
    return [
        KillChainPhase(
            phase=str(item.get("phase") or "unknown"),
            timestamp=(
                datetime.fromisoformat(str(item["occurred_at"]).replace("Z", "+00:00"))
                if item.get("occurred_at") else None
            ),
            actor=str(item.get("actor") or "unknown"),
            actor_role=str(item.get("actor_role") or "actor"),
            actor_basis=str(item.get("actor_basis") or "unknown"),
            action=str(item.get("action") or ""),
            action_outcome=str(item.get("action_outcome") or "unknown"),
            action_direction=item.get("action_direction"),
            evidence_row_ids=[int(value) for value in item.get("evidence_row_ids") or [] if str(value).isdigit()],
            mitre_techniques=list(item.get("mitre_techniques") or []),
            candidate_mitre_techniques=list(item.get("candidate_mitre_techniques") or []),
            enables_phase_id=item.get("enables_phase_id"),
            relation_to_next=item.get("relation_to_next"),
            original_timestamp=item.get("original_timestamp"),
            source_timezone=item.get("source_timezone"),
            time_precision=str(item.get("time_precision") or "unknown"),
            clock_uncertainty_seconds=float(item.get("clock_uncertainty_seconds") or 0.0),
            phase_id=str(item.get("phase_id") or item.get("id") or ""),
        )
        for item in ordered
    ]


__all__ = ["KillChainPhase", "extract_kill_chain"]
