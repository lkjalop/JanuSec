"""Deterministic policy for escalating an unresolved case to a frontier model."""

from __future__ import annotations

from typing import Any


def decide_frontier_escalation(metrics: dict[str, Any], *, external_approved: bool) -> dict[str, Any]:
    reasons: list[str] = []
    if float(metrics.get("attribution_quality") or 0) < 0.75:
        reasons.append("low_attribution_quality")
    if float(metrics.get("evidence_recall") or 0) < 0.60:
        reasons.append("low_evidence_recall")
    if float(metrics.get("unsupported_claim_rate") or 0) > 0.10:
        reasons.append("unsupported_claim_rate_high")
    if int(metrics.get("contradiction_count") or metrics.get("contradictions_discovered") or 0) > 0:
        reasons.append("unresolved_contradictions")
    if int(metrics.get("case_partition_count") or 1) > 1 and not metrics.get("case_scoped"):
        reasons.append("assessment_wide_reasoning_over_multiple_cases")
    if int(metrics.get("analyst_nodes_to_inspect") or 0) > 50:
        reasons.append("analyst_inspection_burden_high")
    required = bool(reasons)
    return {
        "required": required,
        "allowed": required and external_approved,
        "route": "frontier_model" if required and external_approved else "analyst_review" if required else "local_model_accepted",
        "reasons": reasons,
        "external_approval_required": required and not external_approved,
    }


__all__ = ["decide_frontier_escalation"]
