"""Deterministic evidence-grounding metrics for immutable model runs."""

from __future__ import annotations

from typing import Any


_FACT_FIELDS = (
    "what_happened", "confirmed_impact", "suspected_impact", "entry_point", "persistence",
    "lateral_movement", "data_access_or_exfiltration", "alternative_hypotheses",
)

_ABSTENTION_MARKERS = {
    "provisional", "unknown", "not established", "not assessed",
    "insufficient evidence", "no evidence", "undetermined", "unconfirmed",
}


def _is_abstention(value: Any) -> bool:
    """True when the model explicitly declines to make a factual assertion."""

    if not isinstance(value, str):
        return False
    normalized = " ".join(value.strip().lower().replace("_", " ").split())
    return normalized in _ABSTENTION_MARKERS or any(
        normalized.startswith(marker + ":") for marker in _ABSTENTION_MARKERS
    )


def evidence_ids_from_view(view: dict[str, Any]) -> set[str]:
    ids = {str(item.get("id")) for item in ((view.get("evidence") or {}).get("rows") or []) if item.get("id")}
    ids.update(str(value) for value in (view.get("breach_summary") or {}).get("supporting_evidence_ids") or [])
    for claim in view.get("claims") or []:
        ids.update(str(value) for value in claim.get("supporting_evidence_ids") or [])
        ids.update(str(value) for value in claim.get("contradicting_evidence_ids") or [])
    for milestone in (view.get("attack_story") or {}).get("milestones") or []:
        if isinstance(milestone, dict):
            ids.update(str(value) for value in milestone.get("evidence_ids") or [])
    for path in view.get("authorization_paths") or []:
        if isinstance(path, dict):
            ids.update(str(value) for value in path.get("evidence_ids") or [])
    for edge in (view.get("graph") or {}).get("edges") or []:
        if isinstance(edge, dict):
            ids.update(str(value) for value in edge.get("evidence_ids") or [])
    return ids


def evaluate_model_output(output: Any, view: dict[str, Any], *, latency_ms: int | None = None) -> dict[str, Any]:
    available = evidence_ids_from_view(view)
    if not isinstance(output, dict):
        return {
            "action": "refine", "attribution_quality": 0.0, "evidence_recall": 0.0,
            "unsupported_claim_rate": 1.0, "contradictions_discovered": 0,
            "calibration_brier": None, "analyst_nodes_to_inspect": 0,
            "time_to_defensible_conclusion_ms": None, "support_ids": [],
            "contradiction_ids": [], "gaps": ["model_output_not_structured"],
        }
    citations = output.get("evidence_ids_by_field") if isinstance(output.get("evidence_ids_by_field"), dict) else {}
    factual = [
        field for field in _FACT_FIELDS
        if output.get(field) not in (None, "", [], {}) and not _is_abstention(output.get(field))
    ]
    supported_fields = 0
    cited: set[str] = set()
    unknown: set[str] = set()
    for field in factual:
        values = citations.get(field) or []
        if isinstance(values, str):
            values = [values]
        valid = {str(value) for value in values if str(value) in available}
        unknown.update(str(value) for value in values if str(value) not in available)
        cited.update(valid)
        if valid:
            supported_fields += 1
    attribution = supported_fields / max(len(factual), 1)
    abstained = not factual and any(_is_abstention(output.get(field)) for field in _FACT_FIELDS)
    unsupported_rate = 1.0 - attribution if factual else 0.0 if abstained else 1.0
    evidence_recall = len(cited) / max(len(available), 1)
    alternatives = output.get("alternative_hypotheses") or []
    contradictions = len(alternatives) if isinstance(alternatives, list) else int(bool(alternatives))
    confidence = output.get("overall_confidence")
    breach = str((view.get("posture") or {}).get("breach_status") or "").lower()
    target = 1.0 if breach in {"confirmed", "validated_breach", "confirmed_breach"} else 0.0 if breach in {"none", "benign", "no_validated_breach"} else None
    try:
        brier = round((float(confidence) - target) ** 2, 6) if target is not None and confidence is not None else None
    except (TypeError, ValueError):
        brier = None
    action = "accept" if factual and unsupported_rate == 0 and not unknown else "refine"
    if abstained:
        action = "abstain"
    gaps = []
    if unsupported_rate:
        gaps.append("one_or_more_factual_fields_lack_valid_evidence_citations")
    if unknown:
        gaps.append("unknown_evidence_ids:" + ",".join(sorted(unknown)))
    return {
        "action": action,
        "abstained": abstained,
        "factual_field_count": len(factual),
        "attribution_quality": round(attribution, 6),
        "evidence_recall": round(evidence_recall, 6),
        "unsupported_claim_rate": round(unsupported_rate, 6),
        "contradictions_discovered": contradictions,
        "calibration_brier": brier,
        "analyst_nodes_to_inspect": len(cited),
        "time_to_defensible_conclusion_ms": latency_ms if action == "accept" else None,
        "must_detect": None,
        "must_separate": None,
        "must_suppress": None,
        "acceptance_truth_status": "requires_labeled_fixture",
        "metric_basis": {
            "evidence_recall": "cited_available_evidence_proxy",
            "contradictions_discovered": "alternative_hypothesis_count_proxy",
            "calibration_brier": "case_posture_target_proxy",
            "analyst_nodes_to_inspect": "cited_evidence_count_proxy",
        },
        "support_ids": sorted(cited),
        "contradiction_ids": [],
        "gaps": gaps,
    }


__all__ = ["evaluate_model_output", "evidence_ids_from_view"]
