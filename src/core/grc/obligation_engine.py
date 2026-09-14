"""Evidence-gated compliance obligation decisions.

This module evaluates an approved applicability profile.  It does not encode
law, invent deadlines, or convert incident telemetry directly into a legal
conclusion.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.evidence_contract.records import canonical_hash
from src.core.evidence_contract.signed_snapshots import verify_snapshot


DECISION_STATES = {
    "obligation_likely_triggered", "obligation_not_indicated",
    "insufficient_information", "legal_or_privacy_review_required",
}


def evaluate_obligations(
    *, tenant_id: str, affected_asset_ids: list[str], affected_service_ids: list[str],
    data_classification_snapshot: Mapping[str, Any] | None,
    regulatory_applicability_snapshot: Mapping[str, Any] | None,
    incident_facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    classification_valid, classification_reason = (
        verify_snapshot(data_classification_snapshot, expected_kind="data_classification", tenant_id=tenant_id)
        if data_classification_snapshot else (False, "snapshot_missing")
    )
    applicability_valid, applicability_reason = (
        verify_snapshot(regulatory_applicability_snapshot, expected_kind="regulatory_applicability", tenant_id=tenant_id)
        if regulatory_applicability_snapshot else (False, "snapshot_missing")
    )
    gaps = []
    if not classification_valid:
        gaps.append(f"data_classification:{classification_reason}")
    if not applicability_valid:
        gaps.append(f"regulatory_applicability:{applicability_reason}")
    if gaps:
        content = {
            "schema_version": "janusec.compliance-obligation-decisions/v1",
            "decision_status": "insufficient_information", "obligations": [], "gaps": gaps,
        }
        return {**content, "content_hash": canonical_hash(content)}

    affected_assets = {str(value) for value in affected_asset_ids if value}
    affected_services = {str(value) for value in affected_service_ids if value}
    classification_rows = [
        dict(item) for item in data_classification_snapshot.get("asset_classifications") or []
        if isinstance(item, Mapping) and str(item.get("asset_id") or "") in affected_assets
    ]
    categories = {
        str(value) for item in classification_rows
        for value in item.get("data_categories") or [] if value
    }
    facts = dict(incident_facts or {})
    fact_evidence_ids = [str(value) for value in facts.get("evidence_ids") or [] if value]
    decisions = []
    for obligation in regulatory_applicability_snapshot.get("obligations") or []:
        if not isinstance(obligation, Mapping):
            continue
        scope = obligation.get("applicable_to") if isinstance(obligation.get("applicable_to"), Mapping) else {}
        scope_match = bool(
            affected_assets & {str(value) for value in scope.get("asset_ids") or []}
            or affected_services & {str(value) for value in scope.get("service_ids") or []}
            or categories & {str(value) for value in scope.get("data_categories") or []}
        )
        applicability = str(obligation.get("applicability_status") or "review_required")
        conditions = obligation.get("trigger_conditions") if isinstance(obligation.get("trigger_conditions"), Mapping) else {}
        condition_results = [
            {"fact": str(key), "expected": expected, "observed": facts.get(key), "matched": facts.get(key) == expected}
            for key, expected in sorted(conditions.items())
        ]
        if applicability == "not_applicable" or not scope_match:
            state = "obligation_not_indicated"
        elif conditions and fact_evidence_ids and all(item["matched"] for item in condition_results):
            state = "obligation_likely_triggered"
        elif conditions and fact_evidence_ids and any(not item["matched"] for item in condition_results):
            state = "obligation_not_indicated"
        elif not classification_rows and not affected_services:
            state = "insufficient_information"
        else:
            state = "legal_or_privacy_review_required"
        decisions.append({
            "obligation_id": str(obligation.get("obligation_id") or ""),
            "authority": str(obligation.get("authority") or ""),
            "jurisdiction": str(obligation.get("jurisdiction") or ""),
            "version": str(obligation.get("version") or ""),
            "decision_status": state, "applicability_status": applicability,
            "scope_match": scope_match, "matched_asset_ids": sorted(affected_assets & {str(value) for value in scope.get("asset_ids") or []}),
            "matched_service_ids": sorted(affected_services & {str(value) for value in scope.get("service_ids") or []}),
            "matched_data_categories": sorted(categories & {str(value) for value in scope.get("data_categories") or []}),
            "trigger_condition_results": condition_results,
            "supporting_evidence_ids": fact_evidence_ids,
            "notification_window": obligation.get("notification_window"),
            "source_reference": obligation.get("source_reference"),
            "owner_role": str(obligation.get("owner_role") or "legal_privacy_and_grc"),
            "review_required": state in {"obligation_likely_triggered", "legal_or_privacy_review_required"},
        })

    overall = (
        "obligation_likely_triggered" if any(item["decision_status"] == "obligation_likely_triggered" for item in decisions)
        else "legal_or_privacy_review_required" if any(item["decision_status"] == "legal_or_privacy_review_required" for item in decisions)
        else "insufficient_information" if not decisions or any(item["decision_status"] == "insufficient_information" for item in decisions)
        else "obligation_not_indicated"
    )
    content = {
        "schema_version": "janusec.compliance-obligation-decisions/v1",
        "decision_status": overall, "obligations": decisions, "gaps": [],
        "classification_receipt_hash": (data_classification_snapshot.get("snapshot_receipt") or {}).get("receipt_hash"),
        "applicability_receipt_hash": (regulatory_applicability_snapshot.get("snapshot_receipt") or {}).get("receipt_hash"),
    }
    return {**content, "content_hash": canonical_hash(content)}


__all__ = ["DECISION_STATES", "evaluate_obligations"]
