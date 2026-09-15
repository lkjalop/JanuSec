"""Human-governed bridge from incident evidence to external GRC workflows."""

from __future__ import annotations

import datetime as dt
from typing import Any, Mapping

from src.core.evidence_contract.records import canonical_hash


FRAMEWORK_MAPPING_VERSIONS = {
    "iso_27001": "ISO/IEC 27001:2022",
    "iso_19011": "ISO 19011:2018",
    "iso_42001": "ISO/IEC 42001:2023",
    "nist_csf": "NIST CSF 2.0",
    "nist_ai_rmf": "NIST AI RMF 1.0",
}
CLASSIFICATIONS = {
    "possible_control_weakness", "observation", "conformity", "nonconformity",
    "substantiated_control_failure", "formal_nonconformity", "insufficient_grc_evidence",
}
STATUSES = {
    "open", "proposed", "assigned", "approved", "implementing", "implemented",
    "correcting", "verification_pending", "verified", "rejected", "reopened",
    "closed", "cancelled",
}
_TRANSITIONS = {
    "open": {"assigned", "rejected", "cancelled"},
    "proposed": {"assigned", "rejected", "cancelled"},
    "assigned": {"approved", "rejected", "cancelled"},
    "approved": {"implementing", "rejected", "cancelled"},
    "implementing": {"implemented", "rejected", "cancelled"},
    "implemented": {"verification_pending", "reopened"},
    "correcting": {"verification_pending", "reopened"},
    "verification_pending": {"verified", "rejected", "reopened"},
    "verified": {"closed", "reopened"},
    "closed": {"reopened"},
    "rejected": {"reopened"},
    "reopened": {"assigned", "rejected", "cancelled"},
}


def workflow_event(
    *, tenant_id: str, assessment_id: str, case_id: str, finding_id: str,
    event_type: str, actor: str, data: Mapping[str, Any], previous_hash: str | None = None,
    previous_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    classification = str(data.get("classification") or "possible_control_weakness")
    status = str(data.get("status") or "open")
    if classification not in CLASSIFICATIONS or status not in STATUSES:
        raise ValueError("invalid_grc_classification_or_status")
    if previous_event is not None:
        previous_status = str(previous_event.get("status") or "open")
        if status != previous_status and status not in _TRANSITIONS.get(previous_status, set()):
            raise ValueError(f"invalid_grc_transition:{previous_status}->{status}")
    if classification in {"nonconformity", "formal_nonconformity"} and not str(data.get("analyst_signoff") or "").strip():
        raise ValueError("nonconformity_requires_analyst_signoff")
    verification_ids = [str(value) for value in data.get("verification_evidence_ids") or [] if value]
    before_ids = [str(value) for value in data.get("before_evidence_ids") or [] if value]
    after_ids = [str(value) for value in data.get("after_evidence_ids") or [] if value]
    if status == "implemented" and (not before_ids or not after_ids):
        raise ValueError("implementation_requires_before_and_after_receipts")
    if status in {"verification_pending", "verified"} and not after_ids:
        raise ValueError("verification_requires_after_receipt")
    if status == "closed" and not verification_ids:
        raise ValueError("closure_requires_verification_evidence")
    content = {
        "schema_version": "janusec.grc-workflow-event/v1",
        "tenant_id": tenant_id, "assessment_id": assessment_id, "case_id": case_id,
        "finding_id": finding_id, "event_type": event_type, "actor": actor,
        "actor_role": data.get("actor_role"),
        "credential_type": data.get("credential_type"),
        "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "previous_hash": previous_hash,
        "classification": classification, "status": status,
        "control_owner": data.get("control_owner"), "due_at": data.get("due_at"),
        "root_cause": data.get("root_cause"), "correction": data.get("correction"),
        "corrective_action": data.get("corrective_action"),
        "compensating_control": data.get("compensating_control"),
        "analyst_signoff": data.get("analyst_signoff"),
        "verification_evidence_ids": verification_ids,
        "before_evidence_ids": before_ids, "after_evidence_ids": after_ids,
        "supporting_evidence_ids": [str(value) for value in data.get("supporting_evidence_ids") or [] if value],
        "framework_mappings": dict(data.get("framework_mappings") or {}),
        "framework_mapping_versions": dict(FRAMEWORK_MAPPING_VERSIONS),
        "notes": str(data.get("notes") or ""),
    }
    digest = canonical_hash(content)
    return {**content, "event_id": f"grc_{digest}", "content_hash": digest}


def verify_workflow_chain(events: list[Mapping[str, Any]]) -> tuple[bool, str]:
    """Verify content hashes and the per-finding append-only predecessor chain."""

    previous_by_finding: dict[str, str] = {}
    for event in events:
        content = {
            key: value for key, value in dict(event).items()
            if key not in {"event_id", "content_hash"}
        }
        content_hash = canonical_hash(content)
        if content_hash != event.get("content_hash") or event.get("event_id") != f"grc_{content_hash}":
            return False, "grc_event_content_hash_invalid"
        finding_id = str(event.get("finding_id") or "")
        if event.get("previous_hash") != previous_by_finding.get(finding_id):
            return False, "grc_event_previous_hash_invalid"
        previous_by_finding[finding_id] = content_hash
    return True, "verified"


def export_finding(event: Mapping[str, Any], target: str) -> dict[str, Any]:
    """Build a vendor-neutral handoff; credentials and dispatch stay external."""

    target = target.lower().strip()
    if target not in {"vanta", "logicgate", "protecht", "ideagen", "servicenow"}:
        raise ValueError("unsupported_grc_export_target")
    return {
        "schema_version": "janusec.grc-export/v1", "target": target,
        "external_action": "create_or_update_finding",
        "idempotency_key": event.get("content_hash"),
        "finding": {
            "external_ref": event.get("finding_id"),
            "title": f"Evidence-backed review: {event.get('finding_id')}",
            "classification": event.get("classification"), "status": event.get("status"),
            "owner": event.get("control_owner"), "due_at": event.get("due_at"),
            "root_cause": event.get("root_cause"), "correction": event.get("correction"),
            "corrective_action": event.get("corrective_action"),
            "compensating_control": event.get("compensating_control"),
            "verification_evidence_ids": list(event.get("verification_evidence_ids") or []),
            "supporting_evidence_ids": list(event.get("supporting_evidence_ids") or []),
            "framework_mappings": dict(event.get("framework_mappings") or {}),
            "source_receipt_hash": event.get("content_hash"),
        },
        "dispatched": False,
        "dispatch_note": "Payload prepared only; external mutation requires configured credentials and explicit approval.",
    }


def veeam_verification_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    tests = [dict(item) for item in payload.get("recovery_tests") or [] if isinstance(item, Mapping)]
    immutability = dict(payload.get("immutability") or {})
    return {
        "schema_version": "janusec.control-verification/veeam-v1",
        "source": "veeam", "source_version": payload.get("source_version"),
        "collected_at": payload.get("collected_at"),
        "immutability": immutability, "recovery_tests": tests,
        "verification_status": (
            "verified" if immutability.get("enabled") is True and tests and all(item.get("result") == "passed" for item in tests)
            else "failed" if any(item.get("result") == "failed" for item in tests)
            else "unverified"
        ),
        "provider_native": dict(payload),
    }


__all__ = [
    "FRAMEWORK_MAPPING_VERSIONS", "export_finding", "veeam_verification_evidence",
    "verify_workflow_chain", "workflow_event",
]
