"""Assessment-scoped ingestion and status for signed infrastructure truth."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from src.security.auth import require_api_key


router = APIRouter(tags=["infrastructure-truth"])
_ASSESSMENT_KEYS = {
    "iam": "authorization_snapshot",
    "topology": "topology_snapshot",
    "cmdb": "cmdb_mapping_receipt",
    "data_classification": "data_classification_snapshot",
    "regulatory_applicability": "regulatory_applicability_snapshot",
}


def _tenant(request: Request, auth: object) -> str:
    from src.api.ingest_endpoints import _assessment_tenant

    return _assessment_tenant(request, auth)


async def _assessment(assessment_id: str, tenant_id: str) -> dict[str, Any]:
    from src.api.deep_analyze.persistence import _get_assessment_cached
    from src.api.ingest_endpoints import _owned_job
    from src.core.ingest import store

    await asyncio.to_thread(_owned_job, store, assessment_id, tenant_id)
    value = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    if not isinstance(value, dict) or str(value.get("org") or tenant_id) != tenant_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return dict(value)


@router.post("/api/v1/assessments/{assessment_id}/infrastructure-snapshots/{kind}")
async def attach_infrastructure_snapshot(
    assessment_id: str,
    kind: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    if kind not in _ASSESSMENT_KEYS:
        raise HTTPException(status_code=404, detail="unsupported_snapshot_kind")
    tenant_id = _tenant(request, auth)
    body = await request.json()
    snapshot = body.get("snapshot") if isinstance(body, dict) and isinstance(body.get("snapshot"), dict) else body
    if not isinstance(snapshot, dict):
        raise HTTPException(status_code=422, detail="snapshot_required")
    from src.core.evidence_contract.signed_snapshots import verify_snapshot
    from src.core.evidence_contract.asymmetric_signing import cloud_verifier

    receipt = snapshot.get("snapshot_receipt") if isinstance(snapshot.get("snapshot_receipt"), dict) else {}
    verifier = cloud_verifier(
        algorithm=str(receipt.get("algorithm") or ""), key_id=str(receipt.get("key_id") or ""),
    )
    valid, reason = verify_snapshot(
        snapshot, expected_kind=kind, tenant_id=tenant_id, verifier=verifier,
    )
    if not valid:
        raise HTTPException(status_code=422, detail=reason)
    from src.repositories.infrastructure_truth_repo import append_snapshot

    persisted = await append_snapshot(snapshot)
    assessment = await _assessment(assessment_id, tenant_id)
    assessment[_ASSESSMENT_KEYS[kind]] = snapshot
    assessment.setdefault("infrastructure_truth", {})[kind] = {
        "snapshot_id": persisted["snapshot_id"],
        "receipt_hash": snapshot["snapshot_receipt"]["receipt_hash"],
        "verification": reason,
    }
    for projection in (assessment.get("graph_projections_by_case") or {}).values():
        if isinstance(projection, dict):
            projection["status"] = "stale"
            projection["staleness_reasons"] = sorted({
                *(projection.get("staleness_reasons") or []), f"{kind}_changed",
            })
    if isinstance(assessment.get("graph_projection"), dict):
        assessment["graph_projection"]["status"] = "stale"
        assessment["graph_projection"]["staleness_reasons"] = sorted({
            *(assessment["graph_projection"].get("staleness_reasons") or []), f"{kind}_changed",
        })
    # The old projection remains immutable and is now stale. The normal case
    # view path schedules its replacement and keeps the old receipt auditable.
    from src.api.deep_analyze.persistence import _persist_assessment_state

    await asyncio.to_thread(_persist_assessment_state, assessment_id, assessment)
    return {
        "assessment_id": assessment_id,
        "kind": kind,
        "status": "attached_projection_rebuild_required",
        "snapshot": assessment["infrastructure_truth"][kind],
        "persistence": persisted,
    }


@router.get("/api/v1/assessments/{assessment_id}/infrastructure-snapshots")
async def infrastructure_snapshot_status(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    assessment = await _assessment(assessment_id, tenant_id)
    from src.core.evidence_contract.signed_snapshots import verify_snapshot
    from src.core.evidence_contract.asymmetric_signing import cloud_verifier

    status: dict[str, Any] = {}
    for kind, key in _ASSESSMENT_KEYS.items():
        snapshot = assessment.get(key) if isinstance(assessment.get(key), dict) else None
        receipt = snapshot.get("snapshot_receipt") if snapshot else {}
        verifier = cloud_verifier(
            algorithm=str(receipt.get("algorithm") or ""), key_id=str(receipt.get("key_id") or ""),
        ) if receipt else None
        valid, reason = verify_snapshot(
            snapshot, expected_kind=kind, tenant_id=tenant_id, verifier=verifier,
        ) if snapshot else (False, "snapshot_missing")
        status[kind] = {
            "valid": valid, "reason": reason,
            "receipt_hash": receipt.get("receipt_hash"),
            "valid_to": receipt.get("valid_to"),
        }
    return {
        "assessment_id": assessment_id,
        "snapshots": status,
        "business_impact_available": bool(status["cmdb"]["valid"]),
        "regulated_data_conclusions_available": bool(
            status["data_classification"]["valid"] and status["regulatory_applicability"]["valid"]
        ),
    }


__all__ = ["router"]
