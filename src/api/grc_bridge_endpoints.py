"""Human-governed GRC lifecycle and export-payload endpoints."""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from src.security.auth import require_api_key


router = APIRouter(tags=["grc-evidence-bridge"])


def _grc_actor(auth: object, body: dict[str, Any]) -> tuple[str, str]:
    """Derive accountable identity and role from verified credentials, never JSON."""

    actor = str(getattr(auth, "subject", "") or "").strip()
    scopes = {str(value) for value in (getattr(auth, "scopes", None) or [])}
    if str(getattr(auth, "credential_type", "") or "") != "jwt":
        raise HTTPException(status_code=403, detail="jwt_grc_actor_required")
    if not actor:
        raise HTTPException(status_code=403, detail="authenticated_grc_actor_required")
    classification = str(body.get("classification") or "possible_control_weakness")
    status = str(body.get("status") or "open")
    event_type = str(body.get("event_type") or "").lower()
    if classification in {"nonconformity", "formal_nonconformity"}:
        required_scope, role = "grc.audit", "auditor"
    elif status in {"verified", "closed"} or event_type in {"verify", "close"}:
        required_scope, role = "grc.verify", "independent_reviewer"
    elif status == "approved" or event_type == "approve":
        required_scope, role = "grc.approve", "approver"
    elif status in {"assigned", "implementing", "implemented", "correcting", "verification_pending"}:
        required_scope, role = "grc.write", "control_owner"
    else:
        required_scope, role = "grc.review", "analyst"
    if "*" not in scopes and required_scope not in scopes:
        raise HTTPException(status_code=403, detail=f"{required_scope}_scope_required")
    return actor, role


async def _validate_evidence_references(
    *, tenant_id: str, assessment_id: str, case_id: str, body: dict[str, Any],
) -> None:
    requested = {
        str(value) for key in (
            "supporting_evidence_ids", "verification_evidence_ids",
            "before_evidence_ids", "after_evidence_ids",
        )
        for value in body.get(key) or [] if value
    }
    if not requested:
        return
    from src.repositories.evidence_ledger_repo import list_case

    records: list[dict[str, Any]] = []
    for scope in dict.fromkeys((assessment_id, case_id)):
        records.extend(await list_case(tenant_id, scope, limit=10000))
    valid = {
        str(record.get("evidence_id") or record.get("record_id") or "")
        for record in records
    }
    from src.core.evidence_contract.signed_snapshots import verify_snapshot
    from src.repositories.infrastructure_truth_repo import list_snapshots

    for snapshot in await list_snapshots(tenant_id, "control_verification", limit=10000):
        verified, _ = verify_snapshot(
            snapshot, expected_kind="control_verification", tenant_id=tenant_id,
        )
        if not verified:
            continue
        receipt = snapshot.get("snapshot_receipt") if isinstance(snapshot.get("snapshot_receipt"), dict) else {}
        receipt_hash = str(receipt.get("receipt_hash") or "")
        if receipt_hash:
            valid.update({receipt_hash, f"infra_{receipt_hash}"})
    missing = sorted(requested - valid)
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"code": "grc_evidence_not_in_tenant_ledger", "evidence_ids": missing},
        )


def _verify_history(history: list[dict[str, Any]]) -> None:
    from src.core.grc.evidence_bridge import verify_workflow_chain

    verified, reason = verify_workflow_chain(history)
    if not verified:
        raise HTTPException(status_code=409, detail=reason)


def _tenant(request: Request, auth: object) -> str:
    from src.api.ingest_endpoints import _assessment_tenant

    return _assessment_tenant(request, auth)


async def _authorize_assessment(assessment_id: str, tenant_id: str) -> None:
    from src.api.ingest_endpoints import _owned_job
    from src.core.ingest import store

    await asyncio.to_thread(_owned_job, store, assessment_id, tenant_id)


@router.post("/api/v1/assessments/{assessment_id}/cases/{case_id}/grc/events")
async def create_grc_event(
    assessment_id: str, case_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    body = await request.json()
    if not isinstance(body, dict) or not body.get("finding_id"):
        raise HTTPException(status_code=422, detail="finding_id_required")
    from src.repositories.grc_workflow_repo import append_event, list_events
    from src.core.grc.evidence_bridge import workflow_event

    history = await list_events(tenant_id, assessment_id, case_id)
    _verify_history(history)
    await _validate_evidence_references(
        tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id, body=body,
    )
    actor, actor_role = _grc_actor(auth, body)
    event_data = {
        **body, "actor_role": actor_role,
        "credential_type": getattr(auth, "credential_type", None),
    }
    if str(body.get("classification") or "") in {"nonconformity", "formal_nonconformity"}:
        event_data["analyst_signoff"] = actor
    if str(body.get("status") or "") in {"verified", "closed"}:
        implementers = {
            str(item.get("actor") or "") for item in history
            if item.get("status") == "correcting" or "implement" in str(item.get("event_type") or "")
        }
        if actor in implementers:
            raise HTTPException(status_code=409, detail="independent_closure_verifier_required")
    prior = next((item for item in reversed(history) if item.get("finding_id") == body["finding_id"]), None)
    try:
        event = workflow_event(
            tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id,
            finding_id=str(body["finding_id"]), event_type=str(body.get("event_type") or "review_updated"),
            actor=actor, data=event_data,
            previous_hash=prior.get("content_hash") if prior else None,
            previous_event=prior,
        )
        persisted = await append_event(event)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    from src.api.deep_analyze.persistence import _get_assessment_cached, _persist_assessment_state

    assessment = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    if isinstance(assessment, dict):
        updated = dict(assessment)
        updated["grc_workflow_events"] = [
            *[item for item in updated.get("grc_workflow_events") or [] if isinstance(item, dict)],
            event,
        ]
        await asyncio.to_thread(_persist_assessment_state, assessment_id, updated)
    return {"event": event, "persistence": persisted}


@router.get("/api/v1/assessments/{assessment_id}/cases/{case_id}/grc/events")
async def get_grc_events(
    assessment_id: str, case_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    from src.repositories.grc_workflow_repo import list_events

    events = await list_events(tenant_id, assessment_id, case_id)
    _verify_history(events)
    return {"assessment_id": assessment_id, "case_id": case_id, "chain_status": "verified", "events": events}


@router.post("/api/v1/assessments/{assessment_id}/cases/{case_id}/grc/export/{target}")
async def prepare_grc_export(
    assessment_id: str, case_id: str, target: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    body = await request.json()
    finding_id = str(body.get("finding_id") or "") if isinstance(body, dict) else ""
    from src.repositories.grc_workflow_repo import list_events
    from src.core.grc.evidence_bridge import export_finding

    history = await list_events(tenant_id, assessment_id, case_id)
    _verify_history(history)
    event = next((item for item in reversed(history) if not finding_id or item.get("finding_id") == finding_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="grc_finding_not_found")
    try:
        return export_finding(event, target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/v1/assessments/{assessment_id}/cases/{case_id}/grc/export/{target}/dispatch")
async def dispatch_grc_export(
    assessment_id: str, case_id: str, target: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    body = await request.json()
    if not isinstance(body, dict) or body.get("explicit_approval") is not True or not body.get("approval_receipt_hash"):
        raise HTTPException(status_code=422, detail="explicit_approval_and_receipt_required")
    scopes = {str(value) for value in (getattr(auth, "scopes", None) or [])}
    if str(getattr(auth, "credential_type", "") or "") != "jwt":
        raise HTTPException(status_code=403, detail="jwt_grc_approver_required")
    if "*" not in scopes and "grc.approve" not in scopes:
        raise HTTPException(status_code=403, detail="grc.approve_scope_required")
    from src.repositories.grc_workflow_repo import list_events
    from src.core.grc.evidence_bridge import export_finding
    history = await list_events(tenant_id, assessment_id, case_id)
    _verify_history(history)
    finding_id = str(body.get("finding_id") or "")
    event = next((item for item in reversed(history) if not finding_id or item.get("finding_id") == finding_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="grc_finding_not_found")
    export_payload = export_finding(event, target)
    from src.repositories.grc_dispatch_repo import get_receipt_by_idempotency
    existing = await get_receipt_by_idempotency(
        tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id,
        target=target, idempotency_key=str(export_payload["idempotency_key"]),
    )
    if existing:
        return {"dispatch_receipt": existing, "appended": False, "network_dispatch": False}
    from src.core.grc.outbound_connectors import config_from_environment, dispatch_approved_finding
    try:
        config = config_from_environment(target)
        receipt = await asyncio.to_thread(
            dispatch_approved_finding, export_payload=export_payload, config=config,
            approved_by=str(getattr(auth, "subject", "")),
            approval_receipt_hash=str(body["approval_receipt_hash"]), explicit_approval=True,
        )
    except (RuntimeError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    from src.repositories.grc_dispatch_repo import append_receipt
    appended = await append_receipt(
        tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id, receipt=receipt,
    )
    return {"dispatch_receipt": receipt, "appended": appended, "network_dispatch": True}


@router.get("/api/v1/assessments/{assessment_id}/cases/{case_id}/grc/export/receipts")
async def get_grc_dispatch_receipts(
    assessment_id: str, case_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    from src.repositories.grc_dispatch_repo import list_receipts

    return {
        "assessment_id": assessment_id, "case_id": case_id,
        "dispatch_receipts": await list_receipts(
            tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id,
        ),
    }


@router.post("/api/v1/assessments/{assessment_id}/grc/verification/veeam")
async def ingest_veeam_verification(
    assessment_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    scopes = {str(value) for value in (getattr(auth, "scopes", None) or [])}
    if "*" not in scopes and "infrastructure.collect" not in scopes:
        raise HTTPException(status_code=403, detail="infrastructure.collect_scope_required")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="veeam_payload_required")
    from src.core.grc.evidence_bridge import veeam_verification_evidence
    from src.core.evidence_contract.signed_snapshots import sign_snapshot
    from src.repositories.infrastructure_truth_repo import append_snapshot

    evidence = veeam_verification_evidence(body)
    try:
        signed = sign_snapshot(
            kind="control_verification", tenant_id=tenant_id, payload=evidence,
            source="veeam", version=str(body.get("source_version") or "unknown"),
            valid_from=str(body.get("collected_at") or dt.datetime.now(dt.timezone.utc).isoformat()),
            valid_to=body.get("valid_to"),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    persisted = await append_snapshot(signed)
    return {"verification_evidence": signed, "persistence": persisted}


@router.post("/api/v1/assessments/{assessment_id}/grc/verification/provider/{provider}")
async def ingest_provider_verification(
    assessment_id: str, provider: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    """Sign a read-only before/after verification observation; never execute an action."""

    tenant_id = _tenant(request, auth)
    await _authorize_assessment(assessment_id, tenant_id)
    scopes = {str(value) for value in (getattr(auth, "scopes", None) or [])}
    if "*" not in scopes and "infrastructure.collect" not in scopes:
        raise HTTPException(status_code=403, detail="infrastructure.collect_scope_required")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="provider_verification_payload_required")
    from src.core.grc.verification_adapters import (
        build_verification_payload, sign_provider_verification,
    )

    try:
        payload = build_verification_payload(
            provider=provider, action_id=str(body.get("action_id") or ""),
            before_native=body.get("before_native") or {},
            after_native=body.get("after_native") or {},
            expected_after=body.get("expected_after") or {},
            collector_identity=str(getattr(auth, "subject", "") or ""),
            request_receipt=body.get("request_receipt") or {},
            clock_uncertainty_seconds=float(body.get("clock_uncertainty_seconds") or 0.0),
        )
        signed = sign_provider_verification(
            tenant_id=tenant_id, payload=payload,
            version=str(body.get("provider_version") or "unknown"),
            valid_from=str(body.get("collected_at") or dt.datetime.now(dt.timezone.utc).isoformat()),
            valid_to=body.get("valid_to"),
        )
    except (ValueError, TypeError, RuntimeError) as exc:
        raise HTTPException(status_code=422 if not isinstance(exc, RuntimeError) else 503, detail=str(exc)) from exc
    from src.repositories.infrastructure_truth_repo import append_snapshot

    persisted = await append_snapshot(signed)
    return {
        "assessment_id": assessment_id, "provider": provider,
        "collection_mode": "read_only", "verification_status": payload["verification_status"],
        "verification_evidence": signed, "persistence": persisted,
    }


__all__ = ["router"]
