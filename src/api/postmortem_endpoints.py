"""
Postmortem API Endpoints
========================

Six routes per ``architecture_wireframes.md`` C3 — wire into ``app.py`` the
same way other endpoint modules are mounted. Mounts on the same router prefix
pattern as ``breach_endpoints.py``.

INTEGRATION POINT
-----------------
In ``app.py``, add these lines alongside the other ``app.include_router(...)``
calls (search for ``include_router(breach_router)``):

    from src.api.postmortem_endpoints import router as postmortem_router
    app.include_router(postmortem_router)

ROUTES
------
POST  /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}/assemble
GET   /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}
PATCH /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}/sections/{section_id}
POST  /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}/sections/{section_id}/sign-off
POST  /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}/push-itsm
POST  /api/v1/postmortem/{assessment_id}/clusters/{cluster_id}/regulator-form

PERSISTENCE
-----------
Postmortems are persisted in ``cluster['postmortem']`` on the assessment
dict. The same ``_get_assessment(id)`` and ``_persist(id, assessment)``
helpers used in ``breach_endpoints.py`` are used here. If those helpers live
in a different module in your repo, adjust the import accordingly — they're
pulled from breach_endpoints below.

NOTE ON ``_get_tenant``
-----------------------
We use the same tenant-resolution helper as ``breach_endpoints.py``. The
tenant_id flows from there into postmortem_assembler.assemble().
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.postmortem.postmortem_assembler import (
    assemble,
    get_computed_section,
    all_sections_signed,
    signoff_summary,
    POSTMORTEM_VERSION,
)
from src.postmortem.human_edits import append_override
from src.postmortem.itsm_push import push_postmortem
from src.postmortem.regulator_forms import prefill_for_regulator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/postmortem", tags=["postmortem"])


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers — reused from breach_endpoints pattern
# ─────────────────────────────────────────────────────────────────────────────
# Import at function call time so this module loads cleanly even if
# breach_endpoints isn't fully importable.

def _get_assessment(assessment_id: str) -> Optional[dict]:
    from src.api.breach_endpoints import _get_assessment as _ga
    return _ga(assessment_id)


def _persist(assessment_id: str, assessment: dict) -> None:
    from src.api.breach_endpoints import _persist as _ps
    return _ps(assessment_id, assessment)


def _get_tenant(request: Request) -> str:
    from src.api.breach_endpoints import _get_tenant as _gt
    return _gt(request)


def _find_cluster(assessment: dict, cluster_id: str) -> Optional[dict]:
    clusters = assessment.get("correlation_clusters") or []
    for c in clusters:
        if (c.get("cluster_id") or c.get("id")) == cluster_id:
            return c
    return None


def _resolve_evidence_rows(assessment: dict, cluster: dict) -> list[dict]:
    """Same row-resolution pattern as breach_endpoints.regenerate_persona_dispatch."""
    all_rows = (assessment.get("normalized_rows") or
                assessment.get("evidence_rows") or
                assessment.get("rows") or [])
    row_lookup: dict[int, dict] = {}
    for r in all_rows:
        ri = r.get("row_index") or r.get("row_number") or r.get("id")
        if ri is None:
            continue
        try:
            row_lookup[int(float(ri))] = r
        except (TypeError, ValueError):
            pass
    out: list[dict] = []
    for ref in (cluster.get("row_refs") or []):
        try:
            k = int(float(ref))
            if k in row_lookup:
                out.append(row_lookup[k])
        except (TypeError, ValueError):
            pass
    return out


def _load_tenant_config(tenant_id: str) -> dict:
    """Load tenant config dict. Includes entity_name, abn, ciso/privacy_officer
    contacts, etc. Used by regulator forms and ITSM push.

    If your repo has a tenant config loader, swap this implementation. The
    contract is: returns a dict, never None. Empty dict is OK.
    """
    try:
        from src.config.tenant_data_classification import _load_tenant_config_dict  # type: ignore
        cfg = _load_tenant_config_dict(tenant_id) or {}
        return cfg
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  Request models
# ─────────────────────────────────────────────────────────────────────────────


class AssembleRequest(BaseModel):
    regenerate: bool = False


class OverrideRequest(BaseModel):
    actor: str = Field(..., description="user id or email of editor")
    field_path: str = Field(..., description="dotted path into auto_output")
    new_value: Any = Field(...)
    reason: str = Field(..., description="mandatory free-text justification")
    operation: str = Field("replace", description="replace | add | delete")


class SignOffRequest(BaseModel):
    actor: str
    notes: Optional[str] = None


class PushItsmRequest(BaseModel):
    target: str = Field(..., description="jira | confluence | servicenow")
    config_id: Optional[str] = None
    dry_run: bool = False
    config_override: Optional[dict] = Field(
        None, description="Inline config; if absent, loads from integrations state"
    )


class RegulatorFormRequest(BaseModel):
    regulator: str = Field(..., description="au_ndb | au_apra_cps234 | au_soci | au_cyber_security_act")
    ransomware_payment_made: bool = False
    ransomware_payment_meta: Optional[dict] = None


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/{assessment_id}/clusters/{cluster_id}/assemble")
async def assemble_postmortem(
    assessment_id: str,
    cluster_id: str,
    body: AssembleRequest,
    request: Request,
) -> JSONResponse:
    """Build (or rebuild) a postmortem for a cluster.

    Idempotent unless ``regenerate=True``. If a postmortem already exists
    and regenerate is false, returns the existing one.
    """
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")

    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")

    existing = cluster.get("postmortem")
    if existing and not body.regenerate:
        return JSONResponse({
            "assessment_id": assessment_id,
            "cluster_id":    cluster_id,
            "postmortem":    existing,
            "regenerated":   False,
        })

    tenant_id = _get_tenant(request)

    # Re-run enrich + register at assemble-time to ensure the postmortem reads
    # fresh narrative + register state. This is the same code path as
    # breach_endpoints.regenerate_persona_dispatch.
    try:
        from src.analysis.framework_mapper import build_control_failure_register
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=f"upstream_modules_unavailable: {exc}")

    narrative = cluster.get("llm_narrative") or cluster.get("tier1_prefill") or {}
    if not isinstance(narrative, dict):
        narrative = {}

    tenant_class = None
    try:
        from src.config.tenant_data_classification import load_for_tenant
        tenant_class = load_for_tenant(tenant_id)
    except Exception:
        pass

    cl_rows = _resolve_evidence_rows(assessment, cluster)
    narrative = enrich_narrative(narrative, cluster, cl_rows,
                                 tenant_classification=tenant_class)
    if not narrative.get("mitre_techniques"):
        # Fallback — same logic as breach_endpoints.
        narrative["mitre_techniques"] = cluster.get("mitre_techniques") or []

    # ── Inject cluster-level verdict / confidence / kill chain into narrative ──
    # _build_verdict_block() reads from narrative, but the pipeline stores
    # verdict + confidence directly on the cluster dict (not in llm_narrative).
    # Inject them here so the postmortem verdict block reflects actual results.
    if not narrative.get("verdict"):
        raw_v = (cluster.get("verdict") or cluster.get("final_verdict") or "").upper()
        if raw_v:
            narrative["verdict"] = raw_v
    if not narrative.get("confidence"):
        raw_conf = cluster.get("confidence") or cluster.get("confidence_score") or 0.0
        try:
            narrative["confidence"] = float(raw_conf)
        except (TypeError, ValueError):
            pass
    if not narrative.get("kill_chain_stage"):
        phases = cluster.get("phases") or []
        kc_summary = (cluster.get("tier1_prefill") or {}).get("kill_chain_summary") or ""
        if phases:
            phase_names = [p.get("name") or p.get("phase_id", "") for p in phases
                           if p.get("name") or p.get("phase_id")]
            if len(phase_names) <= 5:
                narrative["kill_chain_stage"] = " → ".join(phase_names)
            else:
                narrative["kill_chain_stage"] = (
                    " → ".join(phase_names[:3])
                    + f" → … → {phase_names[-1]} (+{len(phase_names)-4} more phases)"
                )
        elif kc_summary:
            narrative["kill_chain_stage"] = kc_summary[:200]

    cluster["llm_narrative"] = narrative

    entity_context = assessment.get("entity_context") or {}
    register = build_control_failure_register(
        narrative, evidence_rows=cl_rows, entity_context=entity_context,
    )

    tenant_config = _load_tenant_config(tenant_id)

    document = assemble(
        cluster=cluster,
        narrative=narrative,
        register=register,
        evidence_rows=cl_rows,
        tenant_id=tenant_id,
        tenant_config=tenant_config,
        entity_context=entity_context,
        assessment_id=assessment_id,
        prior_postmortem=existing if body.regenerate else None,
    )

    # Attach tenant_config so UI can render tenant header (entity_name, ABN, CISO)
    document["tenant_config"] = tenant_config or {}

    cluster["postmortem"] = document
    _persist(assessment_id, assessment)

    return JSONResponse({
        "assessment_id": assessment_id,
        "cluster_id":    cluster_id,
        "postmortem":    document,
        "regenerated":   body.regenerate,
    })


@router.get("/{assessment_id}/clusters/{cluster_id}")
async def get_postmortem(
    assessment_id: str,
    cluster_id: str,
    request: Request,
) -> JSONResponse:
    """Return the current postmortem for a cluster."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")

    pm = cluster.get("postmortem")
    if not pm:
        raise HTTPException(status_code=404, detail="postmortem_not_found")

    # Attach signoff summary for the UI header.
    return JSONResponse({
        "postmortem":         pm,
        "signoff_summary":    signoff_summary(pm),
        "all_signed":         all_sections_signed(pm),
        "postmortem_version": POSTMORTEM_VERSION,
    })


@router.patch("/{assessment_id}/clusters/{cluster_id}/sections/{section_id}")
async def patch_section(
    assessment_id: str,
    cluster_id: str,
    section_id: str,
    body: OverrideRequest,
    request: Request,
) -> JSONResponse:
    """Apply a human override to a section's auto_output."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")
    pm = cluster.get("postmortem")
    if not pm:
        raise HTTPException(status_code=404, detail="postmortem_not_found")

    section = next((s for s in (pm.get("sections") or [])
                    if s.get("section_id") == section_id), None)
    if not section:
        raise HTTPException(status_code=404, detail="section_not_found")

    override = append_override(
        section,
        actor=body.actor,
        field_path=body.field_path,
        new_value=body.new_value,
        reason=body.reason,
        operation=body.operation,
    )

    # Adding an override invalidates any prior signoff on this section —
    # the analyst must re-sign after edits.
    if section.get("signoff"):
        section["signoff_history"] = section.setdefault("signoff_history", [])
        section["signoff_history"].append(section["signoff"])
        section["signoff"] = None

    _persist(assessment_id, assessment)

    return JSONResponse({
        "assessment_id":  assessment_id,
        "cluster_id":     cluster_id,
        "section_id":     section_id,
        "override":       override,
        "computed_view":  get_computed_section(pm, section_id),
        "signoff_invalidated": True,
    })


@router.post("/{assessment_id}/clusters/{cluster_id}/sections/{section_id}/sign-off")
async def sign_off_section(
    assessment_id: str,
    cluster_id: str,
    section_id: str,
    body: SignOffRequest,
    request: Request,
) -> JSONResponse:
    """Mark a section signed off. Bitemporal — signoff records the state
    hash of the section at signoff time."""
    import hashlib
    import json as _json

    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")
    pm = cluster.get("postmortem")
    if not pm:
        raise HTTPException(status_code=404, detail="postmortem_not_found")

    section = next((s for s in (pm.get("sections") or [])
                    if s.get("section_id") == section_id), None)
    if not section:
        raise HTTPException(status_code=404, detail="section_not_found")

    if section.get("v1_status") == "STUB":
        raise HTTPException(status_code=400, detail="cannot_sign_off_v2_stub")

    # Compute hash of the computed view at signoff time so future audit can
    # verify the section state hasn't been tampered with after signoff.
    computed = get_computed_section(pm, section_id)
    state_hash = "sha256:" + hashlib.sha256(
        _json.dumps(computed, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    section["signoff"] = {
        "signed_by":          body.actor,
        "signed_at":          datetime.now(timezone.utc).isoformat(),
        "signed_state_hash":  state_hash,
        "notes":              body.notes,
    }
    _persist(assessment_id, assessment)

    return JSONResponse({
        "assessment_id":      assessment_id,
        "cluster_id":         cluster_id,
        "section_id":         section_id,
        "signoff":            section["signoff"],
        "all_signed":         all_sections_signed(pm),
    })


@router.post("/{assessment_id}/clusters/{cluster_id}/push-itsm")
async def push_to_itsm(
    assessment_id: str,
    cluster_id: str,
    body: PushItsmRequest,
    request: Request,
) -> JSONResponse:
    """Push the postmortem to the customer's ITSM (Jira / Confluence / ServiceNow)."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")
    pm = cluster.get("postmortem")
    if not pm:
        raise HTTPException(status_code=404, detail="postmortem_not_found")

    # Resolve the integration config. If config_override is supplied, use it
    # directly; otherwise pull from the same _STATE that integrations_endpoints
    # owns. Adjust this lookup if your tenant separates ITSM configs differently.
    config = body.config_override
    if config is None:
        config = _load_itsm_config(body.target, _get_tenant(request))

    if not config:
        raise HTTPException(status_code=400, detail=f"no_config_for_target:{body.target}")

    result = push_postmortem(
        document=pm,
        target=body.target,
        config=config,
        dry_run=body.dry_run,
    )

    # Record the push in the postmortem for the audit trail (unless dry-run).
    if not body.dry_run and result.get("success"):
        pm.setdefault("itsm_links", []).append({
            "target":          body.target,
            "parent_key":      result.get("parent_key"),
            "parent_url":      result.get("parent_url"),
            "child_count":     result.get("child_count"),
            "any_failed":      result.get("any_failed"),
            "pushed_at":       datetime.now(timezone.utc).isoformat(),
            "pushed_by":       _get_tenant(request),
        })
        _persist(assessment_id, assessment)

    return JSONResponse(result)


@router.post("/{assessment_id}/clusters/{cluster_id}/regulator-form")
async def regulator_form_prefill(
    assessment_id: str,
    cluster_id: str,
    body: RegulatorFormRequest,
    request: Request,
) -> JSONResponse:
    """Pre-fill a regulator notification form. Never auto-submits."""
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="assessment_not_found")
    cluster = _find_cluster(assessment, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="cluster_not_found")
    pm = cluster.get("postmortem")
    if not pm:
        raise HTTPException(status_code=404, detail="postmortem_not_found")

    tenant_id = _get_tenant(request)
    tenant_config = _load_tenant_config(tenant_id)

    # Pass through narrative + entity_context as private keys. The regulator
    # form modules read these for fields not directly present on the
    # assembled postmortem (e.g. raw record_count_estimate).
    tenant_config = dict(tenant_config)  # don't mutate the cached dict
    tenant_config["_narrative_passthrough"] = cluster.get("llm_narrative") or {}
    tenant_config["_entity_context_passthrough"] = assessment.get("entity_context") or {}

    if body.regulator in ("au_cyber_security_act", "csa_ransomware"):
        tenant_config["_ransomware_payment_made"] = body.ransomware_payment_made
        tenant_config["_ransomware_payment_meta"] = body.ransomware_payment_meta or {}

    payload = prefill_for_regulator(
        regulator_id=body.regulator,
        document=pm,
        tenant_config=tenant_config,
    )

    # Update the postmortem's regulator_submissions block to reflect that the
    # pre-fill was generated.
    for sub in (pm.get("regulator_submissions") or []):
        if sub.get("regulator") == body.regulator and sub.get("status") == "draft":
            sub["status"] = "prefilled_pending_review"
            sub["prefilled_at"] = datetime.now(timezone.utc).isoformat()
            break
    _persist(assessment_id, assessment)

    return JSONResponse({
        "assessment_id": assessment_id,
        "cluster_id":    cluster_id,
        "regulator":     body.regulator,
        "prefill":       payload,
    })


# ─────────────────────────────────────────────────────────────────────────────
#  ITSM config loader
# ─────────────────────────────────────────────────────────────────────────────


def _load_itsm_config(target: str, tenant_id: str) -> Optional[dict]:
    """Read ITSM config from the existing _STATE in integrations_endpoints.

    Maps target -> _STATE key. If your repo persists ITSM configs differently
    (e.g. per-tenant DB rows), swap this implementation.
    """
    target = (target or "").lower()
    try:
        from src.api.integrations_endpoints import _STATE  # type: ignore
    except Exception as exc:
        logger.warning("could not import integrations _STATE: %s", exc)
        return None

    if target == "jira":
        return dict(_STATE.get("jira") or {})
    if target == "confluence":
        return dict(_STATE.get("confluence") or {})
    if target == "servicenow":
        return dict(_STATE.get("servicenow") or {})
    return None


__all__ = ["router"]
