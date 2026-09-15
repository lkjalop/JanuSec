"""Async assessment ingest API — Phase 2 upload pipeline.

Endpoints:
  POST /api/v1/assessments/upload
      Multipart upload of raw files.  Returns 202 with assessment_id immediately.
      Files are saved to data/raw/{assessment_id}/ and a background job is
      queued to parse, cluster, and persist the assessment.

  GET  /api/v1/assessments/{assessment_id}/progress
      Critical addition #5: Server-Sent Events stream.
      Pushes stage/percent/label events as the worker progresses.
      Falls back gracefully when called from non-SSE clients (see /progress/poll).

  GET  /api/v1/assessments/{assessment_id}/progress/poll
      Plain JSON snapshot for polling clients or non-EventSource browsers.

  POST /api/v1/assessments/{assessment_id}/cancel
      Mark a queued/running job as cancelled.  Does not kill a running worker
      mid-flight but will be checked at the start of each pipeline stage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from typing import Annotated, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.api.tenant_helpers import (
    resolve_tenant_id,
    resolve_tenant_with_default,
    tenant_override_allowed,
)
from src.security.auth import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assessments", tags=["ingest"])
_GRAPH_REBUILD_TASKS: set[str] = set()

_MAX_UPLOAD_BYTES = int(os.getenv("JANUSEC_MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))  # 500 MB
_MAX_FILES = int(os.getenv("JANUSEC_MAX_FILES", "20"))
_ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson", ".xlsx", ".xlsm"}
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_WINDOWS_RESERVED_COMPONENTS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _validate_tenant_identifier(value: object, *, source: str) -> str:
    """Return a filesystem-safe tenant identifier or reject the request.

    Tenant identifiers are persisted as directory names by the assessment worker.
    Keep validation deliberately strict and lossless: silently replacing unsafe
    characters could alias two authenticated tenants to the same directory.
    """
    tenant = str(value or "").strip()
    if (
        not tenant
        or not _TENANT_ID_RE.fullmatch(tenant)
        or tenant.endswith(".")
        or tenant.split(".", 1)[0].upper() in _WINDOWS_RESERVED_COMPONENTS
    ):
        status = 422 if source == "form" else 400
        raise HTTPException(status_code=status, detail="invalid_tenant_identifier")
    return tenant


def _is_explicit_dev_or_test_mode() -> bool:
    return (
        os.getenv("JANUSEC_DEV_MODE", "0").lower() in {"1", "true", "yes"}
        or os.getenv("TEST_HELPERS_ENABLED", "0").lower() in {"1", "true", "yes"}
        or os.getenv("PLATFORM_LITE_INIT", "0").lower() in {"1", "true", "yes"}
        or os.getenv("APP_ENV", "").lower() in {"dev", "development", "local", "test"}
        or os.getenv("ENV", "").lower() in {"dev", "development", "local", "test"}
        or "PYTEST_CURRENT_TEST" in os.environ
    )


def _form_tenant_identifier(form: object) -> str | None:
    """Resolve the legacy org/tenant aliases, rejecting ambiguous requests."""
    values: list[str] = []
    for field in ("tenant_id", "tenant", "org"):
        try:
            raw = form.get(field)  # type: ignore[attr-defined]
        except Exception:
            raw = None
        if raw not in (None, ""):
            values.append(_validate_tenant_identifier(raw, source="form"))
    unique = set(values)
    if len(unique) > 1:
        raise HTTPException(status_code=422, detail="conflicting_tenant_identifiers")
    return values[0] if values else None


def _resolve_upload_tenant(request: Request, form: object, auth: object | None = None) -> str:
    """Resolve upload ownership without allowing form fields to widen scope.

    A tenant-bound authentication context always wins. For unbound credentials,
    an explicit request header/query (as captured by TenantMiddleware) wins. The
    legacy multipart ``org`` field remains selectable only when it agrees with
    that request scope, except in explicit dev/test mode where it may replace an
    implicitly supplied default tenant.
    """
    requested_tenant = _form_tenant_identifier(form)

    state_auth = getattr(request.state, "auth", None)
    # Preserve a tenant binding attached by the global auth middleware when a
    # permissive test dependency returns an otherwise unbound context.
    effective_auth = auth if getattr(auth, "tenant_id", None) else state_auth or auth
    auth_tenant_raw = getattr(effective_auth, "tenant_id", None)
    auth_tenant = (
        _validate_tenant_identifier(auth_tenant_raw, source="auth") if auth_tenant_raw not in (None, "") else None
    )

    explicit_raw = (
        request.headers.get("X-Tenant-ID")
        or request.headers.get("x-tenant-id")
        or request.query_params.get("tenant_id")
        or request.query_params.get("tenant")
    )
    explicit_tenant = (
        _validate_tenant_identifier(explicit_raw, source="request") if explicit_raw not in (None, "") else None
    )

    state_raw = getattr(request.state, "tenant_id", None)
    state_tenant = _validate_tenant_identifier(state_raw, source="request") if state_raw not in (None, "") else None

    if auth_tenant:
        if explicit_tenant and explicit_tenant != auth_tenant:
            raise HTTPException(status_code=403, detail="tenant_scope_mismatch")
        if requested_tenant and requested_tenant != auth_tenant:
            raise HTTPException(status_code=403, detail="tenant_scope_mismatch")
        return auth_tenant

    if explicit_tenant:
        if requested_tenant and requested_tenant != explicit_tenant:
            raise HTTPException(status_code=403, detail="tenant_scope_mismatch")
        return explicit_tenant

    if requested_tenant:
        if state_tenant and state_tenant != requested_tenant:
            default_tenant = _validate_tenant_identifier(os.getenv("DEFAULT_TENANT", "default"), source="request")
            if not (tenant_override_allowed() and state_tenant == default_tenant):
                raise HTTPException(status_code=403, detail="tenant_scope_mismatch")
        elif not state_tenant and not tenant_override_allowed():
            raise HTTPException(status_code=400, detail="tenant_required")
        return requested_tenant

    if state_tenant:
        return state_tenant
    if _is_explicit_dev_or_test_mode():
        return _validate_tenant_identifier(os.getenv("DEFAULT_TENANT", "default"), source="request")
    raise HTTPException(status_code=400, detail="tenant_required")


# ── POST /upload ──────────────────────────────────────────────────────────────


@router.post("/upload", status_code=202)
async def upload_assessment(
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    """Accept multipart file upload; queue background ingest job.

    Returns: {assessment_id, status: "queued", file_count, message}
    """
    from src.core.ingest import store as _store
    from src.core.ingest.assessment_worker import IngestQueueFull, enqueue_job, start_worker

    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" not in content_type:
        raise HTTPException(status_code=415, detail="Multipart/form-data required")

    try:
        form = await request.form()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Form parse failed: {exc}") from exc

    files = form.getlist("files")
    if not files:
        raise HTTPException(status_code=422, detail="No files provided in 'files' field")
    if len(files) > _MAX_FILES:
        raise HTTPException(status_code=422, detail=f"Too many files (max {_MAX_FILES})")

    # Resolve one canonical tenant. A multipart org/tenant alias may never
    # override a tenant-bound auth context or an explicit request tenant.
    org = _resolve_upload_tenant(request, form, auth)

    assessment_id = f"assessment-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    raw_dir = _store.raw_dir_for(assessment_id, tenant_id=org)
    _store.create_job(assessment_id, org=org)

    saved: list[tuple[str, str]] = []
    saved_names: set[str] = set()
    total_bytes = 0
    try:
        for f in files:
            if not hasattr(f, "filename"):
                continue
            ext = os.path.splitext(str(f.filename))[1].lower()
            if ext not in _ALLOWED_EXTENSIONS:
                logger.warning("ingest upload: skipping unsupported file type %s", f.filename)
                continue
            safe_name = _safe_filename(str(f.filename))
            if safe_name in saved_names:
                raise HTTPException(
                    status_code=422,
                    detail=f"Duplicate upload filename: {safe_name}",
                )
            saved_names.add(safe_name)
            dest = os.path.join(raw_dir, safe_name)
            # A raw capture is write-once within its assessment. Downstream
            # stages consume the registered SHA-256 rather than rewriting it.
            with open(dest, "xb") as fh:
                size_bytes = 0
                while content := await f.read(1024 * 1024):
                    total_bytes += len(content)
                    if total_bytes > _MAX_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail="Upload exceeds configured byte limit")
                    fh.write(content)
                    size_bytes += len(content)
            saved.append((dest, str(f.filename)))
            try:
                _store.register_file(assessment_id, str(f.filename), dest, size_bytes)
            except Exception:
                raise HTTPException(status_code=503, detail="Raw capture registration failed") from None
    except HTTPException as exc:
        _store.update_job(assessment_id, status="failed", stage="upload", percent=0, error=str(exc.detail))
        raise
    except Exception as exc:
        _store.update_job(assessment_id, status="failed", stage="upload", percent=0, error=str(exc)[:500])
        raise

    if not saved:
        _store.update_job(
            assessment_id,
            status="failed",
            stage="upload",
            percent=0,
            error="No supported files found in upload",
        )
        raise HTTPException(status_code=422, detail="No supported files found in upload")

    try:
        start_worker()
        enqueue_job(assessment_id, org, saved)
    except IngestQueueFull as exc:
        # Backpressure: the bounded queue is full. enqueue_job already marked the job
        # failed; tell the client to retry (503) rather than returning a 202 for a job
        # that was never queued.
        raise HTTPException(
            status_code=503,
            detail="Ingest queue is full — please retry in a few moments.",
        ) from exc
    except Exception as exc:
        _store.update_job(assessment_id, status="failed", stage="queued", percent=0, error=str(exc)[:500])
        raise

    return JSONResponse(
        status_code=202,
        content={
            "assessment_id": assessment_id,
            "status": "queued",
            "file_count": len(saved),
            "total_bytes": total_bytes,
            "message": f"Assessment {assessment_id} queued — {len(saved)} file(s), {total_bytes // 1024:,} KB",
        },
    )


def _safe_filename(name: str) -> str:
    """Strip path separators and other dangerous characters from a filename."""
    base = os.path.basename(name)
    return "".join(c for c in base if c.isalnum() or c in "._-")[:200] or "upload"


def _assessment_tenant(request: Request, auth: object | None) -> str:
    """Resolve the authenticated tenant for every assessment operation."""

    state_auth = getattr(request.state, "auth", None)
    effective_auth = auth if getattr(auth, "tenant_id", None) else state_auth or auth
    tenant_id = resolve_tenant_id(request, None, auth=effective_auth)
    if not tenant_id:
        tenant_id = resolve_tenant_with_default(request)
    if not tenant_id:  # defensive: the resolver normally raises first
        raise HTTPException(status_code=400, detail="tenant_id_required")
    return tenant_id


def _owned_job(store: object, assessment_id: str, tenant_id: str) -> dict:
    """Load an assessment without disclosing whether another tenant owns it."""

    job = store.get_job(assessment_id)  # type: ignore[attr-defined]
    if not isinstance(job, dict) or job.get("org") != tenant_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return job


# ── GET /progress  (SSE — critical addition #5) ───────────────────────────────


@router.get("/{assessment_id}/progress")
async def progress_sse(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    """Server-Sent Events stream for ingest progress.

    The client opens this with EventSource.  Each event is:
      event: progress
      data: {"stage":"...", "percent":N, "label":"...", "status":"..."}

    Terminal events (status "ready" or "failed") include assessment_id so
    the client can redirect.
    """
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    initial_job = await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)

    accept = request.headers.get("accept", "")
    # If client doesn't accept SSE, fall through to poll endpoint behaviour
    if "text/event-stream" not in accept:
        return JSONResponse(content=_progress_payload(initial_job))

    async def _event_stream() -> AsyncIterator[str]:
        last_percent = -1
        last_status = ""
        deadline = time.monotonic() + 600  # 10-min max SSE session
        while time.monotonic() < deadline:
            job = await asyncio.to_thread(_store.get_job, assessment_id)
            if not isinstance(job, dict) or job.get("org") != tenant_id:
                yield _sse_event({"error": "job not found", "assessment_id": assessment_id})
                return

            pct = job.get("percent") or 0
            status = job.get("status") or ""

            if pct != last_percent or status != last_status:
                payload = _progress_payload(job)
                yield _sse_event(payload)
                last_percent = pct
                last_status = status

            if status in ("ready", "failed", "cancelled"):
                yield _sse_event({**_progress_payload(job), "terminal": True})
                return

            await asyncio.sleep(1.5)

        yield _sse_event({"error": "timeout", "assessment_id": assessment_id, "terminal": True})

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
            "Connection": "keep-alive",
        },
    )


def _progress_payload(job: dict) -> dict:
    return {
        "assessment_id": job.get("assessment_id"),
        "status": job.get("status"),
        "stage": job.get("stage"),
        "percent": job.get("percent") or 0,
        "label": job.get("stage_label") or "",
        "row_count": job.get("row_count") or 0,
        "cluster_count": job.get("cluster_count") or 0,
        "error": job.get("error"),
    }


def _sse_event(data: dict, event: str = "progress") -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── GET /progress/poll  (plain JSON for non-SSE clients) ──────────────────────


@router.get("/{assessment_id}/evidence")
async def evidence_page(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    page: int = 1,
    limit: int = 500,
    case_id: str | None = None,
):
    """Paginated evidence rows for async assessments stored in DuckDB."""
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    page = max(1, int(page or 1))
    limit = max(1, min(2000, int(limit or 500)))
    offset = (page - 1) * limit
    row_indices = None
    if case_id:
        try:
            clusters = (
                _store._db()
                .execute(
                    "SELECT cluster_json FROM cluster_snapshots WHERE assessment_id = ? AND cluster_id = ?",
                    [assessment_id, case_id],
                )
                .fetchall()
            )
            if clusters:
                payload = json.loads(clusters[0][0])
                refs = payload.get("row_refs") or []
                row_indices = [int(r) for r in refs if str(r).isdigit()]
        except Exception:
            row_indices = []
        if row_indices == []:
            return JSONResponse(
                content={
                    "assessment_id": assessment_id,
                    "case_id": case_id,
                    "page": page,
                    "limit": limit,
                    "total": 0,
                    "rows": [],
                }
            )
    total = await asyncio.to_thread(_store.count_evidence_rows, assessment_id, row_indices=row_indices)
    rows = await asyncio.to_thread(
        _store.load_rows,
        assessment_id,
        limit=limit,
        offset=offset,
        row_indices=row_indices,
    )
    return JSONResponse(
        content={
            "assessment_id": assessment_id,
            "case_id": case_id,
            "page": page,
            "limit": limit,
            "total": total,
            "rows": rows,
        }
    )


def _case_view_model(assessment_id: str, tenant_id: str, job: dict, assessment: dict | None) -> dict:
    """Build the single server-owned projection used by the case workspace.

    The browser must not infer causal edges or turn narrative text into facts.
    Every section therefore carries explicit evidence references or an honest
    coverage gap.
    """
    assessment = assessment if isinstance(assessment, dict) else {}
    source_rows = assessment.get("all_rows") or assessment.get("evidence_rows") or assessment.get("rows") or []
    if not isinstance(source_rows, list):
        source_rows = []
    derivation_rows = assessment.get("_derivation_rows") or source_rows
    if not isinstance(derivation_rows, list):
        derivation_rows = source_rows
    derivation_rows = [row for row in derivation_rows if isinstance(row, dict)]
    # A selected case is hydrated by row_refs. Its preview must come from those
    # case rows, not from the assessment's first 500 rows (which may contain only
    # a handful of matching records). Keep the response cap while preserving
    # case relevance; scope_case_view_to_partition reports anything beyond it.
    preview_source = derivation_rows if "_derivation_rows" in assessment else source_rows
    rows = [row for row in preview_source[:500] if isinstance(row, dict)]
    row_count = int(job.get("row_count") or assessment.get("rows_processed") or len(rows))
    clusters = (
        assessment.get("threat_cases")
        or assessment.get("analysis_clusters")
        or assessment.get("correlation_clusters")
        or assessment.get("clusters")
        or assessment.get("cases")
        or []
    )
    if not isinstance(clusters, list):
        clusters = []

    selected = assessment.get("_selected_case_partition")
    if isinstance(selected, dict):
        # Scope before phase grouping and action generation. Filtering evidence
        # afterwards cannot remove sibling metadata merged into the same phase.
        cluster_ids = {str(value) for value in selected.get("supporting_cluster_ids") or []}
        cluster_ids.add(str(selected.get("case_id") or ""))
        clusters = [
            cluster for cluster in clusters if isinstance(cluster, dict)
            and str(cluster.get("case_id") or cluster.get("cluster_id") or cluster.get("id") or "") in cluster_ids
        ]

    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    def _row_id(row: dict, index: int) -> str:
        """Use the same canonical ID as partitions, projections, and Evidence Packs."""

        try:
            row_index = int(float(row.get("row_index", index)))
        except (TypeError, ValueError):
            row_index = index
        return evidence_id_for_row(assessment_id, row_index, normalize_semantics(dict(row)))

    evidence = []
    timeline = []
    row_index_to_evidence_id: dict[str, str] = {}
    node_ids: set[str] = set()
    nodes: list[dict] = []
    for index, row in enumerate(rows):
        evidence_id = _row_id(row, index)
        row_index_to_evidence_id[str(row.get("row_index", index))] = evidence_id
        occurred_at = row.get("event_time") or row.get("timestamp") or row.get("date_utc")
        evidence.append(
            {
                "id": evidence_id,
                "source": row.get("source") or row.get("source_type") or row.get("log_type") or "unknown",
                "occurred_at": occurred_at,
                "known_at": row.get("known_at") or assessment.get("created_at"),
                "severity": row.get("severity") or row.get("level") or "unknown",
                "summary": (
                    row.get("message")
                    or row.get("event_name")
                    or row.get("action")
                    or row.get("Operation")
                    or row.get("description")
                    or row.get("EventID")
                    or row.get("process")
                    or row.get("process_name")
                    or "Evidence row"
                ),
                "raw": row,
            }
        )
        if occurred_at:
            timeline.append(
                {
                    "id": evidence_id,
                    "occurred_at": occurred_at,
                    "label": evidence[-1]["summary"],
                    "source": evidence[-1]["source"],
                }
            )
        for kind, fields in {
            "identity": ("user", "user_canonical", "email"),
            "endpoint": ("host", "hostname", "device_name"),
            "network": ("src_ip", "dst_ip", "ip"),
            "process": ("process", "process_name", "image"),
            "domain": ("domain", "query", "dns_name"),
        }.items():
            value = next((str(row.get(field)).strip() for field in fields if row.get(field)), "")
            node_id = f"{kind}:{value}" if value else ""
            if node_id and node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({"id": node_id, "kind": kind, "label": value})

    # Only backend-produced graph edges are projected. Co-occurrence is not causality.
    graph = assessment.get("graph") if isinstance(assessment.get("graph"), dict) else {}
    authoritative_edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    from src.core.evidence_contract.correlation import validate_edges

    edges, excluded_edges = validate_edges([edge for edge in authoritative_edges if isinstance(edge, dict)])

    claims = []
    for index, cluster in enumerate(clusters[:100]):
        if not isinstance(cluster, dict):
            continue
        support = cluster.get("evidence_ids") or cluster.get("row_refs") or []
        support_ids = [row_index_to_evidence_id.get(str(value), f"row-{value}") for value in support]
        claims.append(
            {
                "id": str(cluster.get("claim_id") or cluster.get("cluster_id") or f"claim-{index}"),
                "type": str(cluster.get("assertion_type") or "inferred"),
                "title": (
                    cluster.get("incident_name")
                    or cluster.get("title")
                    or cluster.get("name")
                    or cluster.get("lead_description")
                    or cluster.get("summary")
                    or "Candidate activity"
                ),
                "confidence": cluster.get("confidence"),
                "supporting_evidence_ids": support_ids,
                "contradicting_evidence_ids": [
                    str(value) for value in (cluster.get("contradicting_evidence_ids") or [])
                ],
                "status": cluster.get("final_verdict") or cluster.get("status") or "unreviewed",
            }
        )

    missing = assessment.get("coverage_gaps") or assessment.get("missing_sources") or []
    if not isinstance(missing, list):
        missing = [str(missing)]
    if row_count == 0:
        missing = [*missing, "No telemetry evidence is available for this assessment."]
    if assessment.get("requires_reingest"):
        missing = [*missing, "Typed analysis is incomplete: canonical correlation fields are missing or clustering failed. Re-ingestion may be required."]
    completeness = min(1.0, len(evidence) / max(row_count, 1)) if row_count else 0.0
    executive_summary = assessment.get("executive_summary") or ""
    if isinstance(executive_summary, dict):
        summary_body = str(
            executive_summary.get("body")
            or executive_summary.get("summary")
            or executive_summary.get("what_happened")
            or ""
        )
    else:
        summary_body = str(executive_summary)
    if not summary_body and claims:
        summary_body = "; ".join(str(claim["title"]) for claim in claims[:3])
    cited_ids = sorted({evidence_id for claim in claims for evidence_id in claim["supporting_evidence_ids"]})[:100]
    claim_statuses = {str(claim.get("status") or "").upper() for claim in claims}
    derived_breach_status = (
        "confirmed"
        if claim_statuses & {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"}
        else "suspected"
        if any("SUSPECTED" in status or "LIKELY" in status for status in claim_statuses)
        else "undetermined"
    )
    scored_confidences = [
        float(claim["confidence"]) for claim in claims if isinstance(claim.get("confidence"), (int, float))
    ]
    base = {
        "schema_version": "janusec.case-evidence-view/v1",
        "case": {
            "id": assessment_id,
            "tenant_id": tenant_id,
            "status": job.get("status") or "unknown",
            "stage": job.get("stage") or "unknown",
            "percent": int(job.get("percent") or 0),
            "created_at": assessment.get("created_at") or job.get("created_at"),
            "updated_at": job.get("updated_at"),
        },
        "posture": {
            "breach_status": assessment.get("verdict") or assessment.get("breach_status") or derived_breach_status,
            "evidence_confidence": (
                assessment.get("confidence") or (max(scored_confidences) if scored_confidences else None)
            ),
            "evidence_completeness": round(completeness, 4),
            "exposure": assessment.get("exposure") or "not_assessed",
            "impact": assessment.get("impact") or "not_assessed",
            "urgency": assessment.get("urgency") or "review_required",
        },
        "breach_summary": {
            "headline": (
                assessment.get("incident_name")
                or assessment.get("headline")
                or (claims[0]["title"] if claims else "What happened is not yet established")
            ),
            "what_happened": summary_body,
            "supporting_evidence_ids": cited_ids,
            "coverage_gaps": missing,
            "status": "supported" if summary_body and cited_ids and "ANALYSIS_INCOMPLETE" not in claim_statuses and not assessment.get("requires_reingest") else "provisional",
            "generated_by": "assessment_pipeline",
        },
        "claims": claims,
        "evidence": {
            "rows": evidence,
            "returned": len(evidence),
            "total": row_count,
            "truncated": row_count > len(evidence),
        },
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "excluded_edges": excluded_edges,
            "edge_policy": "typed_backend_edges_only",
        },
        "timeline": sorted(timeline, key=lambda item: str(item.get("occurred_at") or "")),
        "retrieval_trace": assessment.get("retrieval_trace") or [],
        "coverage_gaps": missing,
        "analyst": {
            "decisions": assessment.get("analyst_decisions") or [],
            "approved_actions": assessment.get("approved_actions") or [],
        },
        "execution": {
            "dag": assessment.get("assessment_dag"),
            "receipts": assessment.get("stage_receipts") or [],
            "legacy_stage": job.get("stage"),
        },
    }
    from src.api.case_view_v2 import build_case_view_v2

    selected = assessment.get("_selected_case_partition")
    if isinstance(selected, dict):
        base["case"].update(id=selected["case_id"], assessment_id=assessment_id)
    return build_case_view_v2(base, assessment, derivation_rows, [cluster for cluster in clusters if isinstance(cluster, dict)])


@router.get("/{assessment_id}/case-view")
async def case_view(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    case_id: str | None = None,
    as_known_at: str | None = None,
):
    """Return the authoritative synchronized projection for the case UI."""
    from src.api.deep_analyze.persistence import _get_assessment_cached
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    job = await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    if as_known_at:
        from src.repositories.case_history_repo import restore_view
        from src.api.models.case_evidence import CaseEvidenceViewModelV2
        try:
            historical = await asyncio.to_thread(
                restore_view, tenant_id, assessment_id, case_id or assessment_id, as_known_at,
            )
        except ValueError as exc:
            raise HTTPException(400 if str(exc) == "invalid_as_known_at" else 409, str(exc)) from exc
        if historical is not None:
            return JSONResponse(content=CaseEvidenceViewModelV2.model_validate(historical).model_dump(mode="json"))
    assessment = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    if isinstance(assessment, dict) and any(
        str(assessment[key]).strip() != tenant_id
        for key in ("org", "tenant_id") if assessment.get(key)
    ):
        raise HTTPException(status_code=404, detail="Assessment not found")
    partitions: list[dict] = []
    selected_partition: dict | None = None
    assessment_for_view = assessment
    if case_id:
        partitions = await _case_partitions(assessment_id, tenant_id, assessment or {})
        selected_partition = next((item for item in partitions if str(item.get("case_id") or "") == case_id), None)
        if selected_partition is None or selected_partition.get("status") == "background":
            raise HTTPException(status_code=404, detail="Case partition not found")
        derivation_rows = await asyncio.to_thread(
            _store.load_rows, assessment_id, min_triage=0.0, limit=250000,
            row_indices=[int(value) for value in selected_partition.get("row_refs") or []],
        )
        assessment_for_view = {
            **dict(assessment or {}),
            "_derivation_rows": list(derivation_rows or []),
            "_selected_case_partition": dict(selected_partition),
        }
    model = _case_view_model(assessment_id, tenant_id, job, assessment_for_view)
    graph_projections_by_case = (
        dict(assessment.get("graph_projections_by_case") or {}) if isinstance(assessment, dict) else {}
    )
    if case_id:
        model["_graph_projections_by_case"] = graph_projections_by_case
        model["_evidence_pack_receipts_by_case"] = (
            assessment.get("evidence_pack_receipts_by_case")
            if isinstance(assessment, dict)
            and isinstance(assessment.get("evidence_pack_receipts_by_case"), dict)
            else {}
        )
        from src.api.case_view_v2 import scope_case_view_to_partition

        model = scope_case_view_to_partition(model, selected_partition)
        case_summary = (assessment.get("executive_summaries_by_case") or {}).get(case_id)
        if isinstance(case_summary, dict) and case_summary.get("executive_summary"):
            model["breach_summary"]["what_happened"] = str(case_summary["executive_summary"])
    try:
        from src.core.acceptance_truth import (
            evaluate_assessment_truth, infer_truth_scenario, load_truth_fixture,
        )

        truth_scenario = infer_truth_scenario(assessment or {})
        if truth_scenario:
            truth_fixture, truth_receipt = load_truth_fixture(
                truth_scenario, caller_requested=False,
            )
            truth_partitions = partitions or await _case_partitions(
                assessment_id, tenant_id, assessment or {},
            )
            model.setdefault("report_context", {})["acceptance_truth"] = {
                "scenario": truth_scenario,
                "receipt": truth_receipt,
                "evaluation": evaluate_assessment_truth(truth_partitions, truth_fixture),
            }
    except Exception:
        logger.exception("acceptance truth attachment failed for %s", assessment_id)
    try:
        from src.repositories.evidence_ledger_repo import list_case

        ledger_records = await list_case(tenant_id, assessment_id)
        model["execution"]["evidence_kernel"] = {
            "status": "available" if ledger_records else "unrecorded",
            "record_count": len(ledger_records),
            "record_types": sorted({record.get("record_type") for record in ledger_records}),
        }
        if not ledger_records:
            model["coverage_gaps"].append(
                "This assessment predates evidence-ledger capture; custody lineage is unrecorded."
            )
        ledger_dag = next(
            (record for record in ledger_records if record.get("record_type") == "assessment_dag"),
            None,
        )
        receipts = [record for record in ledger_records if record.get("record_type") == "artifact_receipt"]
        if ledger_dag:
            model["execution"]["dag"] = ledger_dag
        if receipts:
            model["execution"]["receipts"] = receipts

        from src.core.evidence_contract.graph_projection import (
            MAPPING_VERSION,
            NORMALIZER_VERSION,
            GraphProjectionReceipt,
            configured_sensor_slas,
            eligible_ledger_head,
            projection_staleness,
        )
        from src.repositories.graph_projection_repo import load_projection
        from src.core.evidence_contract.records import canonical_hash
        from src.core.evidence_contract.projection_builder import infrastructure_receipt_hash

        projection = graph_projections_by_case.get(case_id) if case_id else assessment.get("graph_projection")
        projection = projection if isinstance(projection, dict) else {}
        receipt_raw = projection.get("receipt") if isinstance(projection.get("receipt"), dict) else None
        rebuild_needed = False
        if receipt_raw:
            receipt = GraphProjectionReceipt.from_dict(receipt_raw)
            reasons = projection_staleness(
                receipt,
                current_ledger_head_hash=eligible_ledger_head(ledger_records),
                normalizer_version=NORMALIZER_VERSION,
                mapping_version=MAPPING_VERSION,
                sensor_max_age_seconds=configured_sensor_slas(),
                clock_calibration_hash=canonical_hash(assessment.get("clock_calibration") or {}),
                iam_receipt_hash=infrastructure_receipt_hash(assessment.get("authorization_snapshot")),
                topology_receipt_hash=infrastructure_receipt_hash(assessment.get("topology_snapshot")),
                cmdb_receipt_hash=infrastructure_receipt_hash(assessment.get("cmdb_mapping_receipt")),
            )
            status = "stale" if reasons else "current"
            model["report_context"].update({
                "graph_projection_id": receipt.projection_id,
                "graph_receipt_hash": receipt.content_hash,
                "graph_ledger_head_hash": receipt.ledger_head_hash,
                "graph_clock_calibration_hash": receipt.clock_calibration_hash,
                "graph_projection_status": status,
                "graph_staleness_reasons": [reason.value for reason in reasons],
            })
            try:
                stored_graph = await load_projection(tenant_id, receipt.case_id, receipt.projection_id)
                model["graph"] = {
                    "nodes": stored_graph["nodes"],
                    "edges": stored_graph["edges"],
                    "excluded_edges": [],
                    "edge_policy": "typed_backend_edges_only",
                }
            except Exception as graph_exc:
                status = "unavailable"
                model["report_context"]["graph_projection_status"] = status
                model["coverage_gaps"].append(f"Typed graph projection is unavailable: {type(graph_exc).__name__}.")
            if reasons:
                model["coverage_gaps"].append(
                    "The typed graph projection is stale and is being rebuilt; causal narration must be treated as provisional."
                )
                rebuild_needed = True
        else:
            model["report_context"]["graph_projection_status"] = "unrecorded"
            model["coverage_gaps"].append("No authoritative typed graph projection receipt exists for this assessment.")
            rebuild_needed = True

        rebuild_key = f"{tenant_id}:{assessment_id}"
        if rebuild_needed and rebuild_key not in _GRAPH_REBUILD_TASKS and isinstance(assessment, dict):
            _GRAPH_REBUILD_TASKS.add(rebuild_key)

            async def _rebuild_graph_projection() -> None:
                try:
                    from src.core.evidence_contract.projection_builder import (
                        evidence_id_for_row, infrastructure_receipt_hash, infrastructure_valid_to,
                        persist_assessment_projection,
                    )
                    from src.core.evidence_contract.semantic_adapters import normalize_semantics
                    from src.core.ingest.assessment_worker import _persist_assessment_json

                    rebuild_rows = await asyncio.to_thread(
                        _store.load_all_rows,
                        assessment_id,
                    )
                    row_evidence_ids = [
                        evidence_id_for_row(assessment_id, index, normalize_semantics(dict(row)))
                        if isinstance(row, dict) else None
                        for index, row in enumerate(rebuild_rows)
                    ]
                    partitions = await _case_partitions(assessment_id, tenant_id, assessment)
                    rebuilt_by_case: dict[str, dict] = {}
                    for partition in partitions:
                        if not isinstance(partition, dict) or partition.get("status") == "background":
                            continue
                        case_id = str(partition.get("case_id") or "")
                        allowed_ids = {str(value) for value in partition.get("evidence_ids") or []}
                        case_rows = [
                            row for row, evidence_id in zip(rebuild_rows, row_evidence_ids)
                            if evidence_id in allowed_ids
                        ]
                        if not case_id or not case_rows:
                            continue
                        rebuilt_by_case[case_id] = await persist_assessment_projection(
                            tenant_id=tenant_id,
                            case_id=case_id,
                            rows=case_rows,
                            topology_valid_to=infrastructure_valid_to(assessment.get("topology_snapshot")),
                            clock_calibration=assessment.get("clock_calibration") or {},
                            evidence_namespace=assessment_id,
                            iam_receipt_hash=infrastructure_receipt_hash(assessment.get("authorization_snapshot")),
                            topology_receipt_hash=infrastructure_receipt_hash(assessment.get("topology_snapshot")),
                            cmdb_receipt_hash=infrastructure_receipt_hash(assessment.get("cmdb_mapping_receipt")),
                        )
                    updated = dict(assessment)
                    updated["case_partitions"] = partitions
                    updated["graph_projections_by_case"] = rebuilt_by_case
                    lead_case_id = str(updated.get("kill_chain_case_id") or "")
                    updated["graph_projection"] = (
                        rebuilt_by_case.get(lead_case_id)
                        or next(iter(rebuilt_by_case.values()), {
                            "status": "unavailable",
                            "reason": "no_case_projection",
                        })
                    )
                    await asyncio.to_thread(_persist_assessment_json, assessment_id, tenant_id, updated)
                except Exception as exc:
                    logger.exception("asynchronous typed graph rebuild failed for %s: %s", assessment_id, exc)
                finally:
                    _GRAPH_REBUILD_TASKS.discard(rebuild_key)

            asyncio.create_task(_rebuild_graph_projection())
            model["report_context"]["graph_projection_status"] = "rebuilding"
    except Exception:
        model["execution"]["evidence_kernel"] = {
            "status": "unavailable",
            "record_count": 0,
        }
        model["coverage_gaps"].append("Evidence ledger is unavailable; custody lineage cannot be verified.")
    # Ledger checks happen after the base v2 projection is assembled. Mirror the
    # final authoritative gap set into the executive summary before validation.
    model.pop("_graph_projections_by_case", None)
    model["breach_summary"]["coverage_gaps"] = list(model["coverage_gaps"])
    from src.api.models.case_evidence import CaseEvidenceViewModelV2

    from src.api.case_scope import scope_to_knowledge_time
    model = scope_to_knowledge_time(model, as_known_at)
    validated = CaseEvidenceViewModelV2.model_validate(model)
    result = validated.model_dump(mode="json")
    if not as_known_at:
        from src.repositories.case_history_repo import record_view
        try:
            receipt = await asyncio.to_thread(record_view, tenant_id, assessment_id, result)
            result["report_context"]["historical_receipt"] = receipt
        except Exception:
            logger.exception("Case history capture failed for %s", assessment_id)
            result["coverage_gaps"].append("This view could not be archived for historical reconstruction.")
            result["breach_summary"]["coverage_gaps"] = list(result["coverage_gaps"])
    return JSONResponse(content=result)


async def _case_partitions(assessment_id: str, tenant_id: str, assessment: dict) -> list[dict]:
    from src.core.evidence_contract.case_partition import CasePartition, build_case_partitions
    from src.core.evidence_contract.graph_projection import MAPPING_VERSION, NORMALIZER_VERSION
    from src.core.ingest import store as _store

    existing = assessment.get("case_partitions")
    if isinstance(existing, list) and existing and all(
        isinstance(item, dict)
        and item.get("schema_version") == CasePartition.schema_version
        and item.get("normalizer_version") == NORMALIZER_VERSION
        and item.get("mapping_version") == MAPPING_VERSION
        for item in existing
    ):
        return [item for item in existing if isinstance(item, dict)]
    rows = await asyncio.to_thread(_store.load_rows, assessment_id, min_triage=0.0, limit=250000)
    return build_case_partitions(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        threat_cases=list(assessment.get("threat_cases") or []),
        analysis_clusters=list(assessment.get("analysis_clusters") or []),
        rows=list(rows or []),
    )


@router.get("/{assessment_id}/cases")
async def list_assessment_cases(
    assessment_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    as_known_at: str | None = None,
):
    from src.api.deep_analyze.persistence import _get_assessment_cached
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    if as_known_at:
        from src.repositories.case_history_repo import list_recorded_cases
        try:
            historical = await asyncio.to_thread(list_recorded_cases, tenant_id, assessment_id, as_known_at)
        except ValueError as exc:
            raise HTTPException(400 if str(exc) == "invalid_as_known_at" else 409, str(exc)) from exc
        return {"assessment_id": assessment_id, "selected_case_id": None, "cases": historical,
                "count": len(historical), "as_known_at": as_known_at}
    assessment = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    assessment = assessment if isinstance(assessment, dict) else {}
    partitions = await _case_partitions(assessment_id, tenant_id, assessment)
    return {
        "assessment_id": assessment_id,
        "selected_case_id": assessment.get("kill_chain_case_id"),
        "cases": partitions,
        "count": len(partitions),
    }


@router.get("/{assessment_id}/cases/{case_id}")
async def get_assessment_case(
    assessment_id: str, case_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    as_known_at: str | None = None,
):
    payload = await list_assessment_cases(assessment_id, request, auth, as_known_at=as_known_at)
    partition = next((item for item in payload["cases"] if str(item.get("case_id")) == case_id), None)
    if partition is None:
        raise HTTPException(status_code=404, detail="Case partition not found")
    return partition


async def _compile_case_evidence_pack(
    *, assessment_id: str, tenant_id: str, body: dict, requested_case_id: str | None = None,
) -> dict:
    """Compile one immutable pack for one case partition and one question."""
    from src.core.evidence_contract.retrieval import compile_evidence_pack
    from src.core.ingest import store as _store
    from src.repositories.evidence_ledger_repo import append, list_case

    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    records = await list_case(tenant_id, assessment_id)
    from src.api.deep_analyze.persistence import _get_assessment_cached
    from src.core.evidence_contract.contradiction_policies import DEFAULT_CONTRADICTION_POLICIES
    from src.core.evidence_contract.retrieval_adapters import TemporalRAGContextAdapter, TemporalRAGDenseEvidenceAdapter
    from src.repositories.graph_projection_repo import load_projection

    assessment = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    assessment = assessment if isinstance(assessment, dict) else {}
    partitions = await _case_partitions(assessment_id, tenant_id, assessment)
    selected_case_id = str(requested_case_id or body.get("case_id") or assessment_id)
    partition = next((item for item in partitions if str(item.get("case_id")) == selected_case_id), None)
    if selected_case_id != assessment_id and partition is None:
        raise HTTPException(status_code=404, detail="Case partition not found")
    # The ledger stores custody/manifests; the normalized evidence projection is
    # content-addressed here and bound to those receipts. This avoids one ledger
    # row per event while giving CorrectiveRAG the actual local case evidence.
    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.records import canonical_hash
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    normalized_rows = await asyncio.to_thread(_store.load_all_rows, assessment_id)
    for fallback_index, original in enumerate(normalized_rows):
        if not isinstance(original, dict):
            continue
        normalized = normalize_semantics(dict(original))
        # ``load_all_rows`` is not contractually ordered by ingestion position.
        # Reuse the persisted row index so an Evidence Pack cites the same
        # content-addressed record as the authoritative graph projection.
        try:
            row_index = int(original.get("row_index"))
        except (TypeError, ValueError):
            row_index = fallback_index
        evidence_id = evidence_id_for_row(assessment_id, row_index, normalized)
        content_hash = canonical_hash(normalized)
        records.append({
            **normalized,
            "record_type": "normalized_evidence_projection",
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            # Keep the assessment-scoped stable evidence ID used by the graph,
            # while assigning case membership through the immutable partition.
            "case_id": selected_case_id,
            "content_hash": content_hash,
        })
    projections_by_case = (
        assessment.get("graph_projections_by_case")
        if isinstance(assessment.get("graph_projections_by_case"), dict)
        else {}
    )
    projection = projections_by_case.get(selected_case_id)
    if not isinstance(projection, dict):
        # Compatibility for assessments created before per-case projections.
        projection = assessment.get("graph_projection") if isinstance(assessment.get("graph_projection"), dict) else {}
    projection_receipt = projection.get("receipt") if isinstance(projection.get("receipt"), dict) else None
    typed_edges: list[dict] = []
    if projection_receipt and projection_receipt.get("projection_id"):
        try:
            stored_graph = await load_projection(tenant_id, selected_case_id, str(projection_receipt["projection_id"]))
            typed_edges = stored_graph.get("edges") or []
        except Exception:
            logger.exception("evidence pack could not load typed projection for %s", assessment_id)
    pack = await asyncio.to_thread(
        compile_evidence_pack,
        tenant_id=tenant_id,
        case_id=selected_case_id,
        query=str(body.get("query") or ""),
        identifiers=[str(value) for value in body.get("identifiers") or []],
        records=records,
        edges=typed_edges,
        as_known_at=body.get("as_known_at"),
        max_hops=int(body.get("max_hops") or 2),
        limit=int(body.get("limit") or 200),
        dense_retriever=TemporalRAGDenseEvidenceAdapter(
            tenant_id=tenant_id, assessment_id=assessment_id, case_id=selected_case_id,
        ),
        temporal_prior_retriever=TemporalRAGContextAdapter(scope="tenant_history"),
        contradiction_policies=DEFAULT_CONTRADICTION_POLICIES,
        clock_skew_calibration=assessment.get("clock_skew_calibration") if isinstance(assessment.get("clock_skew_calibration"), dict) else {},
        ppr_candidates=[item for item in body.get("ppr_candidates") or [] if isinstance(item, dict)],
        projection_receipt=projection_receipt,
        cmdb_mapping_receipt=assessment.get("cmdb_mapping_receipt") if isinstance(assessment.get("cmdb_mapping_receipt"), dict) else None,
        required_sensors=[str(value) for value in body.get("required_sensors") or []],
        case_partition=partition,
        episodes=list((partition or {}).get("episodes") or []),
        topology_snapshot=assessment.get("topology_snapshot") if isinstance(assessment.get("topology_snapshot"), dict) else None,
        authorization_snapshot=assessment.get("authorization_snapshot") if isinstance(assessment.get("authorization_snapshot"), dict) else None,
        assessment_id=assessment_id,
        # Acceptance labels are caller-supplied test artifacts. They are never
        # inferred from telemetry or fixture-only semantic selectors.
        expected_evidence_ids=[
            str(value) for value in body.get("expected_evidence_ids") or [] if value
        ],
    )
    await append(pack.to_dict())
    try:
        from src.api.deep_analyze.persistence import _persist_assessment_state
        from src.core.ingest.assessment_worker import _persist_assessment_json

        assessment["evidence_pack_hash"] = pack.content_hash
        assessment["evidence_pack_id"] = pack.pack_id
        assessment["evidence_pack_projection_id"] = pack.graph_projection_id
        receipts = [item for item in assessment.get("evidence_pack_receipts") or [] if isinstance(item, dict)]
        receipt = {
            "pack_id": pack.pack_id,
            "content_hash": pack.content_hash,
            "case_id": pack.case_id,
            "question_id": pack.question_id,
            "graph_projection_id": pack.graph_projection_id,
            "graph_receipt_hash": pack.graph_receipt_hash,
            "ledger_head_hash": pack.ledger_head_hash,
            "corrective_outcome": pack.corrective_acceptance.get("outcome"),
            "added_evidence_count": len(pack.corrective_acceptance.get("added_evidence_ids") or []),
            "changed_evidence_set": bool(pack.corrective_acceptance.get("changed_evidence_set")),
            "truth_set_attached": bool(pack.corrective_acceptance.get("truth_set_attached")),
            "corrective_accepted": bool(pack.corrective_acceptance.get("accepted")),
            "initial_evidence_recall": pack.corrective_acceptance.get("initial_evidence_recall"),
            "corrected_evidence_recall": pack.corrective_acceptance.get("corrected_evidence_recall"),
        }
        if not any(item.get("content_hash") == pack.content_hash for item in receipts):
            receipts.append(receipt)
        assessment["evidence_pack_receipts"] = receipts
        receipts_by_case = (
            dict(assessment.get("evidence_pack_receipts_by_case") or {})
            if isinstance(assessment.get("evidence_pack_receipts_by_case"), dict)
            else {}
        )
        case_receipts = [
            item for item in receipts_by_case.get(pack.case_id) or []
            if isinstance(item, dict)
        ]
        if not any(item.get("content_hash") == pack.content_hash for item in case_receipts):
            case_receipts.append(receipt)
        receipts_by_case[pack.case_id] = case_receipts
        assessment["evidence_pack_receipts_by_case"] = receipts_by_case
        await asyncio.to_thread(_persist_assessment_json, assessment_id, tenant_id, assessment)
        # Keep the authoritative in-process cache in lockstep with disk. This
        # is deliberately explicit: case-view requests may arrive before the
        # filesystem fallback is consulted.
        await asyncio.to_thread(_persist_assessment_state, assessment_id, assessment)
    except Exception:
        logger.exception("failed to attach evidence-pack receipt to assessment %s", assessment_id)
    return pack.to_dict()


@router.post("/{assessment_id}/evidence-pack")
async def create_evidence_pack(
    assessment_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    tenant_id = _assessment_tenant(request, auth)
    body = await request.json()
    return JSONResponse(content=await _compile_case_evidence_pack(
        assessment_id=assessment_id, tenant_id=tenant_id, body=body,
    ))


@router.post("/{assessment_id}/cases/{case_id}/evidence-pack")
async def create_case_evidence_pack(
    assessment_id: str, case_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    tenant_id = _assessment_tenant(request, auth)
    body = await request.json()
    return JSONResponse(content=await _compile_case_evidence_pack(
        assessment_id=assessment_id, tenant_id=tenant_id, body=body, requested_case_id=case_id,
    ))


@router.post("/{assessment_id}/agent-sessions")
async def create_agent_session(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    """Create an append-only, provider-neutral investigation session."""
    from src.core.agent_harness import SessionLog
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    body = await request.json()
    session_id = f"session-{uuid.uuid4().hex[:16]}"
    event = SessionLog().append(
        tenant_id=tenant_id,
        case_id=assessment_id,
        session_id=session_id,
        event_type="session_started",
        payload={"provider": body.get("provider"), "model": body.get("model")},
    )
    return JSONResponse(content={"session_id": session_id, "event": event.to_dict()}, status_code=201)


@router.get("/{assessment_id}/agent-sessions/{session_id}")
async def read_agent_session(
    assessment_id: str,
    session_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    from src.core.agent_harness import SessionLog
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    events = SessionLog().read(tenant_id, session_id)
    if events and any(event.get("case_id") != assessment_id for event in events):
        raise HTTPException(status_code=404, detail="Session not found")
    return JSONResponse(content={"session_id": session_id, "events": events})


@router.post("/{assessment_id}/agent-sessions/{session_id}/events")
async def append_agent_session_event(
    assessment_id: str,
    session_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    from src.core.agent_harness import SessionLog
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    body = await request.json()
    event_type = str(body.get("event_type") or "")
    allowed = {"prompt", "model_output", "tool_requested", "tool_result", "analyst_decision", "replay_marker"}
    if event_type not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported session event type")
    event = SessionLog().append(
        tenant_id=tenant_id,
        case_id=assessment_id,
        session_id=session_id,
        event_type=event_type,
        payload=body.get("payload") if isinstance(body.get("payload"), dict) else {},
    )
    return JSONResponse(content=event.to_dict(), status_code=201)


@router.post("/{assessment_id}/agent-sessions/{session_id}/fork")
async def fork_agent_session(
    assessment_id: str,
    session_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    from src.core.agent_harness import SessionLog
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    body = await request.json()
    child = SessionLog().fork(
        tenant_id=tenant_id,
        case_id=assessment_id,
        session_id=session_id,
        at_sequence=int(body.get("at_sequence", 0)),
    )
    return JSONResponse(content={"session_id": child, "parent_session_id": session_id}, status_code=201)


@router.get("/{assessment_id}/progress/poll")
async def progress_poll(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    """Plain JSON progress snapshot — for non-EventSource clients or debugging."""
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    job = await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    return JSONResponse(content=_progress_payload(job))


# ── POST /cancel ──────────────────────────────────────────────────────────────


@router.post("/{assessment_id}/cancel")
async def cancel_assessment(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
):
    """Mark a queued or running assessment as cancelled."""
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    job = await asyncio.to_thread(_owned_job, _store, assessment_id, tenant_id)
    if job.get("status") in ("ready", "failed", "cancelled"):
        return JSONResponse(
            content={
                "assessment_id": assessment_id,
                "status": job["status"],
                "message": "Already terminal",
            }
        )
    await asyncio.to_thread(
        _store.update_job,
        assessment_id,
        status="cancelled",
        stage_label="Cancelled by user",
    )
    return JSONResponse(content={"assessment_id": assessment_id, "status": "cancelled"})


# ── GET /  (list recent jobs — convenience for debugging) ─────────────────────


@router.get("/")
async def list_assessments(
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    limit: int = 20,
):
    """List recent assessment jobs from DuckDB."""
    from src.core.ingest import store as _store

    tenant_id = _assessment_tenant(request, auth)
    limit = max(1, min(200, int(limit or 20)))
    try:
        with _store._lock:
            rows = (
                _store._db()
                .execute(
                    "SELECT id, org, status, stage, percent, row_count, cluster_count, created_at "
                    "FROM assessment_jobs WHERE org = ? ORDER BY created_at DESC LIMIT ?",
                    [tenant_id, limit],
                )
                .fetchall()
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return JSONResponse(
        content={
            "jobs": [
                {
                    "assessment_id": r[0],
                    "org": r[1],
                    "status": r[2],
                    "stage": r[3],
                    "percent": r[4],
                    "row_count": r[5],
                    "cluster_count": r[6],
                    "created_at": r[7],
                }
                for r in rows
            ]
        }
    )
