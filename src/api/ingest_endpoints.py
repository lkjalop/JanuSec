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
import time
import uuid
from typing import AsyncIterator

from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assessments", tags=["ingest"])

_MAX_UPLOAD_BYTES = int(os.getenv("JANUSEC_MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))  # 500 MB
_MAX_FILES = int(os.getenv("JANUSEC_MAX_FILES", "20"))
_ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson", ".xlsx", ".xlsm"}


# ── POST /upload ──────────────────────────────────────────────────────────────

@router.post("/upload", status_code=202)
async def upload_assessment(request: Request):
    """Accept multipart file upload; queue background ingest job.

    Returns: {assessment_id, status: "queued", file_count, message}
    """
    from src.core.ingest import store as _store
    from src.core.ingest.assessment_worker import enqueue_job, start_worker

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

    # Derive org from auth context if available, else default
    org = "unknown"
    try:
        from src.security.auth import AuthContext
        ctx = getattr(request.state, "auth", None)
        if isinstance(ctx, AuthContext):
            org = ctx.org or "unknown"
    except Exception:
        pass
    # Allow explicit org in form field for API clients
    form_org = form.get("org")
    if form_org:
        org = str(form_org)[:64]

    assessment_id = f"assessment-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    raw_dir = _store.raw_dir_for(assessment_id)
    _store.create_job(assessment_id, org=org)

    saved: list[tuple[str, str]] = []
    total_bytes = 0
    try:
        for f in files:
            if not hasattr(f, "filename"):
                continue
            ext = os.path.splitext(str(f.filename))[1].lower()
            if ext not in _ALLOWED_EXTENSIONS:
                logger.warning("ingest upload: skipping unsupported file type %s", f.filename)
                continue
            dest = os.path.join(raw_dir, _safe_filename(str(f.filename)))
            content = await f.read()
            total_bytes += len(content)
            if total_bytes > _MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail=f"Upload exceeds limit ({_MAX_UPLOAD_BYTES // 1024 // 1024} MB)")
            with open(dest, "wb") as fh:
                fh.write(content)
            saved.append((dest, str(f.filename)))
            try:
                _store.register_file(assessment_id, str(f.filename), dest, len(content))
            except Exception:
                logger.debug("ingest upload: raw file registration failed for %s", f.filename, exc_info=True)
    except HTTPException as exc:
        _store.update_job(assessment_id, status="failed", stage="upload", percent=0, error=str(exc.detail))
        raise
    except Exception as exc:
        _store.update_job(assessment_id, status="failed", stage="upload", percent=0, error=str(exc)[:500])
        raise

    if not saved:
        _store.update_job(assessment_id, status="failed", stage="upload", percent=0, error="No supported files found in upload")
        raise HTTPException(status_code=422, detail="No supported files found in upload")

    try:
        start_worker()
        enqueue_job(assessment_id, org, saved)
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


def _valid_api_key(value: str | None) -> bool:
    if os.getenv("JANUSEC_DEV_MODE") or os.getenv("TEST_HELPERS_ENABLED"):
        return True
    key = (value or "").strip()
    if not key:
        return False
    try:
        configured = json.loads(os.getenv("API_KEYS_JSON", "[]") or "[]")
        for item in configured:
            if isinstance(item, dict) and item.get("key") == key:
                return True
    except Exception:
        pass
    expected = os.getenv("JANUSEC_API_KEY") or os.getenv("API_KEY") or "devkey123"
    return key == expected


def _validate_progress_auth(request: Request) -> None:
    token = (
        request.query_params.get("token")
        or request.query_params.get("api_key")
        or request.headers.get("x-api-key")
        or request.headers.get("X-API-Key")
    )
    if not _valid_api_key(token):
        raise HTTPException(status_code=401, detail="Invalid API key")


# ── GET /progress  (SSE — critical addition #5) ───────────────────────────────

@router.get("/{assessment_id}/progress")
async def progress_sse(assessment_id: str, request: Request):
    """Server-Sent Events stream for ingest progress.

    The client opens this with EventSource.  Each event is:
      event: progress
      data: {"stage":"...", "percent":N, "label":"...", "status":"..."}

    Terminal events (status "ready" or "failed") include assessment_id so
    the client can redirect.
    """
    from src.core.ingest import store as _store
    _validate_progress_auth(request)

    accept = request.headers.get("accept", "")
    # If client doesn't accept SSE, fall through to poll endpoint behaviour
    if "text/event-stream" not in accept:
        job = _store.get_job(assessment_id)
        if not job:
            raise HTTPException(status_code=404, detail="Assessment not found")
        return JSONResponse(content=_progress_payload(job))

    async def _event_stream() -> AsyncIterator[str]:
        last_percent = -1
        last_status = ""
        deadline = time.monotonic() + 600  # 10-min max SSE session
        while time.monotonic() < deadline:
            job = await asyncio.to_thread(_store.get_job, assessment_id)
            if not job:
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
            "X-Accel-Buffering": "no",     # disable nginx buffering
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
    page: int = 1,
    limit: int = 500,
    case_id: str | None = None,
):
    """Paginated evidence rows for async assessments stored in DuckDB."""
    from src.core.ingest import store as _store
    _validate_progress_auth(request)
    page = max(1, int(page or 1))
    limit = max(1, min(2000, int(limit or 500)))
    offset = (page - 1) * limit
    row_indices = None
    if case_id:
        try:
            clusters = _store._db().execute(
                "SELECT cluster_json FROM cluster_snapshots WHERE assessment_id = ? AND cluster_id = ?",
                [assessment_id, case_id],
            ).fetchall()
            if clusters:
                payload = json.loads(clusters[0][0])
                refs = payload.get("row_refs") or []
                row_indices = [int(r) for r in refs if str(r).isdigit()]
        except Exception:
            row_indices = []
        if row_indices == []:
            return JSONResponse(content={
                "assessment_id": assessment_id,
                "case_id": case_id,
                "page": page,
                "limit": limit,
                "total": 0,
                "rows": [],
            })
    total = await asyncio.to_thread(_store.count_evidence_rows, assessment_id, row_indices=row_indices)
    rows = await asyncio.to_thread(
        _store.load_rows,
        assessment_id,
        limit=limit,
        offset=offset,
        row_indices=row_indices,
    )
    return JSONResponse(content={
        "assessment_id": assessment_id,
        "case_id": case_id,
        "page": page,
        "limit": limit,
        "total": total,
        "rows": rows,
    })


@router.get("/{assessment_id}/progress/poll")
async def progress_poll(assessment_id: str, request: Request):
    """Plain JSON progress snapshot — for non-EventSource clients or debugging."""
    from src.core.ingest import store as _store
    _validate_progress_auth(request)
    job = await asyncio.to_thread(_store.get_job, assessment_id)
    if not job:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return JSONResponse(content=_progress_payload(job))


# ── POST /cancel ──────────────────────────────────────────────────────────────

@router.post("/{assessment_id}/cancel")
async def cancel_assessment(assessment_id: str):
    """Mark a queued or running assessment as cancelled."""
    from src.core.ingest import store as _store
    job = await asyncio.to_thread(_store.get_job, assessment_id)
    if not job:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if job.get("status") in ("ready", "failed", "cancelled"):
        return JSONResponse(content={"assessment_id": assessment_id, "status": job["status"], "message": "Already terminal"})
    await asyncio.to_thread(
        _store.update_job,
        assessment_id,
        status="cancelled",
        stage_label="Cancelled by user",
    )
    return JSONResponse(content={"assessment_id": assessment_id, "status": "cancelled"})


# ── GET /  (list recent jobs — convenience for debugging) ─────────────────────

@router.get("/")
async def list_assessments(limit: int = 20):
    """List recent assessment jobs from DuckDB."""
    from src.core.ingest import store as _store
    try:
        with _store._lock:
            rows = _store._db().execute(
                "SELECT id, org, status, stage, percent, row_count, cluster_count, created_at "
                "FROM assessment_jobs ORDER BY created_at DESC LIMIT ?",
                [limit],
            ).fetchall()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return JSONResponse(content={
        "jobs": [
            {
                "assessment_id": r[0], "org": r[1], "status": r[2],
                "stage": r[3], "percent": r[4], "row_count": r[5],
                "cluster_count": r[6], "created_at": r[7],
            }
            for r in rows
        ]
    })
