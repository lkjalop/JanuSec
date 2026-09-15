"""
routes/investigations.py — Investigation session management endpoints.

GET  /api/v1/investigations/                    — list sessions for a tenant
GET  /api/v1/investigations/{session_id}        — get session detail + event log
POST /api/v1/investigations/{session_id}/resume — resume interrupted investigation
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


def _get_tenant(request: Request) -> str:
    return (
        request.headers.get("X-Tenant-ID")
        or request.headers.get("x-tenant-id")
        or "default"
    )


@router.get("", summary="List investigation sessions for a tenant")
async def list_sessions(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
):
    tenant_id = _get_tenant(request)
    try:
        from src.core.ingest.store import list_investigation_sessions
        sessions = list_investigation_sessions(tenant_id, limit=limit)
        return {"sessions": sessions, "count": len(sessions), "tenant_id": tenant_id}
    except Exception as exc:
        logger.exception("list_sessions failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{session_id}", summary="Get investigation session detail and event log")
async def get_session(session_id: str, request: Request):
    tenant_id = _get_tenant(request)
    try:
        from src.core.ingest.store import get_investigation_session
        record = get_investigation_session(session_id)
    except Exception as exc:
        logger.exception("get_session store error")
        raise HTTPException(status_code=500, detail=str(exc))

    if not record:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")

    if record["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="session belongs to different tenant")

    # Strip the bulky resumable state from the response; clients get events + metadata
    return {
        "session_id": record["session_id"],
        "assessment_id": record["assessment_id"],
        "cluster_id": record["cluster_id"],
        "tenant_id": record["tenant_id"],
        "status": record["status"],
        "close_reason": record["close_reason"],
        "cycles_completed": record["cycles_completed"],
        "events": record["events"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }


@router.post("/{session_id}/resume", summary="Resume an interrupted investigation")
async def resume_session(session_id: str, request: Request):
    tenant_id = _get_tenant(request)

    try:
        from src.core.ingest.store import get_investigation_session
        record = get_investigation_session(session_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if not record:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")

    if record["tenant_id"] != tenant_id:
        raise HTTPException(status_code=403, detail="session belongs to different tenant")

    if record["status"] == "complete":
        raise HTTPException(
            status_code=409,
            detail=f"investigation already complete (reason: {record['close_reason']})",
        )

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    assessment_summary = payload.get("assessment_summary") or {}

    try:
        from src.agents.router import resume_investigation
        result = await resume_investigation(
            session_id=session_id,
            assessment_summary=assessment_summary,
        )
        return result
    except Exception as exc:
        logger.exception("resume_investigation failed for session %s", session_id)
        raise HTTPException(status_code=500, detail=str(exc))
