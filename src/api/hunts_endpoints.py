"""Hunt / Finops related endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import time

router = APIRouter()

# External helpers (import lazily in handlers to avoid heavy deps at import time)

class HuntStartRequest(BaseModel):
    session_id: str
    window_hours: int = 24
    model_enabled: bool = False
    budget_cap_units: float | None = None
    async_run: bool = False
    model_config = {"protected_namespaces": ()}

def resolve_tenant():  # placeholder dependency
    return None

@router.post('/hunts/start')
async def hunts_start(payload: HuntStartRequest, tenant_id: Optional[str] = Depends(resolve_tenant)):
    from sidecar_server import get_sidecar_manager  # type: ignore
    mgr = get_sidecar_manager()
    try:
        sess = mgr.start(session_id=payload.session_id, tenant=tenant_id or 'default', window_hours=payload.window_hours, model_enabled=payload.model_enabled, budget_cap_units=payload.budget_cap_units, async_run=payload.async_run)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {'session_id': sess.id, 'status': sess.status, 'estimate_units': sess.estimate_units, 'async': payload.async_run}

@router.get('/hunts/report/{session_id}')
async def hunts_report(session_id: str, format: str = 'json', tenant_id: Optional[str] = Depends(resolve_tenant)):
    from sidecar_server import get_sidecar_manager  # type: ignore
    mgr = get_sidecar_manager()
    rep = mgr.report(session_id)
    if not rep:
        raise HTTPException(status_code=404, detail='not_found')
    if format == 'markdown':
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(rep.get('report_markdown',''))
    if format == 'raw':
        return rep.get('report', {})
    return rep

@router.get('/hunts/session/{session_id}/progress')
async def hunts_progress(session_id: str, tenant_id: Optional[str] = Depends(resolve_tenant)):
    from sidecar_server import get_sidecar_manager  # type: ignore
    mgr = get_sidecar_manager()
    sess = mgr.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail='not_found')
    elapsed = (time.time() - sess.start_time) if sess.start_time else 0.0
    return {'session_id': session_id,'status': sess.status,'elapsed_seconds': round(elapsed,2),'factors_partial': dict(list(sess.factors.items())[:5]),'model_tiers_used': sess.model_tiers_used}

__all__ = ['router']
