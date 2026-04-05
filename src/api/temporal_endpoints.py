from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Query, Request, Header
from .tenant_helpers import resolve_tenant_id

try:
    from src.ml.temporal_model import GLOBAL_TEMPORAL_MODEL  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_TEMPORAL_MODEL = None  # type: ignore

router = APIRouter()


@router.get('/api/v1/temporal/stats')
def temporal_stats(request: Request, tenant_id: str | None = Header(None, alias='X-Tenant-ID')) -> Dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    if not GLOBAL_TEMPORAL_MODEL:
        raise HTTPException(status_code=503, detail='temporal_unavailable')
    try:
        stats = GLOBAL_TEMPORAL_MODEL.stats()  # type: ignore[attr-defined]
        if isinstance(stats, dict):
            stats['tenant_id'] = tenant_id
        return stats
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f'stats_failed:{exc}')


@router.post('/api/v1/temporal/rotate')
def temporal_rotate(payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not GLOBAL_TEMPORAL_MODEL:
        raise HTTPException(status_code=503, detail='temporal_unavailable')
    do_persist = True
    try:
        if isinstance(payload, dict):
            do_persist = bool(payload.get('persist', True))
    except Exception:
        do_persist = True
    try:
        # Rotate clears in-memory state optionally persisting a snapshot
        GLOBAL_TEMPORAL_MODEL.rotate(persist=do_persist)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f'rotate_failed:{exc}')
    return {'ok': True, 'persisted': bool(do_persist)}


__all__ = ['router']


@router.get('/api/v1/metrics/temporal')
def metrics_temporal(request: Request, tenant_id: str | None = Query(None, description='Optional tenant id prefix'), limit: int = Query(50, description='Max samples to return')) -> Dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    # If model missing, provide demo synthetic data when running in lite/test mode.
    if not GLOBAL_TEMPORAL_MODEL:
        import os, time, math
        demo_env = os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}
        if not demo_env:
            raise HTTPException(status_code=503, detail='temporal_unavailable')
        # produce simple sinusoidal demo series
        now = int(time.time())
        series = []
        vals = []
        for i in range(max(10, int(limit))):
            t = now - (int(limit)-i) * 60
            v = 0.5 + 0.5 * math.sin(i / 3.0)
            vals.append({'t': t, 'v': round(v, 4)})
        series.append({'entity': tenant_id or 'demo', 'values': vals})
        return {'series': series, 'summary': {'count': len(vals)}}
    try:
        return GLOBAL_TEMPORAL_MODEL.recent_history(tenant=tenant_id, limit=limit)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f'recent_history_failed:{exc}')
