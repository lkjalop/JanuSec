"""API endpoints for pre-generated persona views (BatchPersonaWorker cache).

Routes::

    POST /api/v1/persona/enqueue            — submit a triage batch for pre-gen
    GET  /api/v1/persona/views/{report_id}  — all personas for a report
    GET  /api/v1/persona/views/{report_id}/{persona}  — single persona view
    GET  /api/v1/persona/cached             — list cached report IDs
    GET  /api/v1/persona/worker/stats       — worker health + queue depth
    POST /api/v1/persona/worker/start       — start background worker
    POST /api/v1/persona/worker/stop        — graceful stop
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/persona', tags=['Persona'])


# ── Request models ─────────────────────────────────────────────────────

class EnqueueReportRequest(BaseModel):
    report: Dict[str, Any]
    tier: str = 'P3'


class EnqueueBatchRequest(BaseModel):
    alerts: List[Dict[str, Any]]
    config: Optional[Dict[str, Any]] = None


# ── Helpers ───────────────────────────────────────────────────────────

def _worker():
    from src.workers.persona_worker import get_persona_worker
    return get_persona_worker()


def _cache():
    from src.workers.persona_worker import get_persona_cache
    return get_persona_cache()


# ── Enqueue ───────────────────────────────────────────────────────────

@router.post('/enqueue')
async def enqueue_report(body: EnqueueReportRequest) -> Dict[str, Any]:
    """Submit a single report for background persona pre-generation."""
    worker = _worker()
    if not worker._threads:
        # auto-start if not yet running
        worker.start()
    queued = worker.enqueue_report(body.report, tier=body.tier)
    return {'queued': queued, 'queue_depth': worker._queue.qsize()}


@router.post('/enqueue/batch')
async def enqueue_batch(body: EnqueueBatchRequest) -> Dict[str, Any]:
    """Submit a batch of alerts through triage and enqueue for persona pre-gen."""
    if not body.alerts:
        raise HTTPException(status_code=400, detail='empty_alerts')

    try:
        from src.reporting.tiered_triage import TriageConfig, triage_alerts
        cfg = TriageConfig()
        if body.config:
            for k, v in body.config.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
        result = triage_alerts(body.alerts, config=cfg)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'triage_failed: {exc}')

    worker = _worker()
    if not worker._threads:
        worker.start()

    # Build a report lookup from the raw alert dicts
    lookup = {
        a.get('report_id') or a.get('id') or '': a
        for a in body.alerts
    }
    queued = worker.enqueue(result, report_lookup=lookup)
    return {
        'queued': queued,
        'triage_stats': result.stats,
        'queue_depth': worker._queue.qsize(),
    }


# ── View retrieval ─────────────────────────────────────────────────────

@router.get('/views/{report_id}')
async def get_views(report_id: str) -> Dict[str, Any]:
    """Get all pre-generated persona views for a report."""
    views = _cache().get(report_id)
    if not views:
        raise HTTPException(status_code=404, detail='not_cached')
    return {'report_id': report_id, 'personas': list(views.keys()), 'views': views}


@router.get('/views/{report_id}/{persona}')
async def get_persona_view(report_id: str, persona: str) -> Dict[str, Any]:
    """Get pre-generated view for a specific persona."""
    view = _cache().get_persona(report_id, persona)
    if not view:
        raise HTTPException(status_code=404, detail='not_cached')
    return view


@router.get('/cached')
async def list_cached() -> Dict[str, Any]:
    """List all cached report IDs (non-expired)."""
    ids = _cache().list_cached()
    return {'report_ids': ids, 'count': len(ids)}


# ── Worker management ──────────────────────────────────────────────────

@router.get('/worker/stats')
async def worker_stats() -> Dict[str, Any]:
    return _worker().stats()


@router.post('/worker/start')
async def worker_start() -> Dict[str, Any]:
    w = _worker()
    w.start()
    return {'started': True, 'threads': w.n_threads}


@router.post('/worker/stop')
async def worker_stop() -> Dict[str, Any]:
    w = _worker()
    w.stop()
    return {'stopped': True}
