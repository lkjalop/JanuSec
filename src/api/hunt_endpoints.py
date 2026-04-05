from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from typing import Any, Dict, List
import time
from .runtime_state import DECISION_CACHE  # type: ignore
from hunt.dsl import run_query  # type: ignore

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])

# Simple in-memory ring buffer for recent queries (not persisted; demo only)
_HUNT_QUERY_LOG: List[Dict[str, Any]] = []
_HUNT_QUERY_LOG_MAX = 100

@router.post('/run')
async def hunt_run(request: Request) -> Dict[str, Any]:
    try:
        spec = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(spec, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    decisions = list(DECISION_CACHE.values()) if isinstance(DECISION_CACHE, dict) else []
    results = run_query(spec, decisions)
    entry = {
        'ts': time.time(),
        'spec': spec,
        'result_count': len(results)
    }
    try:
        _HUNT_QUERY_LOG.append(entry)
        if len(_HUNT_QUERY_LOG) > _HUNT_QUERY_LOG_MAX:
            # truncate oldest
            del _HUNT_QUERY_LOG[0: len(_HUNT_QUERY_LOG) - _HUNT_QUERY_LOG_MAX]
    except Exception:
        pass
    return {'count': len(results), 'results': results[:spec.get('limit', 100)], 'query': spec}

@router.get('/queries/recent')
async def hunt_recent_queries(limit: int = 25) -> Dict[str, Any]:
    try:
        items = list(reversed(_HUNT_QUERY_LOG))[:max(1, min(limit, _HUNT_QUERY_LOG_MAX))]
    except Exception:
        items = []
    return {'queries': items, 'count': len(items)}

__all__ = ['router']