from __future__ import annotations

from typing import Any, Dict
import time

from fastapi import APIRouter, HTTPException, Query, Request, Header

from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as G
from src.core.graph.graph_scoring import compute_composite_score


router = APIRouter(prefix="/api/v1/graph/identity", tags=["Identity Graph"])


@router.post("/ingest")
async def ingest_identity_event(payload: Dict[str, Any], request: Request, redact: str | None = Query(None, description="Optional redaction mode: mask|none"), x_privacy_mode: str | None = Header(default=None, convert_underscores=False)) -> Dict[str, Any]:
    try:
        ev = dict(payload or {})
        # Policy-driven privacy: prefer explicit query/header; fallback to env
        mode = (redact or x_privacy_mode or '').lower()
        if mode in {'mask','none'}:
            ev['_privacy_mode'] = mode
        else:
            import os
            try:
                from src.core.flags import get_flag as _get_flag  # type: ignore
            except Exception:
                _get_flag = lambda *_a, **_k: None  # type: ignore
            dflt = str(_get_flag('PRIVACY_DEFAULT_MODE', os.getenv('PRIVACY_DEFAULT_MODE','')) or '').lower()
            if dflt in {'mask','none'}:
                ev['_privacy_mode'] = dflt
        G.ingest_identity_event(ev)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid_event:{e}")


@router.get("/paths")
async def get_identity_paths(user: str = Query(..., description="User id, e.g., user:alice@corp.com"), limit: int = 5) -> Dict[str, Any]:
    if not user.startswith('user:'):
        user = f'user:{user}'
    paths = G.find_top_paths(user, limit=max(1, min(limit, 25)))
    enriched = []
    for p in paths:
        meta = G.explain_path(p['path'])
        enriched.append({**p, **meta})
    return {"user": user, "paths": enriched}


@router.post('/preview')
async def preview_identity(payload: Dict[str, Any], detail: str | None = Query('summary')) -> Dict[str, Any]:
    """Preview endpoint: accepts an event-like payload and returns a summarized explain payload.

    detail: 'summary' or 'full' (full currently behaves same as summary for identity)
    """
    try:
        ev = dict(payload or {})
        # Map to a short path for preview: try to infer user and host
        user = ev.get('user') or ev.get('username')
        dst_h = ev.get('dest_host') or ev.get('host') or ev.get('hostname')
        if user and dst_h:
            path = [f'user:{user}', f'host:{dst_h}']
        elif user:
            path = [f'user:{user}']
        else:
            # fallback: inspect any host/process keys
            path = [str(ev.get('id') or ev.get('event_id') or 'unknown')]
        res = G.explain_path(path)
        scoring = compute_composite_score(path, res.get('mapping_details') if isinstance(res, dict) else None, tenant=ev.get('tenant'), ts=ev.get('ts'))
        out = {k: res[k] for k in ('mitre','stride','pasta','dread','mapping_details') if k in res}
        out['scoring'] = scoring
        out['diagnostic'] = {'preview_ts': time.time()}
        return out if detail == 'full' else out
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'preview_failed:{e}')
