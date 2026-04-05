from __future__ import annotations
from fastapi import APIRouter, Query
from typing import List, Dict, Any
from src.core.correlation.cooccurrence import GLOBAL_COOCCURRENCE  # type: ignore

router = APIRouter()


@router.get('/api/v1/correlation/top_pairs')
async def top_pairs(limit: int = Query(20, ge=1, le=200)) -> Dict[str, Any]:
    """Return top co-occurrence pairs by count (descending)."""
    try:
        pairs = getattr(GLOBAL_COOCCURRENCE, 'pairs', {}) or {}
        # transform {('a','b'):(cnt,ts)} -> [{'a':'..','b':'..','cnt':int,'ts':float}, ...]
        rows = []
        for (a,b), (cnt, ts) in pairs.items():
            rows.append({'a': a, 'b': b, 'cnt': int(cnt), 'ts': float(ts)})
        rows.sort(key=lambda r: r['cnt'], reverse=True)
        return {'pairs': rows[:limit]}
    except Exception:
        return {'pairs': []}


@router.get('/api/v1/correlation/persisted')
async def persisted_state(limit: int = Query(200, ge=1, le=200)) -> Dict[str, Any]:
    """Return persisted correlation state (pairs + temporal buffers).

    This reads the long-term TTL JSON store written by the correlation
    persistence helper and returns a compact view. Best-effort; failures
    return empty structures.
    """
    try:
        from src.core.correlation.correlation_state_store import load_state  # type: ignore
        state = load_state() or {}
        # convert persisted pairs dict keyed by "a|b" into list
        pairs = []
        for k, meta in (state.get('pairs') or {}).items():
            try:
                a, b = k.split('|', 1)
            except Exception:
                a = k
                b = ''
            pairs.append({'a': a, 'b': b, 'cnt': int(meta.get('cnt', 0)), 'ts': float(meta.get('ts', 0))})
        pairs.sort(key=lambda r: r['cnt'], reverse=True)
        temporal = state.get('temporal') or {}
        # limit temporal buffers to reasonable size in response
        for ent, buf in list(temporal.items()):
            temporal[ent] = buf[-50:]
        return {'pairs': pairs[:limit], 'temporal': temporal}
    except Exception:
        return {'pairs': [], 'temporal': {}}
