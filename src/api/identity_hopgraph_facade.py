from __future__ import annotations

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import time

router = APIRouter(prefix='/api/v1/identity', tags=['Identity HopGraph'])

try:
    from src.graph.hopgraph import HopGraph  # type: ignore
    _HG_AVAILABLE = True
except Exception:
    _HG_AVAILABLE = False


@router.get('/nodes/{node_id}')
async def get_node(node_id: str) -> Dict[str, Any]:
    if not _HG_AVAILABLE:
        raise HTTPException(status_code=404, detail='hopgraph_unavailable')
    try:
        hg = HopGraph.get_instance()
        node = hg.get_node(node_id)
        if not node:
            raise HTTPException(status_code=404, detail='not_found')
        return {'node': node}
    except Exception:
        raise HTTPException(status_code=500, detail='internal_error')


@router.get('/neighbors/{node_id}')
async def get_neighbors(node_id: str, limit: int = 50) -> Dict[str, Any]:
    if not _HG_AVAILABLE:
        raise HTTPException(status_code=404, detail='hopgraph_unavailable')
    try:
        hg = HopGraph.get_instance()
        nbrs = hg.get_neighbors(node_id, limit=limit)
        return {'neighbors': nbrs}
    except Exception:
        raise HTTPException(status_code=500, detail='internal_error')


@router.get('/session/list', operation_id='identity_session_list')
async def list_sessions() -> Dict[str, Any]:
    # Return recently built sessions from graph_sessions in-memory store (best-effort)
    try:
        from src.api.graph_sessions import _SESSIONS  # type: ignore
        return {'sessions': list(_SESSIONS.keys())}
    except Exception:
        return {'sessions': []}


@router.post('/session/{session_id}/ttl/{seconds}')
async def set_session_ttl(session_id: str, seconds: int) -> Dict[str, Any]:
    try:
        from src.api.graph_sessions import _SESSIONS  # type: ignore
        if session_id not in _SESSIONS:
            raise HTTPException(status_code=404, detail='not_found')
        # Attach ttl metadata and a deletion timestamp
        _SESSIONS[session_id]['ttl'] = int(seconds)
        _SESSIONS[session_id]['expires_at'] = time.time() + int(seconds)
        return {'ok': True}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail='internal_error')


__all__ = ['router']
