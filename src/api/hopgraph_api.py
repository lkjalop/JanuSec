from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from src.core.hopgraph.ingest_queue import list_sessions, build_session_summary, get_session_events, cleanup_sessions

router = APIRouter(prefix='/api/v1/hopgraph')


@router.get('/sessions')
def api_list_sessions() -> Dict[str, Any]:
    return list_sessions()


@router.get('/sessions/{session_id}')
def api_get_session(session_id: str, alpha: float = 0.6) -> Dict[str, Any]:
    try:
        summary = build_session_summary(session_id, alpha=alpha)
        events = get_session_events(session_id)
        summary['events'] = events
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/sessions/cleanup')
def api_cleanup_sessions(ttl_seconds: int = 60 * 60 * 24 * 7) -> Dict[str, Any]:
    removed = cleanup_sessions(ttl_seconds=ttl_seconds)
    return {'removed': removed}
