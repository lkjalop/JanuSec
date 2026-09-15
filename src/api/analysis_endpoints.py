from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from src.pipeline.deep_analyze_pipeline import DEFAULT_WORKER
from src.security.auth import auth_dependency, require_scopes

MAX_PAYLOAD_BYTES = int(__import__('os').getenv('DEEP_ANALYZE_MAX_PAYLOAD_BYTES','102400'))  # 100KB

router = APIRouter(prefix='/api/v1/analysis')


class StartSessionRequest(BaseModel):
    session_id: str
    payload: dict = {}


@router.post('/session/start')
async def start_session(request: Request, auth=Depends(require_scopes())):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    # minimal validation
    session_id = data.get('session_id')
    payload = data.get('payload') or {}
    if not session_id:
        raise HTTPException(status_code=400, detail='session_id required')
    try:
        import json as _json
        b = len(_json.dumps(payload).encode('utf-8'))
        if b > MAX_PAYLOAD_BYTES:
            raise HTTPException(status_code=413, detail='payload too large')
        s = DEFAULT_WORKER.start_session(session_id, payload)
        return {'session_id': session_id, 'status': s['status']}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get('/session/{session_id}/status')
def session_status(session_id: str):
    s = DEFAULT_WORKER.status(session_id)
    if not s:
        raise HTTPException(status_code=404, detail='not found')
    return s


@router.post('/session/{session_id}/cancel')
def session_cancel(session_id: str):
    ok = DEFAULT_WORKER.cancel(session_id)
    if not ok:
        raise HTTPException(status_code=400, detail='cannot cancel')
    return {'session_id': session_id, 'cancelled': True}
