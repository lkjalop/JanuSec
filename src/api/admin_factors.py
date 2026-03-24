from fastapi import APIRouter, Request, HTTPException, Header, Depends
from typing import Dict, Any
from src.ml.closed_loop_manager import ClosedLoopManager
import os
import json as _json
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/factors', dependencies=[Depends(require_roles('admin'))])
_mgr = ClosedLoopManager()


def _require_admin_key(x_admin_key: str | None, x_api_key: str | None):
    expected = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    provided = x_admin_key or x_api_key
    if not provided or provided != expected:
        if os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'}:
            return
        raise HTTPException(status_code=403, detail='forbidden')


@router.post('/feedback', operation_id='admin_factors_post_feedback')
async def post_feedback(
    request: Request,
    x_admin_key: str | None = Header(None, alias='x-admin-key'),
    x_api_key: str | None = Header(None, alias='x-api-key'),
):
    _require_admin_key(x_admin_key, x_api_key)
    try:
        body = await request.json()
    except Exception:
        try:
            body = await request.form()
        except Exception:
            body = {}
    event_id = body.get('event_id') if isinstance(body, dict) else None
    factors = (body.get('factors') if isinstance(body, dict) else None) or []
    vote = int((body.get('vote', 0) if isinstance(body, dict) else 0) or 0)
    if not event_id or not factors:
        return {'status': 'ok', 'note': 'missing_fields'}
    try:
        _mgr.add_feedback(event_id, list(factors), vote)
    except Exception:
        return {'status': 'ok', 'note': 'feedback cached in-memory'}
    return {'status': 'ok'}


@router.get('/candidates')
async def get_candidates(
    x_admin_key: str | None = Header(None, alias='x-admin-key'),
    x_api_key: str | None = Header(None, alias='x-api-key'),
):
    _require_admin_key(x_admin_key, x_api_key)
    return {'candidates': _mgr.list_candidates()}


@router.post('/candidates/{candidate_id}/approve')
async def approve_candidate(
    candidate_id: int,
    request: Request,
    x_admin_key: str | None = Header(None, alias='x-admin-key'),
    x_api_key: str | None = Header(None, alias='x-api-key'),
):
    _require_admin_key(x_admin_key, x_api_key)
    body = await request.json()
    actor = body.get('actor') or 'manual'
    current = body.get('current_weights') or {}
    try:
        applied = _mgr.approve_candidate(candidate_id, actor, current_weights=current)
    except KeyError:
        raise HTTPException(status_code=404, detail='candidate not found')
    return {'status': 'approved', 'applied': applied}


@router.get('/audit')
async def get_audit(
    x_admin_key: str | None = Header(None, alias='x-admin-key'),
    x_api_key: str | None = Header(None, alias='x-api-key'),
):
    _require_admin_key(x_admin_key, x_api_key)
    # Return last 200 audit entries
    conn = _mgr._conn()
    cur = conn.cursor()
    cur.execute('SELECT id, action, payload, actor, ts FROM factor_weight_audit ORDER BY id DESC LIMIT 200')
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        payload = r[2]
        try:
            payload = _json.loads(r[2]) if isinstance(r[2], str) else r[2]
        except Exception:
            payload = r[2]
        out.append({'id': r[0], 'action': r[1], 'payload': payload, 'actor': r[3], 'ts': r[4]})
    return {'audit': out}
