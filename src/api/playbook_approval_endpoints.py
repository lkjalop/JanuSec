from fastapi import APIRouter, Request, HTTPException, Depends, Body
from pydantic import BaseModel
import os
import uuid
from typing import Dict, Any
from src.core.approval_store import create_request, approve_token, is_approved, list_requests, revoke_token
from src.core.playbooks import execute_playbook
from src.core import approval_repo
from fastapi.responses import StreamingResponse
import io, csv
from dateutil import parser as dateparser
from datetime import timezone

try:
    from src.security.auth import auth_dependency, AuthContext, require_scopes
except Exception:
    # Fallbacks for test/lite modes
    def auth_dependency():
        return None

    class AuthContext:  # type: ignore
        def __init__(self, actor: str = 'test'):
            self.actor = actor

    def require_scopes(_s: str):
        def _fn():
            return None
        return _fn

router = APIRouter()


def require_role(role: str):
    # Lightweight RBAC stub used in tests: allow when PLATFORM_LITE_INIT or when role=="approver"
    def _fn():
        if role == 'approver' and (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ):
            return True
        raise HTTPException(status_code=403, detail='forbidden')
    return _fn


class ApprovalRequest(BaseModel):
    action: str
    target: str
    params: Dict[str, Any] | None = None
    require_approval: bool = True


@router.post('/api/v1/playbook/request')
async def request_playbook(request: Request, auth: AuthContext = Depends(auth_dependency)):
    token = str(uuid.uuid4())
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail='expected_object')
    if 'action' not in body or 'target' not in body:
        raise HTTPException(status_code=422, detail='missing_action_or_target')
    req_obj = dict(body)
    # attach requester identity when available
    if auth is not None and hasattr(auth, 'subject'):
        req_obj['requested_by'] = getattr(auth, 'subject', None)
    elif auth is not None and hasattr(auth, 'actor'):
        req_obj['requested_by'] = getattr(auth, 'actor', None)
    create_request(token, req_obj)
    return {'token': token, 'status': 'requested'}


@router.post('/api/v1/playbook/approve')
async def approve_playbook(token: str, approver: str | None = None, auth: AuthContext = Depends(auth_dependency)):
    # Use authenticated actor as approver when available
    approver_id = approver or (getattr(auth, 'actor', None) if auth is not None else 'system')
    try:
        approve_token(token, approver_id)
        return {'token': token, 'status': 'approved', 'approver': approver_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/playbook/revoke')
async def revoke_playbook(token: str, reason: str | None = None, auth: AuthContext = Depends(auth_dependency)):
    revoker = getattr(auth, 'subject', None) or getattr(auth, 'actor', None) or 'system'
    try:
        revoke_token(token, revoker, reason)
        return {'token': token, 'status': 'revoked', 'revoked_by': revoker}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/v1/playbook/requests')
async def get_requests(status: str | None = None, approver: str | None = None, since: str | None = None, until: str | None = None, offset: int = 0, limit: int = 50, _=Depends(require_scopes('telemetry.read'))):
    # parse ISO if provided
    def _norm(ts: str | None):
        if not ts:
            return None
        try:
            # parse flexibly, coerce to UTC, and emit strict Z-suffixed ISO
            dt = dateparser.parse(ts)
            if dt.tzinfo is None:
                # assume UTC for naive datetimes
                dt = dt.replace(tzinfo=timezone.utc)
            dt_utc = dt.astimezone(timezone.utc)
            return dt_utc.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
        except Exception:
            return ts

    s = _norm(since)
    u = _norm(until)
    try:
        items = approval_repo.query_approvals(status=status, approver=approver, since=s, until=u, offset=offset, limit=limit)
    except Exception:
        # fallback
        items = list_requests()
    return {'requests': items, 'offset': offset, 'limit': limit}


@router.get('/api/v1/playbook/requests/export')
async def export_requests(format: str = 'json', offset: int = 0, limit: int = 1000, _=Depends(require_scopes('telemetry.read'))):
    items = approval_repo.query_approvals(offset=offset, limit=limit) if approval_repo else list_requests()
    if format == 'csv':
        def gen():
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(['token','status','requested_at','approved_at','approver','revoked_at','revoked_by'])
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)
            for it in items:
                writer.writerow([it.get('token'), it.get('status'), it.get('requested_at'), it.get('approved_at'), it.get('approver'), it.get('revoked_at'), it.get('revoked_by')])
                yield buf.getvalue()
                buf.seek(0); buf.truncate(0)
        return StreamingResponse(gen(), media_type='text/csv')
    else:
        return {'requests': items}


@router.post('/api/v1/playbook/execute')
async def exec_playbook(request: Request, auth: AuthContext = Depends(auth_dependency)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    action = body.get('action')
    target = body.get('target')
    params = body.get('params')
    dry_run = body.get('dry_run', True)
    approval_token = body.get('approval_token')

    # If approval required, check token
    if approval_token:
        if not is_approved(approval_token):
            raise HTTPException(status_code=403, detail='approval_required')

    # attach actor info into params/audit
    actor = getattr(auth, 'actor', None) if auth is not None else None
    if isinstance(params, dict):
        params['_requested_by'] = actor
    else:
        params = {'_requested_by': actor}

    res = execute_playbook(action, target, params=params, dry_run=bool(dry_run))
    # audit is performed by approval_store writes; additional audit logs may be added here
    return {'ok': True, 'result': res}
