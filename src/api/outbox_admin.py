from fastapi import APIRouter, HTTPException, Request
from typing import Any
from src.security.auth import require_api_key
try:
    from src.security.rbac import has_role
except Exception:
    def has_role(_a, _b):
        return False

from .dispatch_outbox import list_failed, get_by_id, repair

router = APIRouter(prefix="/api/v1/outbox", tags=["outbox_admin"])


@router.get('/')
async def list_failed_entries(request: Request, _auth = require_api_key):
    # only admins should list failed entries
    if not has_role(request.headers.get('x-actor') or '', 'admin'):
        raise HTTPException(status_code=403, detail='forbidden')
    return {'failed': list_failed()}


@router.get('/{dispatch_id}')
async def get_entry(dispatch_id: str, request: Request, _auth = require_api_key):
    if not has_role(request.headers.get('x-actor') or '', 'admin'):
        raise HTTPException(status_code=403, detail='forbidden')
    ent = get_by_id(dispatch_id)
    if not ent:
        raise HTTPException(status_code=404, detail='not_found')
    return ent


@router.post('/{dispatch_id}/repair')
async def repair_entry(dispatch_id: str, request: Request, _auth = require_api_key):
    if not has_role(request.headers.get('x-actor') or '', 'admin'):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        repair(dispatch_id)
    except Exception:
        raise HTTPException(status_code=500, detail='repair_failed')
    return {'repaired': dispatch_id}
