from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix='/api/v1/approvals', tags=['Approvals'])

_APPROVALS: dict[str, dict[str, Any]] = {}
_AUDIT: list[dict[str, Any]] = []


@router.get('/status')
async def approval_status(target_id: str) -> Dict[str, Any]:
    rec = _APPROVALS.get(target_id) or {'status': 'pending', 'updated_by': None, 'updated_ts': None}
    return {'target_id': target_id, **rec}


@router.post('/set')
async def approval_set(target_id: str, status: str, user: str) -> Dict[str, Any]:
    st = status.lower()
    if st not in ('pending','approved','rejected'):
        raise HTTPException(status_code=400, detail='invalid_status')
    rec = {'status': st, 'updated_by': user, 'updated_ts': time.time()}
    _APPROVALS[target_id] = rec
    _AUDIT.append({'ts': time.time(), 'target_id': target_id, 'status': st, 'user': user, 'action': 'approval_set'})
    return {'ok': True, 'target_id': target_id, **rec}


@router.get('/audit')
async def approval_audit(limit: int = 100) -> Dict[str, Any]:
    items = _AUDIT[-limit:]
    return {'items': items, 'count': len(items)}

__all__ = ['router']
