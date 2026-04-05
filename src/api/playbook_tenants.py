from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from starlette.responses import JSONResponse
from typing import Any
from src.core.playbooks.tenant_playbook_generator import TenantPlaybookGenerator
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter()
gen = TenantPlaybookGenerator()


@router.get('/api/v1/tenants/{tenant_id}/playbooks')
async def list_playbooks(tenant_id: str, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id) or tenant_id
    try:
        p = gen.list_playbooks(tenant_id)
        return JSONResponse({'playbooks': p})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/tenants/{tenant_id}/playbooks')
async def create_playbook(tenant_id: str, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id) or tenant_id
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail='playbook must be an object')
        pb = gen.save_playbook(tenant_id, body)
        return JSONResponse(pb)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import json
import os
from fastapi import APIRouter, Body, HTTPException, Request
from typing import Dict, List

from .auth import check_admin_token_async

DATA_PATH = os.getenv('PLAYBOOK_TENANTS_PATH', 'data/playbook_tenants.json')
_LOCK = None


def _load() -> Dict[str, List[str]]:
    try:
        with open(DATA_PATH, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {'allow': [], 'deny': []}


def _save(d: Dict[str, List[str]]):
    os.makedirs(os.path.dirname(DATA_PATH) or '.', exist_ok=True)
    with open(DATA_PATH, 'w', encoding='utf-8') as fh:
        json.dump(d, fh, indent=2)


router = APIRouter(prefix='/api/v1/playbook-tenants', tags=['PlaybookTenants'])


@router.get('/', operation_id='playbook_tenants_list')
async def list_tenants(request: Request):
    await check_admin_token_async(request)
    return _load()


@router.post('/allow')
async def allow_tenant(request: Request, payload: Dict[str, str] = Body(...)):
    await check_admin_token_async(request)
    t = payload.get('tenant')
    if not t:
        raise HTTPException(400, 'missing tenant')
    d = _load()
    if t not in d.get('allow', []):
        d.setdefault('allow', []).append(t)
    _save(d)
    return {'status': 'ok', 'allow': d.get('allow')}


@router.post('/deny')
async def deny_tenant(request: Request, payload: Dict[str, str] = Body(...)):
    await check_admin_token_async(request)
    t = payload.get('tenant')
    if not t:
        raise HTTPException(400, 'missing tenant')
    d = _load()
    if t not in d.get('deny', []):
        d.setdefault('deny', []).append(t)
    _save(d)
    return {'status': 'ok', 'deny': d.get('deny')}


@router.delete('/allow')
async def remove_allow(request: Request, payload: Dict[str, str] = Body(...)):
    await check_admin_token_async(request)
    t = payload.get('tenant')
    if not t:
        raise HTTPException(400, 'missing tenant')
    d = _load()
    if t in d.get('allow', []):
        d['allow'].remove(t)
    _save(d)
    return {'status': 'ok', 'allow': d.get('allow')}


@router.delete('/deny')
async def remove_deny(request: Request, payload: Dict[str, str] = Body(...)):
    await check_admin_token_async(request)
    t = payload.get('tenant')
    if not t:
        raise HTTPException(400, 'missing tenant')
    d = _load()
    if t in d.get('deny', []):
        d['deny'].remove(t)
    _save(d)
    return {'status': 'ok', 'deny': d.get('deny')}


__all__ = ['router']
