from __future__ import annotations

import os
import json
import time
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request, Header
from .tenant_helpers import resolve_tenant_id

router = APIRouter(prefix='/api/v1/mappings', tags=['Mapping Templates'])

BASE_DIR = os.getenv('MAPPING_TEMPLATES_DIR', 'data/mappings')
os.makedirs(BASE_DIR, exist_ok=True)

def _tenant_dir(tenant: str) -> str:
    p = os.path.join(BASE_DIR, tenant or 'default')
    os.makedirs(p, exist_ok=True)
    return p

def _path(tenant: str, name: str) -> str:
    return os.path.join(_tenant_dir(tenant), f'{name}.json')

@router.get('/list')
async def list_templates(tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> Dict[str, Any]:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT') or 'default'
    td = _tenant_dir(tenant)
    out = []
    for fname in sorted(os.listdir(td)):
        if not fname.endswith('.json'): continue
        path = os.path.join(td, fname)
        try:
            stat = os.stat(path)
            out.append({'name': fname[:-5], 'size': stat.st_size, 'modified': stat.st_mtime})
        except Exception:
            continue
    return {'tenant': tenant, 'templates': out}

@router.get('/get/{name}')
async def get_template(name: str, tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> Dict[str, Any]:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT') or 'default'
    path = _path(tenant, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='not_found')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'load_error:{e}')
    return {'tenant': tenant, 'name': name, 'mapping': data}

@router.post('/save/{name}')
async def save_template(name: str, payload: Dict[str, Any], request: Request, tenant_id: str | None = Header(None, alias='X-Tenant-ID')) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')
    mapping = payload.get('mapping') or {}
    if not isinstance(mapping, dict):
        raise HTTPException(status_code=400, detail='invalid_mapping')
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT') or 'default'
    path = _path(tenant, name)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'mapping': mapping, 'saved_at': time.time(), 'saved_by': request.headers.get('x-api-key')}, f, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'save_error:{e}')
    return {'tenant': tenant, 'name': name, 'ok': True}

@router.delete('/delete/{name}')
async def delete_template(name: str, tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> Dict[str, Any]:
    tenant = resolve_tenant_id(request, tenant_id) or os.getenv('DEFAULT_TENANT') or 'default'
    path = _path(tenant, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='not_found')
    try:
        os.remove(path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'delete_error:{e}')
    return {'tenant': tenant, 'name': name, 'deleted': True}
