"""Test-only helper routes, extracted from app.py (State-extraction Step 3c).

These routes (clear tenant rate windows; create a lite incident) are used by the test
harness / local dev only. Moving them into a router shrinks app.py and is now possible
because their dependencies are all in canonical homes: auth_helpers.admin_ok,
tenant_helpers.resolve_tenant_with_default, and runtime_state's rate/incident stores.

Guarded exactly as before (PLATFORM_LITE_INIT or admin key / localhost).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

from fastapi import APIRouter, HTTPException, Request

from .auth_helpers import admin_ok
from .tenant_helpers import resolve_tenant_with_default
from .runtime_state import (
    _TENANT_RATE_STORAGE, _TENANT_RATE_DROPS, _TENANT_LAST_ALERT, _LITE_INCIDENT_STORE,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post('/api/v1/test_helpers/reset_tenant_rate')
async def reset_tenant_rate(request: Request):
    """Clear in-memory tenant rate windows and counters. Guarded: lite mode or admin key."""
    if os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1', 'true', 'yes'}:
        allowed = True
    else:
        allowed = admin_ok(request)
    if not allowed:
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        _TENANT_RATE_STORAGE.clear()
        _TENANT_RATE_DROPS.clear()
        _TENANT_LAST_ALERT.clear()
        return {'status': 'ok', 'cleared': True}
    except Exception:
        raise HTTPException(status_code=500, detail='reset_failed')


@router.post('/api/v1/test_helpers/create_incident')
async def create_incident(request: Request, payload: dict = None) -> dict:
    """Create an incident bypassing RBAC for local dev / UI tests. Guarded: lite mode or
    localhost origin."""
    if payload is None:
        payload = await request.json()
    remote = None
    try:
        remote = request.client.host if request.client else None
    except Exception:
        remote = None
    allowed = (os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1', 'true', 'yes'}
               or (remote in ('127.0.0.1', '::1', 'localhost')))
    if not allowed:
        raise HTTPException(status_code=403, detail='forbidden')
    iid = payload.get('id') or f"inc-{int(time.time() * 1000)}"
    try:
        tenant_hdr = resolve_tenant_with_default(request)
    except Exception:
        try:
            tenant_hdr = request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id') or None
        except Exception:
            tenant_hdr = None
    item = {
        'id': iid,
        'artifact_id': payload.get('artifact_id'),
        'title': payload.get('title'),
        'severity': payload.get('severity') or 'high',
        'status': payload.get('status') or 'open',
        'summary': payload.get('description'),
        'metadata': {'attack_subgraph': payload.get('attack_subgraph')} if 'attack_subgraph' in payload else {},
        'tenant_id': payload.get('tenant_id') or tenant_hdr,
        'ts': time.time(),
    }
    try:
        import src.repositories.incidents_repo as incidents_repo  # type: ignore
        coro = incidents_repo.upsert_incident(iid, item, item.get('tenant_id'))
        if asyncio.iscoroutine(coro):
            await coro  # type: ignore[misc]
    except Exception:
        try:
            _LITE_INCIDENT_STORE.append(item)
        except Exception as _exc:
            logger.debug('test_helpers create_incident lite-store fallback failed: %s', _exc)
    return {'incident': item}
