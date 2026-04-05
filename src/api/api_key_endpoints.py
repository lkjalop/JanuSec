from __future__ import annotations
import os, time, secrets
from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Request, Depends
from .api_key_scope import verify_api_key, rotate_api_key
from .tenant_helpers import resolve_tenant_id
from src.security.roles import require_roles
from database_adapter import db_manager

router = APIRouter(dependencies=[Depends(require_roles('admin'))])

def _require_admin(req: Request) -> None:
    # Simple scope check; production should extend RBAC
    api_key = req.headers.get('x-api-key') or ''
    tenant = req.headers.get('x-tenant-id') or None
    tenant = resolve_tenant_id(req, tenant)
    if not api_key or not tenant:
        raise HTTPException(status_code=401, detail='missing_auth')
    if not os.getenv('API_KEY_ADMIN_BYPASS') and not req.headers.get('x-admin', '').lower() in {'1','true','yes'}:
        if not req.headers.get('x-scopes'):
            # Validate scope via stored key scopes
            ok = False
            import asyncio
            ok = asyncio.get_event_loop().run_until_complete(verify_api_key(api_key, tenant, ['admin']))
            if not ok:
                raise HTTPException(status_code=403, detail='insufficient_scope')

@router.post('/api/v1/api_keys/rotate')
async def api_key_rotate(request: Request, body: Dict[str, Any]) -> Dict[str, Any]:
    _require_admin(request)
    tenant = resolve_tenant_id(request, body.get('tenant_id') or request.headers.get('x-tenant-id'))
    old_key = body.get('old_key')
    if not tenant or not old_key:
        raise HTTPException(status_code=400, detail='missing_fields')
    new_key = secrets.token_hex(32)
    scopes = body.get('scopes') or ['admin']
    ok = await rotate_api_key(old_key, new_key, tenant, scopes)
    if not ok:
        raise HTTPException(status_code=500, detail='rotation_failed')
    # Audit log entry
    adp = db_manager.adapter
    try:
        if adp and hasattr(adp,'pool') and adp.pool:
            async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                await conn.execute("INSERT INTO audit_log(event_id, action, actor, details, tenant_id) VALUES($1,$2,$3,$4,$5)", f"rot-{int(time.time()*1000)}", 'api_key_rotate', 'system', {'old': old_key, 'new': new_key}, tenant)
        elif adp and hasattr(adp,'connection') and adp.connection:
            await adp.connection.execute("INSERT INTO audit_log(event_id, action, actor, details, tenant_id) VALUES(?,?,?,?,?)", (f"rot-{int(time.time()*1000)}", 'api_key_rotate', 'system', str({'old': old_key, 'new': new_key}), tenant))  # type: ignore[attr-defined]
            await adp.connection.commit()  # type: ignore[attr-defined]
    except Exception:
        pass
    return {'status':'rotated','new_key': new_key}

@router.get('/api/v1/api_keys/audit')
async def api_key_audit(request: Request) -> Dict[str, Any]:
    _require_admin(request)
    tenant = resolve_tenant_id(request, request.headers.get('x-tenant-id'))
    adp = db_manager.adapter
    entries = []
    try:
        if adp and hasattr(adp,'pool') and adp.pool:
            async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                rows = await conn.fetch("SELECT timestamp, action, actor, details FROM audit_log WHERE tenant_id=$1 AND action='api_key_rotate' ORDER BY timestamp DESC LIMIT 100", tenant)
                for r in rows:
                    entries.append({'timestamp': r['timestamp'].isoformat(), 'action': r['action'], 'actor': r['actor'], 'details': r['details']})
        elif adp and hasattr(adp,'connection') and adp.connection:
            cur = await adp.connection.execute("SELECT timestamp, action, actor, details FROM audit_log WHERE tenant_id=? AND action='api_key_rotate' ORDER BY timestamp DESC LIMIT 100", (tenant,))  # type: ignore[attr-defined]
            rows = await cur.fetchall()
            for row in rows:
                entries.append({'timestamp': row[0], 'action': row[1], 'actor': row[2], 'details': row[3]})
    except Exception:
        pass
    return {'audit': entries}

__all__ = ['router']
