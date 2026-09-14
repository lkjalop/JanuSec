from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Request, Depends
import os
from integrations.bgp_client import CLIENT as BGP
from src.security.roles import require_roles

router = APIRouter(tags=["BGP"])


@router.get('/api/v1/bgp/incidents')
async def list_bgp_incidents() -> dict[str, Any]:
    """Stub: return empty incident list, structure ready for future integration."""
    prefixes = sorted(list(BGP.get_prefixes()))
    return { 'incidents': [{'prefix': p} for p in prefixes], 'ts': __import__('time').time() }


def _admin_ok(request: Request) -> bool:
    try:
        key = request.headers.get('x-admin-key') or request.headers.get('X-Admin-Key')
        expected = os.getenv('ADMIN_API_KEY') or os.getenv('X_ADMIN_KEY')
        return bool(expected) and key == expected
    except Exception:
        return False

@router.post('/api/v1/admin/bgp/refresh', dependencies=[Depends(require_roles('admin'))])
async def bgp_refresh(request: Request) -> dict[str, Any]:
    if not _admin_ok(request):
        raise HTTPException(status_code=403, detail='forbidden')
    res = await BGP.refresh()
    if not res.get('ok'):
        raise HTTPException(status_code=502, detail=res.get('error') or 'refresh_failed')
    return res


@router.get('/api/v1/admin/bgp/status', dependencies=[Depends(require_roles('admin'))])
async def bgp_status(request: Request) -> dict[str, Any]:
    if not _admin_ok(request):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        last = float(getattr(BGP, '_last', 0.0) or 0.0)
        ttl = int(getattr(BGP, 'ttl', 0) or 0)
        count = len(BGP.get_prefixes())
        return { 'last_refresh_ts': last, 'ttl_seconds': ttl, 'prefix_count': count }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'status_error: {exc}')

__all__ = ['router']
