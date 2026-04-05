from __future__ import annotations

from fastapi import APIRouter, HTTPException, Header, Depends
import os
from typing import Dict, Any
from src.security.roles import require_admin_dep

router = APIRouter(prefix='/api/v1/admin/cooccurrence', tags=['Cooccurrence Admin'], dependencies=[Depends(require_admin_dep)])

try:
    from src.tasks.cooccurrence_pruner import start_background, stop_background  # type: ignore
    _PRUNER_AVAILABLE = True
except Exception:
    _PRUNER_AVAILABLE = False

ADMIN_KEY_ENV = 'ADMIN_API_KEY'

def _admin_ok(x_admin_key: str | None) -> bool:
    expected = os.getenv(ADMIN_KEY_ENV)
    return bool(expected) and x_admin_key == expected


@router.get('/pruner/status')
async def pruner_status(x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    return {'available': _PRUNER_AVAILABLE}


@router.post('/pruner/start')
async def pruner_start(x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    if not _PRUNER_AVAILABLE:
        raise HTTPException(status_code=404, detail='pruner_unavailable')
    try:
        start_background()
        return {'ok': True}
    except Exception:
        raise HTTPException(status_code=500, detail='start_failed')


@router.post('/pruner/stop')
async def pruner_stop(x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    if not _PRUNER_AVAILABLE:
        raise HTTPException(status_code=404, detail='pruner_unavailable')
    try:
        stop_background()
        return {'ok': True}
    except Exception:
        raise HTTPException(status_code=500, detail='stop_failed')


__all__ = ['router']
