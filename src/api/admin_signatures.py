from __future__ import annotations

import os
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Request, Depends

try:
    from signatures.config_store import load_signatures, set_signatures  # type: ignore
except Exception:
    from src.signatures.config_store import load_signatures, set_signatures  # type: ignore
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/signatures', tags=['Admin Signatures'], dependencies=[Depends(require_roles('admin'))])

def _require_admin(request: Request):
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if admin_key and request.headers.get('x-api-key') != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')

@router.get('/get')
async def get_signatures() -> Dict[str, Any]:
    return {'config': load_signatures()}

@router.post('/set')
async def set_signatures_endpoint(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_admin(request)
    cfg = payload.get('config')
    if not isinstance(cfg, dict):
        raise HTTPException(status_code=400, detail='invalid_config')
    try:
        updated = set_signatures(cfg)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {'ok': True, 'config': updated}
