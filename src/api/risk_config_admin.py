from __future__ import annotations
from fastapi import APIRouter, HTTPException, Header, Request, Depends
from security.auth import require_scopes  # type: ignore
from typing import Optional
from src.config import risk_loader
import json, os
from src.security.roles import require_roles

router = APIRouter(prefix="/api/v1/risk-config", tags=["Risk Config"], dependencies=[Depends(require_roles('admin'))])

ADMIN_KEY_ENV = "ADMIN_API_KEY"


def _check_admin(x_admin_key: Optional[str]):
    expected = os.environ.get(ADMIN_KEY_ENV)
    if expected and x_admin_key != expected:
        raise HTTPException(status_code=403, detail="forbidden")

@router.get("/")
async def get_risk_config(request: Request, x_admin_key: Optional[str] = Header(None), auth=Depends(require_scopes('risk.read'))):  # type: ignore[misc]
    _check_admin(x_admin_key)
    resp = {"config": risk_loader.current_config(), "hash": risk_loader.config_hash()}
    try:
        from src.api.server import audit_emit, audit_user  # type: ignore
        audit_emit('risk_config_get', audit_user(request, auth), {'hash': resp['hash']})
    except Exception:
        pass
    return resp

@router.post("/reload")
async def reload_risk_config(request: Request, x_admin_key: Optional[str] = Header(None), auth=Depends(require_scopes('risk.write'))):  # type: ignore[misc]
    _check_admin(x_admin_key)
    cfg = risk_loader.reload_config()
    resp = {"status": "ok", "hash": risk_loader.config_hash(), "config": cfg}
    try:
        from src.api.server import audit_emit, audit_user  # type: ignore
        audit_emit('risk_config_reload', audit_user(request, auth), {'hash': resp['hash']})
    except Exception:
        pass
    return resp

@router.post("/update")
async def update_risk_config(payload: dict, request: Request, x_admin_key: Optional[str] = Header(None), auth=Depends(require_scopes('risk.write'))):  # type: ignore[misc]
    _check_admin(x_admin_key)
    path = risk_loader.get_config_path()
    # simple overwrite with validation
    cur = risk_loader.current_config()
    new_cfg = {**cur, **payload}
    # naive merge for nested dicts
    for k,v in payload.items():
        if isinstance(v, dict) and isinstance(cur.get(k), dict):
            nv = {**cur.get(k, {}), **v}
            new_cfg[k] = nv
    # write temp then move
    tmp = path + ".tmp"
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(new_cfg, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write_error:{e}")
    risk_loader.reload_config()
    resp = {"status": "ok", "hash": risk_loader.config_hash()}
    try:
        from src.api.server import audit_emit, audit_user  # type: ignore
        audit_emit('risk_config_update', audit_user(request, auth), {'updated_keys': list(payload.keys()), 'hash': resp['hash']})
    except Exception:
        pass
    return resp
