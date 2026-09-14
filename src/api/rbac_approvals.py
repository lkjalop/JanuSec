import os
import json
import time
from typing import Dict, Any

from fastapi import APIRouter, Request, HTTPException, Depends
from src.security.roles import require_roles


router = APIRouter(prefix="/api/v1/admin/approvals", tags=["admin-approvals"], dependencies=[Depends(require_roles('admin'))])

_STORE_PATH = os.environ.get("APPROVALS_STORE_PATH", os.path.join("data", "approvals.json"))


def _load() -> Dict[str, Any]:
    try:
        if not os.path.exists(_STORE_PATH):
            return {"items": []}
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"items": []}


def _save(store: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    with open(_STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)


def _now() -> int:
    return int(time.time())


def _role(req: Request) -> str:
    return (req.headers.get("X-Role") or req.headers.get("x-role") or "analyst").lower()


def _require_api_key(req: Request) -> None:
    key = req.headers.get("x-api-key") or req.headers.get("X-API-Key")
    expected = os.environ.get("ADMIN_API_KEY") or os.environ.get("API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="admin_api_key_not_configured")
    if not key or key != expected:
        raise HTTPException(status_code=401, detail="invalid_api_key")


@router.get("")
async def list_approvals(req: Request):
    _require_api_key(req)
    store = _load()
    return {"items": store.get("items", [])}


@router.post("/request")
async def request_approval(req: Request):
    _require_api_key(req)
    try:
        body = await req.json()
    except Exception:
        body = {}
    action = body.get("action") or ""
    resource = body.get("resource") or ""
    role_required = (body.get("role_required") or "incident_commander").lower()
    requested_by = body.get("requested_by") or _role(req)
    if not action or not resource:
        raise HTTPException(status_code=400, detail="missing_fields")
    store = _load()
    iid = f"a-{_now()}-{len(store.get('items', []))+1}"
    item = {
        "id": iid,
        "action": action,
        "resource": resource,
        "role_required": role_required,
        "status": "pending",
        "requested_by": requested_by,
        "created_ts": _now(),
    }
    store.setdefault("items", []).append(item)
    _save(store)
    return {"ok": True, "approval": item}


@router.post("/{approval_id}/approve")
async def approve(approval_id: str, req: Request):
    _require_api_key(req)
    role = _role(req)
    if role not in ("incident_commander", "admin"):
        raise HTTPException(status_code=403, detail="insufficient_role")
    store = _load()
    items = store.get("items", [])
    found = None
    for it in items:
        if str(it.get("id")) == approval_id:
            found = it
            break
    if not found:
        raise HTTPException(status_code=404, detail="not_found")
    found["status"] = "approved"
    found["approved_by"] = role
    found["approved_ts"] = _now()
    _save(store)
    return {"ok": True, "approval": found}


@router.post("/{approval_id}/reject")
async def reject(approval_id: str, req: Request):
    _require_api_key(req)
    role = _role(req)
    if role not in ("incident_commander", "admin"):
        raise HTTPException(status_code=403, detail="insufficient_role")
    store = _load()
    items = store.get("items", [])
    found = None
    for it in items:
        if str(it.get("id")) == approval_id:
            found = it
            break
    if not found:
        raise HTTPException(status_code=404, detail="not_found")
    found["status"] = "rejected"
    found["approved_by"] = role
    found["approved_ts"] = _now()
    _save(store)
    return {"ok": True, "approval": found}
