import os
import json
import time
from typing import Dict, Any, List

from fastapi import APIRouter, Request, HTTPException, Depends
from src.security.roles import require_roles


router = APIRouter(prefix="/api/v1/admin/suppression", tags=["admin-suppression"], dependencies=[Depends(require_roles('admin'))])

_STORE_PATH = os.environ.get("SUPPRESSION_STORE_PATH", os.path.join("data", "suppression_rules.json"))


def _load_store() -> Dict[str, Any]:
    try:
        if not os.path.exists(_STORE_PATH):
            return {"rules": [], "audit": []}
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"rules": [], "audit": []}


def _save_store(store: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    with open(_STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)


def _now() -> int:
    return int(time.time())


def _require_api_key(req: Request) -> None:
    key = req.headers.get("x-api-key") or req.headers.get("X-API-Key")
    expected = os.environ.get("ADMIN_API_KEY") or os.environ.get("API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="admin_api_key_not_configured")
    if not key or key != expected:
        raise HTTPException(status_code=401, detail="invalid_api_key")


def _prune_expired(store: Dict[str, Any]) -> None:
    now = _now()
    rules = store.get("rules", [])
    active: List[Dict[str, Any]] = []
    for r in rules:
        exp = r.get("expires_ts")
        if exp is None or int(exp) > now:
            active.append(r)
    store["rules"] = active


@router.get("/rules", operation_id='suppression_list_rules')
async def list_rules(req: Request):
    _require_api_key(req)
    store = _load_store()
    _prune_expired(store)
    return {"rules": store.get("rules", [])}


@router.post("/rules")
async def add_rule(req: Request):
    _require_api_key(req)
    body = None
    try:
        body = await req.json()
    except Exception:
        body = {}
    rule_type = str(body.get("type", "")).strip()
    value = str(body.get("value", "")).strip()
    ttl = body.get("ttl_seconds")
    reason = body.get("reason") or ""
    actor = body.get("actor") or "unknown"
    if not rule_type or not value:
        raise HTTPException(status_code=400, detail="missing_fields")
    if ttl is not None:
        try:
            ttl = int(ttl)
            if ttl < 0:
                raise ValueError()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_ttl")
    store = _load_store()
    rid = f"r-{_now()}-{len(store.get('rules', []))+1}"
    new_rule = {
        "id": rid,
        "type": rule_type,
        "value": value,
        "reason": reason,
        "actor": actor,
        "created_ts": _now(),
        "expires_ts": (_now() + int(ttl)) if ttl is not None else None,
    }
    store.setdefault("rules", []).append(new_rule)
    store.setdefault("audit", []).append({
        "ts": _now(),
        "action": "add_rule",
        "rule_id": rid,
        "actor": actor,
        "meta": {"type": rule_type, "value": value, "ttl_seconds": ttl, "reason": reason},
    })
    _save_store(store)
    return {"ok": True, "rule": new_rule}


@router.delete("/rules/{rid}", operation_id='suppression_delete_rule')
async def delete_rule(rid: str, req: Request):
    _require_api_key(req)
    store = _load_store()
    rules = store.get("rules", [])
    new_rules = [r for r in rules if str(r.get("id")) != rid]
    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail="not_found")
    store["rules"] = new_rules
    actor = req.headers.get("X-Actor") or "unknown"
    store.setdefault("audit", []).append({
        "ts": _now(),
        "action": "delete_rule",
        "rule_id": rid,
        "actor": actor,
    })
    _save_store(store)
    return {"ok": True}


@router.get("/audit")
async def list_audit(req: Request):
    _require_api_key(req)
    store = _load_store()
    return {"audit": store.get("audit", [])}
