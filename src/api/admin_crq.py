from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from pathlib import Path
import json
from typing import Dict, Any
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/crq', tags=['admin'], dependencies=[Depends(require_roles('admin'))])
P = Path('data')
P.mkdir(parents=True, exist_ok=True)
OWNERS_FILE = P / 'crq_owners.json'
WEIGHTS_FILE = P / 'scoring_weights.json'

def _load(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8') or '{}')
    except Exception:
        pass
    return {}

def _save(path: Path, obj: Dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(obj), encoding='utf-8')
    except Exception:
        pass

@router.get('/owners')
def get_owners():
    return _load(OWNERS_FILE)

@router.post('/owners')
def set_owner_priors(owner_id: str, slef: float | None = None, slm: float | None = None):
    data = _load(OWNERS_FILE)
    rec = data.get(owner_id, {})
    if slef is not None:
        rec['slef'] = float(slef)
    if slm is not None:
        rec['slm'] = float(slm)
    data[owner_id] = rec
    _save(OWNERS_FILE, data)
    return {'ok': True}

@router.get('/weights')
def get_weights():
    return _load(WEIGHTS_FILE)

@router.post('/weights')
def set_weights(payload: Dict[str, Any]):
    _save(WEIGHTS_FILE, payload or {})
    return {'ok': True}

__all__ = ['router']
