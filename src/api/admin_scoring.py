from __future__ import annotations

import os
import json
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Depends
from src.core.configuration import persist_scoring_config, scoring_config_path
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/scoring', tags=['Admin Scoring'], dependencies=[Depends(require_roles('admin'))])


def _load_record() -> Dict[str, Any]:
    path = scoring_config_path()
    if not os.path.exists(path):
        return {'version': 0, 'weights': {}, 'adaptive_ewma': {}, 'history': []}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh) or {}
    except Exception:
        return {'version': 0, 'weights': {}, 'adaptive_ewma': {}, 'history': []}
    if not isinstance(data, dict):
        return {'version': 0, 'weights': {}, 'adaptive_ewma': {}, 'history': []}
    data.setdefault('weights', {})
    data.setdefault('adaptive_ewma', {})
    data.setdefault('history', [])
    data['version'] = int(data.get('version', 0) or 0)
    return data


@router.get('/get')
async def get_weights() -> Dict[str, Any]:
    return _load_record()


@router.post('/update')
async def update_weights(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    api_key = request.headers.get('x-api-key')
    # Basic protection: require admin key when present
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if admin_key and api_key != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')
    new_weights = payload.get('weights')
    if not isinstance(new_weights, dict):
        raise HTTPException(status_code=400, detail='invalid_weights')
    persist_scoring_config({'weights': new_weights}, updated_by=api_key or 'unknown')
    return _load_record()


@router.get('/versions')
async def list_versions() -> Dict[str, Any]:
    rec = _load_record()
    return {'current_version': rec.get('version',0), 'history': rec.get('history',[])}


@router.post('/diff')
async def diff_weights(payload: Dict[str, Any]) -> Dict[str, Any]:
    base = payload.get('base')
    other = payload.get('other')
    if base is None or other is None:
        raise HTTPException(status_code=400, detail='missing_base_or_other')
    # base/other are weight maps
    diffs = {}
    keys = set(list(base.keys())+list(other.keys()))
    for k in keys:
        a = float(base.get(k,0) or 0)
        b = float(other.get(k,0) or 0)
        diffs[k] = {'base':a,'other':b,'delta':round(b-a,4)}
    return {'diffs':diffs}


@router.post('/rollback')
async def rollback_to(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    api_key = request.headers.get('x-api-key')
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if admin_key and api_key != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')
    target = payload.get('version')
    if target is None:
        raise HTTPException(status_code=400, detail='missing_version')
    record = _load_record()
    hist = record.get('history',[])
    # find matching
    chosen = next((h for h in hist if h.get('version') == target), None)
    if chosen is None or not isinstance(chosen, dict):
        raise HTTPException(status_code=404, detail='version_not_found')
    persist_scoring_config({'weights': chosen.get('weights', chosen)}, updated_by=api_key or 'rollback')
    return _load_record()
