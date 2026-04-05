from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Depends

from src.core.quality.factor_quality import get_quality_manager
from src.core.quality.factor_telemetry import load_factor_telemetry
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/admin/factors', tags=['Admin Factors'], dependencies=[Depends(require_roles('admin'))])


def _require_admin(request: Request) -> None:
    api_key = request.headers.get('x-admin-key') or request.headers.get('x-api-key')
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if admin_key and api_key != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')


@router.get('/telemetry')
async def get_factor_telemetry() -> Dict[str, Any]:
    """Return the latest telemetry snapshot for dashboards/admin panels."""
    manager = get_quality_manager()
    live_snapshot = manager.telemetry_snapshot()
    disk_snapshot = load_factor_telemetry()
    merged = dict(disk_snapshot or {})
    merged.update({k: v for k, v in live_snapshot.items() if v})
    return {'telemetry': merged}


@router.post('/context')
async def update_context_multipliers(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Allow admins to override context multipliers via API."""
    _require_admin(request)
    ctx = payload.get('context') or payload.get('context_multipliers')
    if not isinstance(ctx, dict):
        raise HTTPException(status_code=400, detail='invalid_context')
    manager = get_quality_manager()
    for marker, value in ctx.items():
        try:
            manager.set_context_multiplier(marker, float(value))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f'invalid_value:{marker}') from exc
    manager.persist(force=True)
    return {'ok': True, 'context_multipliers': manager.get_context_multipliers()}


@router.post('/observations')
async def update_factor_observations(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Upsert TP/FP counts for specific factors to seed priors."""
    _require_admin(request)
    observations = payload.get('observations')
    if not isinstance(observations, dict):
        raise HTTPException(status_code=400, detail='invalid_observations')
    manager = get_quality_manager()
    manager.apply_admin_observations(observations)
    manager.persist(force=True)
    return {'ok': True, 'telemetry': manager.telemetry_snapshot()}


@router.get('/calibration')
async def get_calibration_status(request: Request) -> Dict[str, Any]:
    """Return current calibration file and context multipliers (admin only)."""
    _require_admin(request)
    manager = get_quality_manager()
    return {
        'path': manager.calibration_path(),
        'context_multipliers': manager.get_context_multipliers(),
    }


@router.post('/calibration/reload')
async def reload_calibration(payload: Dict[str, Any] | None = None, request: Request = None) -> Dict[str, Any]:
    """Reload calibration JSON (or override path) to update priors."""
    _require_admin(request)
    manager = get_quality_manager()
    body = payload or {}
    config_payload = body.get('config')
    if not config_payload:
        ctx = {}
        if isinstance(body.get('context_multipliers'), dict):
            ctx['context_multipliers'] = body.get('context_multipliers')
        if isinstance(body.get('context'), dict):
            ctx.setdefault('context_multipliers', body.get('context'))
        if isinstance(body.get('observations'), dict):
            ctx['observations'] = body.get('observations')
        if ctx:
            config_payload = ctx
    if config_payload:
        manager.apply_calibration_dict(config_payload if isinstance(config_payload, dict) else None)
        manager.persist(force=True)
    else:
        path = body.get('path')
        ok = manager.reload_calibration_config(path)
        if not ok:
            raise HTTPException(status_code=400, detail='calibration_not_configured')
    return {'ok': True, 'path': manager.calibration_path(), 'telemetry': manager.telemetry_snapshot()}
