from fastapi import APIRouter, Request, HTTPException, Depends
import os
from typing import Any
from src.graph.auto_incident import register_auto_incident, _AUTO_SCANNER
from src.core.configuration import (
    get_scoring_config as _get_scoring_config,
    persist_scoring_config,
)
from src.security.roles import require_roles

router = APIRouter(dependencies=[Depends(require_roles('admin'))])

def _check_admin(req: Request):
    key = req.headers.get('x-api-key') or req.headers.get('X-API-Key')
    if not key:
        raise HTTPException(status_code=401, detail='unauthorized')
    if key != (os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')):
        raise HTTPException(status_code=403, detail='forbidden')


@router.get('/api/v1/admin/autogen/status')
async def autogen_status(request: Request):
    _check_admin(request)
    sc = _AUTO_SCANNER or register_auto_incident()
    return {
        'enabled': bool(sc and sc.enabled),
        'threshold': getattr(sc, 'threshold', None),
        'tenant_rate_max': getattr(sc, '_tenant_rate_max', None),
        'dedup_ttl': getattr(sc, '_dedup_ttl', None),
        'weights': _get_scoring_config().get('weights', {}),
    }


@router.post('/api/v1/admin/autogen/update')
async def autogen_update(request: Request, body: dict[str, Any]):
    _check_admin(request)
    sc = _AUTO_SCANNER or register_auto_incident()
    if sc is None:
        raise HTTPException(status_code=500, detail='scanner_not_initialized')
    # apply fields
    if 'enabled' in body:
        sc.enabled = bool(body.get('enabled'))
    if 'threshold' in body:
        try:
            sc.threshold = float(body.get('threshold') or sc.threshold)
        except Exception:
            pass
    if 'tenant_rate_max' in body:
        try:
            sc._tenant_rate_max = int(body.get('tenant_rate_max'))
        except Exception:
            pass
    if 'dedup_ttl' in body:
        try:
            sc._dedup_ttl = int(body.get('dedup_ttl'))
        except Exception:
            pass
    if 'weights' in body:
        try:
            persist_scoring_config({'weights': body.get('weights') or {}}, updated_by='autogen')
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f'invalid_weights:{exc}')
    return {'status': 'ok'}


@router.post('/api/v1/admin/autogen/trigger')
async def autogen_trigger(request: Request):
    _check_admin(request)
    sc = _AUTO_SCANNER or register_auto_incident()
    if sc is None:
        raise HTTPException(status_code=500, detail='scanner_not_initialized')
    # run a single scan (sync call)
    try:
        sc._scan_once()
        return {'status': 'ok'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
from fastapi import APIRouter, Request, HTTPException, Depends
import os, json

router = APIRouter(prefix='/api/v1/admin', dependencies=[Depends(require_roles('admin'))])


def _require_admin(req: Request):
    key = req.headers.get('x-api-key') or req.headers.get('X-API-Key')
    admin = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if not admin or key != admin:
        raise HTTPException(status_code=403, detail='forbidden')


@router.post('/scoring/weights')
async def set_scoring_weights(payload: dict, request: Request):
    _require_admin(request)
    try:
        persist_scoring_config({'weights': payload}, updated_by='admin_api')
        return {'ok': True, 'weights': _get_scoring_config().get('weights', {})}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f'internal_error:{exc}')


@router.post('/autogen/toggle')
async def toggle_autogen(request: Request, enabled: bool):
    _require_admin(request)
    try:
        os.environ['INCIDENT_AUTOGEN_ENABLED'] = '1' if enabled else '0'
        return {'ok': True, 'enabled': enabled}
    except Exception:
        raise HTTPException(status_code=500, detail='unable_to_toggle')
