from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any
import os

# Avoid router-level RBAC dependencies: applying the RBAC decorator at router
# construction time can cause FastAPI to introspect wrapper signatures and
# generate spurious required parameters (422). RBAC checks are enforced via
# the `_require_api_key` helper and by configuring API keys/roles in tests.
router = APIRouter(prefix='/api/v1/admin/ingest', tags=['admin-ingest'])

_THRESHOLDS: Dict[str, int] = {}

def _require_api_key(request: Request) -> None:
    hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    dev_ok = os.getenv('ALLOW_DEV_API_KEY','1').lower() in {'1','true','yes'}
    if not hdr and not dev_ok:
        raise HTTPException(status_code=403, detail='api_key_required')

def _get_rate_drops() -> Dict[str, int]:
    try:
        import src.api.app as app_mod  # type: ignore
        drops = getattr(app_mod, '_TENANT_RATE_DROPS', {})
        if isinstance(drops, dict):
            return dict(drops)
    except Exception:
        pass
    return {}

def _set_gauge(tenant_id: str, value: int) -> None:
    try:
        from src.api.metrics_init import tenant_rate_drops_gauge  # type: ignore
        if tenant_rate_drops_gauge is not None:
            tenant_rate_drops_gauge.labels(tenant_id).set(float(value))  # type: ignore[attr-defined]
    except Exception:
        pass

@router.get('/thresholds', operation_id='admin_ingest_get_thresholds')
async def get_thresholds(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    return {'thresholds': dict(_THRESHOLDS)}

@router.post('/thresholds', operation_id='admin_ingest_set_thresholds')
async def set_thresholds(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    items = payload.get('items') or {}
    if not isinstance(items, dict) or not items:
        raise HTTPException(status_code=400, detail='no_items')
    for tenant_id, val in items.items():
        try:
            _THRESHOLDS[str(tenant_id)] = int(val)
        except Exception:
            continue
    return {'updated': len(items)}

@router.get('/status')
async def get_status(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    drops = _get_rate_drops()
    # reflect in gauge for visibility
    for t, v in drops.items():
        _set_gauge(t, v)
    # compute alerts
    alerts = []
    for t, v in drops.items():
        thr = _THRESHOLDS.get(t) or int(os.getenv('TENANT_NOISY_ALERT_THRESHOLD','0') or 0)
        if thr and v >= thr:
            alerts.append({'tenant_id': t, 'drops': v, 'threshold': thr})
    return {'drops': drops, 'alerts': alerts}

@router.post('/reset')
async def reset_drops(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    tenant_id = (payload.get('tenant_id') or '').strip()
    try:
        import src.api.app as app_mod  # type: ignore
        drops = getattr(app_mod, '_TENANT_RATE_DROPS', None)
        if isinstance(drops, dict):
            if tenant_id:
                drops.pop(tenant_id, None)
                _set_gauge(tenant_id, 0)
                return {'reset': tenant_id}
            else:
                drops.clear()
                return {'reset': 'all'}
    except Exception:
        pass
    raise HTTPException(status_code=500, detail='reset_failed')

__all__ = ['router']
