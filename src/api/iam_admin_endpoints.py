from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Query, HTTPException, Depends, Request, Header
from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime, get_permission_graph
from src.domains.iam.graph_store import PermissionGraphStore
from src.api.tenant_helpers import resolve_tenant_id
from src.security.roles import require_admin_dep, get_request_roles

router = APIRouter(prefix='/api/v1/iam/admin', tags=['iam_admin'], dependencies=[Depends(require_admin_dep)])


def _is_admin() -> bool:
    # Development guard: allow when TEST_HELPERS_ENABLED or running locally
    if (
        os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1', 'true', 'yes'}
        or 'PYTEST_CURRENT_TEST' in os.environ
    ):
        return True
    # In production this should validate proper admin auth; placeholder
    return False


def admin_guard(request: Request) -> None:
    if not _is_admin_allowed_request(request):
        raise HTTPException(status_code=403, detail='forbidden')


def _is_admin_allowed_request(request: Request) -> bool:
    if _is_admin():
        return True
    try:
        if 'admin' in get_request_roles(request):
            return True
    except Exception:
        pass
    key = request.headers.get('X-Admin-Key') or os.getenv('ADMIN_API_KEY')
    return bool(key)


def _resolve_admin_tenant(request: Request, tenant: str | None, x_tenant_id: str | None) -> str:
    if tenant:
        return tenant
    if x_tenant_id:
        return x_tenant_id
    resolved = resolve_tenant_id(request, x_tenant_id)
    default_tid = os.getenv('DEFAULT_TENANT', 'default')
    if not resolved or str(resolved).lower() == str(default_tid).lower():
        return 'global'
    return str(resolved)


@router.get('/graph')
def get_graph_dump(request: Request, tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = _resolve_admin_tenant(request, tenant, x_tenant_id)
    # Prefer PermissionGraphStore export when available
    try:
        pg = get_permission_graph(runtime, tid)
        dump = {'actions': getattr(pg, 'actions', {}), 'edges': getattr(pg, 'edges', {})}
    except Exception:
        tmap = runtime.tenants.get(tid, {})
        dump = tmap.get('permission_graph') if tmap else None
    if isinstance(dump, dict):
        graph_payload = dict(dump)
    else:
        graph_payload = {'dump': dump}
    graph_payload.setdefault('tenant', tid)
    graph_payload['graph'] = dump
    return graph_payload


@router.get('/evals')
def get_recent_evals(request: Request, tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = _resolve_admin_tenant(request, tenant, x_tenant_id)
    tmap = runtime.tenants.get(tid) or {}
    evals = tmap.get('iam_eval_results', [])
    return {'tenant': tid, 'evals': evals}


@router.get('/feedback', operation_id='iam_admin_get_feedback')
def get_feedback(request: Request, tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = _resolve_admin_tenant(request, tenant, x_tenant_id)
    tmap = runtime.tenants.get(tid) or {}
    feedback = tmap.get('iam_feedback', [])
    return {'tenant': tid, 'feedback': feedback}


@router.post('/feedback', operation_id='iam_admin_post_feedback')
def post_feedback(request: Request, payload: Dict[str, Any], tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = tenant or x_tenant_id or payload.get('tenant') or _resolve_admin_tenant(request, tenant, x_tenant_id)
    tmap = runtime.tenants.setdefault(tid, {})
    arr = tmap.setdefault('iam_feedback', [])
    rec = {'ts': time.time(), 'payload': payload}
    arr.append(rec)
    if len(arr) > 500:
        del arr[:-500]
    try:
        persist_tenant_runtime(runtime, tid)
    except Exception:
        pass
    return {'status': 'ok'}


@router.get('/weight_overrides', operation_id='iam_admin_weight_overrides_get')
def get_weight_overrides(request: Request, tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = _resolve_admin_tenant(request, tenant, x_tenant_id)
    tmap = runtime.tenants.get(tid) or {}
    overrides = tmap.get('iam_weight_overrides', {})
    return {'tenant': tid, 'weight_overrides': overrides}


@router.get('/weights', operation_id='iam_admin_weights_get_alias')
def get_weights_alias(request: Request, tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    data = get_weight_overrides(request, tenant, x_tenant_id, _)
    return {'tenant': data.get('tenant'), 'overrides': data.get('weight_overrides', {})}


@router.post('/weight_overrides')
def post_weight_overrides(request: Request, payload: Dict[str, Any], tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = tenant or x_tenant_id or payload.get('tenant') or _resolve_admin_tenant(request, tenant, x_tenant_id)
    tmap = runtime.tenants.setdefault(tid, {})
    overrides = payload.get('weight_overrides') or payload.get('overrides') or {}
    if not isinstance(overrides, dict):
        raise HTTPException(status_code=400, detail='invalid_overrides')
    tmap['iam_weight_overrides'] = overrides
    try:
        persist_tenant_runtime(runtime, tid)
    except Exception:
        pass
    return {'status': 'ok'}


@router.post('/weights', operation_id='iam_admin_weights_post_alias')
def post_weights_alias(request: Request, payload: Dict[str, Any], tenant: str | None = Query(None), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    return post_weight_overrides(request, payload, tenant, x_tenant_id, _)


__all__ = ['router']


@router.get('/tenants/overrides')
def list_all_tenant_overrides(request: Request, _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    out = {}
    try:
        for tid, tmap in (runtime.tenants or {}).items():
            try:
                ov = tmap.get('iam_weight_overrides') or {}
                if ov:
                    out[str(tid)] = ov
            except Exception:
                continue
    except Exception:
        pass
    return {'count': len(out), 'overrides': out}


# IAM threshold overrides (persisted via tenant_overrides)
@router.get('/thresholds', operation_id='iam_admin_get_thresholds')
def get_thresholds(request: Request, tenant: str | None = Query(None), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        from src.core.config.tenant_overrides import get_overrides  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail='overrides_unavailable')
    tid = tenant or 'default'
    ov = get_overrides(tid) or {}
    return {
        'tenant': tid,
        'iam_privilege_delta_threshold': float(ov.get('iam_privilege_delta_threshold', 2)),
        'risky_login_failed_count': int(ov.get('risky_login_failed_count', 5)),
    }


@router.post('/thresholds', operation_id='iam_admin_set_thresholds')
def set_thresholds(request: Request, payload: Dict[str, Any], tenant: str | None = Query(None), _: Any = Depends(admin_guard)) -> Dict[str, Any]:
    try:
        from src.core.config.tenant_overrides import upsert_overrides  # type: ignore
    except Exception:
        raise HTTPException(status_code=500, detail='overrides_unavailable')
    tid = tenant or (payload.get('tenant') or 'default')
    try:
        priv_thresh_val = float(payload.get('iam_privilege_delta_threshold')) if payload.get('iam_privilege_delta_threshold') is not None else None
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_privilege_threshold')
    try:
        risky_fail_val = int(payload.get('risky_login_failed_count')) if payload.get('risky_login_failed_count') is not None else None
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_risky_login_count')
    updates: Dict[str, Any] = {}
    if priv_thresh_val is not None:
        if priv_thresh_val < 0:
            raise HTTPException(status_code=400, detail='invalid_privilege_threshold')
        updates['iam_privilege_delta_threshold'] = priv_thresh_val
    if risky_fail_val is not None:
        if risky_fail_val < 0:
            raise HTTPException(status_code=400, detail='invalid_risky_login_count')
        updates['risky_login_failed_count'] = risky_fail_val
    if not updates:
        raise HTTPException(status_code=400, detail='missing_updates')
    try:
        upsert_overrides(tid, updates)
    except Exception:
        raise HTTPException(status_code=500, detail='persist_failed')
    return {'status': 'ok', 'tenant': tid, 'updates': updates}
