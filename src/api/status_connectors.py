from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, Request

from src.api.runtime_state import get_server_runtime_state, get_connector_health
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/status")


def _runtime_projection(entry: Dict[str, Any], now: float) -> Dict[str, Any]:
    runtime_state = entry.get('runtime_state') or {}
    metadata = entry.get('metadata') or {}
    open_until = runtime_state.get('open_until')
    circuit_open = False
    try:
        circuit_open = bool(open_until and float(open_until) > now)
    except Exception:
        circuit_open = False
    return {
        'last_duplicate_count': entry.get('last_duplicate_count', metadata.get('last_duplicate_count', 0)),
        'last_latency_ms': entry.get('last_latency_ms', runtime_state.get('last_latency_ms')),
        'runtime_state': runtime_state,
        'circuit_open': circuit_open,
        'circuit_open_until': open_until,
    }


@router.get("/connectors")
def connectors_status(
    request: Request,
    tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
) -> Dict[str, Any]:
    runtime = get_server_runtime_state(request.app)
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or 'default'
    health = get_connector_health(runtime, tenant)
    now = time.time()
    connectors = []
    for name, entry in health.items():
        if not isinstance(entry, dict):
            continue
        connectors.append(
            {
                'name': name,
                'provider': entry.get('provider'),
                'healthy': bool(entry.get('ok', False)),
                'status': entry.get('status', 'unknown'),
                'last_ok_ts': entry.get('last_ok_ts'),
                'last_error': entry.get('last_error'),
                'last_poll_ts': entry.get('last_poll_ts'),
                'last_count': entry.get('last_count', 0),
                'checkpoint': entry.get('checkpoint') or {},
                'seconds_since_ok': (now - float(entry.get('last_ok_ts'))) if entry.get('last_ok_ts') else None,
                **_runtime_projection(entry, now),
            }
        )
    return {
        'tenant': tenant,
        'connectors': connectors,
        'dependency_status': {
            'redis': {'healthy': True},
            'runtime_state': {'healthy': True},
        },
    }
