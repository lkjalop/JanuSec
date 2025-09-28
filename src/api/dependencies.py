from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, Header, HTTPException

from .schemas import TenantContext
from .state import PlatformState

_COST_PER_EVENT = float(os.getenv('COST_PER_EVENT', '0.001'))
_COST_HEAVY_EVENT = float(os.getenv('COST_HEAVY_EVENT', '0.01'))
_ROLLUP_WINDOW = int(os.getenv('ROLLUP_WINDOW_SECONDS', '300'))
_CACHE_MAX = int(os.getenv('DECISION_CACHE_MAX', '5000'))
_ALERT_RING_MAX = int(os.getenv('ALERT_RING_MAX', '500'))

_PLATFORM_STATE = PlatformState(
    cache_size=_CACHE_MAX,
    alert_max=_ALERT_RING_MAX,
    cost_per_event=_COST_PER_EVENT,
    cost_heavy_event=_COST_HEAVY_EVENT,
    rollup_window_seconds=_ROLLUP_WINDOW,
)


def get_platform_state() -> PlatformState:
    return _PLATFORM_STATE


def get_tenant_context(x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id")) -> TenantContext:
    allow_default = os.getenv('ALLOW_DEFAULT_TENANT', '1').lower() not in {'0', 'false', 'no'}
    raw = x_tenant_id.strip() if x_tenant_id else None
    if raw:
        tenant = raw
    else:
        if not allow_default:
            raise HTTPException(status_code=400, detail='tenant_id_required')
        tenant = os.getenv('DEFAULT_TENANT', 'public').strip() or 'public'
    if len(tenant) > 64:
        raise HTTPException(status_code=400, detail='tenant_id_too_long')
    return TenantContext(tenant_id=tenant, raw_header=x_tenant_id)
