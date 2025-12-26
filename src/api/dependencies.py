from __future__ import annotations

import os
from typing import Optional
from threading import Lock

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
    # Robust resolution: scan loaded modules for any existing PlatformState
    # instance so different import aliases still converge to a single runtime
    # object under pytest/import-time aliasing scenarios.
    try:
        import sys as _sys
        for m in list(_sys.modules.values()):
            try:
                if not m:
                    continue
                ps = getattr(m, '_PLATFORM_STATE', None)
                if isinstance(ps, PlatformState):
                    try:
                        if 'PYTEST_CURRENT_TEST' in __import__('os').environ or __import__('os').getenv('ALERTS_DEBUG','0').lower() in {'1','true','yes'}:
                            import sys as _sys2
                            try:
                                print(f'DBG_GET_PLATFORM_STATE returning module ps id={id(ps)} from module', file=_sys2.stderr)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    return ps
            except Exception:
                continue
    except Exception:
        pass
    try:
        if 'PYTEST_CURRENT_TEST' in __import__('os').environ or __import__('os').getenv('ALERTS_DEBUG','0').lower() in {'1','true','yes'}:
            import sys as _sys3
            try:
                print(f'DBG_GET_PLATFORM_STATE returning default _PLATFORM_STATE id={id(_PLATFORM_STATE)}', file=_sys3.stderr)
            except Exception:
                pass
    except Exception:
        pass
    return _PLATFORM_STATE


def get_canonical_alert_ring():
    """Return a canonical ALERT_RING container and lock tuple for cross-module use.

    This helper centralizes the canonical in-memory alert ring so all modules
    use a single shared instance regardless of import path or aliasing.
    """
    # Use attributes on the PlatformState instance to host the ring so it's
    # collocated with the canonical runtime. Create lazily if missing.
    try:
        # Prefer any existing PlatformState found in sys.modules
        import sys as _sys
        ps = None
        for m in list(_sys.modules.values()):
            try:
                if not m:
                    continue
                candidate = getattr(m, '_PLATFORM_STATE', None)
                if isinstance(candidate, PlatformState):
                    ps = candidate
                    break
            except Exception:
                continue
        if ps is None:
            ps = _PLATFORM_STATE
        ring = getattr(ps, '_alert_ring', None)
        lock = getattr(ps, '_alert_ring_lock', None)
        maxlen = getattr(ps, 'alert_max', None) or int(os.getenv('ALERT_RING_MAX','500'))
        if ring is None:
            ring = []
            try:
                setattr(ps, '_alert_ring', ring)
            except Exception:
                pass
        if lock is None:
            lock = Lock()
            try:
                setattr(ps, '_alert_ring_lock', lock)
            except Exception:
                pass
        return ring, lock, maxlen
    except Exception:
        # Fallback: create a local ring/lock (shouldn't happen normally)
        r = []
        l = Lock()
        return r, l, int(os.getenv('ALERT_RING_MAX','500'))


def get_tenant_context(x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id")) -> TenantContext:
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
