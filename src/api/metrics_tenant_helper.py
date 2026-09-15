"""Helper for registering tenant-aware metric labels with cardinality guard.

Usage: from src.api.metrics_tenant_helper import with_tenant_label
       labels = with_tenant_label(runtime, base_labels=['factor'], tenant=tid)
       if labels: _FACTOR_COUNTER.labels(**labels).inc()
"""
from __future__ import annotations
import os
from typing import Dict, Optional
from src.core.metrics.registry import normalize_emit_labels

def _tenant_count(runtime) -> int:
    try:
        return len(getattr(runtime, 'tenants', {}) or {})
    except Exception:
        return 0

def with_tenant_label(runtime, base: Dict[str, str], tenant: Optional[str] = None) -> Dict[str, str] | None:
    """Return a labels dict to pass to prometheus `.labels()` or None when
    tenant labeling should be avoided due to cardinality.

    Behavior:
      - If tenant is falsy, return base.
      - If METRICS_MAX_TENANTS env var present and current tenant count exceeds it,
        return base (no tenant label) to avoid label explosion.
      - Otherwise return base with tenant key added.
    """
    if not tenant:
        return base
    try:
        max_t = int(os.getenv('METRICS_MAX_TENANTS','50') or 50)
    except Exception:
        max_t = 50
    try:
        cur = _tenant_count(runtime)
    except Exception:
        cur = 0
    # Allow tenant label when within cap (including new tenant addition)
    if cur > max_t:
        return base
    labels = dict(base)
    labels['tenant'] = str(tenant)
    return labels


def emit_labels_with_guard(runtime, base: Dict[str, str], tenant: Optional[str] = None) -> Dict[str, str]:
    """Return a labels dict suitable for passing to metric.labels(...).

    This will consult with_tenant_label and always return a dict that
    contains a 'tenant' key (empty string when suppressed).
    """
    try:
        got = with_tenant_label(runtime, base, tenant)
    except Exception:
        got = dict(base or {})
    # normalize_emit_labels ensures tenant key exists and uses '' when None
    try:
        tval = None
        if isinstance(got, dict):
            tval = got.get('tenant')
        return normalize_emit_labels({k: v for k, v in (got or {}).items() if k != 'tenant'}, tval)
    except Exception:
        return normalize_emit_labels(base or {}, tenant)

__all__ = ['with_tenant_label','emit_labels_with_guard']
