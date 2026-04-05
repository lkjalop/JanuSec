from __future__ import annotations

from fastapi import HTTPException, Request
import os


def resolve_tenant_id(request: Request | None, tenant_id: str | None = None) -> str | None:
    """Resolve tenant_id from request state/header and enforce mismatch protection.

    Permissive behavior:
    - In lite/test contexts or for metrics endpoints, allow payload tenant override.
    - If middleware set the default tenant, allow override.
    """
    req_tenant = None
    path = ''
    if request is not None:
        try:
            req_tenant = getattr(request.state, "tenant_id", None)
        except Exception:
            req_tenant = None
        if not req_tenant:
            try:
                req_tenant = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
            except Exception:
                req_tenant = None
        try:
            path = request.url.path or ''
        except Exception:
            path = ''

    default_tid = os.getenv('DEFAULT_TENANT', 'default')
    lite_or_test = (
        os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1','true','yes'} or
        os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1','true','yes'} or
        ('PYTEST_CURRENT_TEST' in os.environ)
    )
    is_metrics_path = path.startswith('/api/v1/metrics/') or path == '/metrics'

    if tenant_id and req_tenant and tenant_id != req_tenant:
        # Permit override when request tenant equals default or in permissive contexts
        if str(req_tenant) == str(default_tid) or lite_or_test or is_metrics_path:
            return tenant_id
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    return tenant_id or req_tenant


__all__ = ["resolve_tenant_id"]
