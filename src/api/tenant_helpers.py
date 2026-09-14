from __future__ import annotations

import os
import re
from typing import Any

from fastapi import HTTPException, Request


_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRUE_VALUES = {"1", "true", "yes", "on"}
_WINDOWS_RESERVED_COMPONENTS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def validate_tenant_id(value: str | None, *, required: bool = False) -> str | None:
    """Return a normalized tenant id or raise a stable client error.

    Tenant ids are used as cache, database, and (in a few legacy paths)
    filesystem partition keys. Treating them as unvalidated strings weakens
    every one of those boundaries, so use one small portable alphabet.
    """

    if value is None or not str(value).strip():
        if required:
            raise HTTPException(status_code=400, detail="tenant_id_required")
        return None
    tenant = str(value).strip()
    if (
        not _TENANT_ID_RE.fullmatch(tenant)
        or tenant in {".", ".."}
        or tenant.endswith(".")
        or tenant.split(".", 1)[0].upper() in _WINDOWS_RESERVED_COMPONENTS
    ):
        raise HTTPException(status_code=400, detail="invalid_tenant_id")
    return tenant


def tenant_override_allowed() -> bool:
    """Whether a payload may override the request's authenticated tenant.

    The compatibility gate is explicit and cannot operate in production.
    Pytest, lite mode, or a default tenant never disables the BOLA boundary.
    """

    enabled = os.getenv("ALLOW_TENANT_OVERRIDE", "0").strip().lower() in _TRUE_VALUES
    profile = (
        os.getenv("JANUSEC_RUNTIME_PROFILE")
        or os.getenv("APP_ENV")
        or os.getenv("ENV")
        or "production"
    ).strip().lower()
    return enabled and profile in {"test", "demo", "dev", "development", "local"}


def resolve_tenant_id(
    request: Request | None,
    tenant_id: str | None = None,
    auth: Any | None = None,
) -> str | None:
    """Resolve tenant scope and reject payload/request mismatches by default.

    Request state/header is the authenticated transport scope. A body or query
    tenant is only a consistency assertion; it cannot select another tenant
    unless the explicit non-production compatibility gate is enabled.
    """

    req_tenant = None
    auth_context = auth
    if request is not None:
        try:
            req_tenant = getattr(request.state, "tenant_id", None)
            if auth_context is None:
                auth_context = getattr(request.state, "auth", None)
        except Exception:
            req_tenant = None
        if not req_tenant:
            try:
                req_tenant = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
            except Exception:
                req_tenant = None

    requested = validate_tenant_id(tenant_id)
    resolved_request = validate_tenant_id(req_tenant)
    auth_tenant = validate_tenant_id(getattr(auth_context, "tenant_id", None))
    if auth_tenant:
        if requested and requested != auth_tenant:
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        if resolved_request and resolved_request != auth_tenant:
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        return auth_tenant
    if requested and resolved_request and requested != resolved_request:
        if tenant_override_allowed():
            return requested
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    return requested or resolved_request


def resolve_tenant_with_default(request: Request | None, fallback: str | None = None) -> str | None:
    """Resolve the transport tenant, optionally falling back when policy allows.

    Unlike the legacy implementation, this function does not swallow its own
    ``tenant_id_required`` exception. Request state is authoritative when set.
    """

    raw = None
    if request is not None:
        try:
            raw = getattr(request.state, "tenant_id", None)
        except Exception:
            raw = None
        if not raw:
            raw = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id")
    if raw:
        return validate_tenant_id(raw, required=True)

    configured_default = os.getenv("ALLOW_DEFAULT_TENANT")
    if configured_default is not None:
        # An explicit 0 must win even under pytest so fail-closed behavior can
        # be tested and production operators can disable compatibility modes.
        allow_default = configured_default.strip().lower() in _TRUE_VALUES
    else:
        profile = (
            os.getenv("JANUSEC_RUNTIME_PROFILE")
            or os.getenv("APP_ENV")
            or os.getenv("ENV")
            or ""
        ).strip().lower()
        allow_default = profile in {"test", "demo", "dev", "development", "local"}
        allow_default = allow_default or "PYTEST_CURRENT_TEST" in os.environ
    if not allow_default:
        raise HTTPException(status_code=400, detail="tenant_id_required")
    candidate = fallback if fallback is not None else os.getenv("DEFAULT_TENANT", "default")
    return validate_tenant_id(candidate, required=True)


__all__ = [
    "resolve_tenant_id",
    "resolve_tenant_with_default",
    "tenant_override_allowed",
    "validate_tenant_id",
]
