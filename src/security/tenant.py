"""Tenant utilities for multi-tenant scoping.

Extraction precedence:
1. Header `X-Tenant-ID`
2. Query param `tenant`
3. Fallback environment default TENANT_DEFAULT (default 'default')

NULL vs explicit 'default': We store 'default' for legacy traffic unless
explicitly configured to allow null; repository queries treat NULL as
legacy/global. New writes use provided tenant string; empty string coerced
to NULL.
"""
from __future__ import annotations

import os

from fastapi import Depends, Header, Request

TENANT_ENV_DEFAULT = os.getenv('TENANT_DEFAULT', 'default')

async def resolve_tenant(request: Request, x_tenant_id: str | None = Header(None)) -> str | None:
    tid = x_tenant_id or request.query_params.get('tenant') or TENANT_ENV_DEFAULT
    tid = tid.strip() if isinstance(tid, str) else tid
    if not tid:
        return None
    # Basic guard: limit length
    if len(tid) > 64:
        tid = tid[:64]
    # Optionally restrict charset (alnum, dash, underscore)
    import re
    if not re.match(r'^[A-Za-z0-9_.-]+$', tid):
        # Sanitize invalid chars to dash
        tid = re.sub(r'[^A-Za-z0-9_.-]', '-', tid)
    # Attach to request.state
    try:
        request.state.tenant_id = tid
    except Exception:
        pass
    return tid

def tenant_dep():  # convenience wrapper for Depends
    return Depends(resolve_tenant)
