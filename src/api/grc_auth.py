"""Authenticated, tenant-owned access to legacy GRC and evidence reports."""
from __future__ import annotations
from fastapi import Header, HTTPException, Request
from src.security.auth import auth_dependency
from src.api.tenant_helpers import resolve_tenant_id


async def require_report_access(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    authorization: str | None = Header(None),
):
    auth = await auth_dependency(x_api_key, authorization, ["grc:read"])
    tenant_id = resolve_tenant_id(request, auth=auth)
    if not tenant_id:
        raise HTTPException(403, "tenant_id_required")
    assessment_id = request.path_params.get("assessment_id")
    if assessment_id:
        from src.api.report_endpoints import _load_persisted_assessment_report_data
        _, assessment = _load_persisted_assessment_report_data(assessment_id, tenant_id)
        if not assessment:
            raise HTTPException(404, "assessment_not_found")
    return auth
