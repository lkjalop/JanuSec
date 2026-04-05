"""Expose API stage benchmark artifacts + pipeline metadata."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.security.auth import auth_dependency
from src.core.pipeline.api_stage_profiles import load_manifest_entries, load_pipeline_profile_map

router = APIRouter(tags=["Performance"])


@router.get("/api/v1/perf/api_stage/artifacts")
async def list_api_stage_artifacts(
    limit: int = Query(5, ge=1, le=50),
    include_profiles: bool = Query(False, alias="include_profiles"),
    _auth=Depends(auth_dependency),
) -> dict:
    entries = load_manifest_entries()
    payload = {"artifacts": entries[:limit]}
    if include_profiles:
        payload["pipeline_profiles"] = load_pipeline_profile_map(None)
    return payload


__all__ = ["router"]
