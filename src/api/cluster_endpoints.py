"""Cluster Tier-1 prefill endpoints.

Routes:
  POST /api/v1/assessments/{aid}/tier1-prefill
      Run Tier-1 prefill on top-N clusters (auto-called after pipeline).

  POST /api/v1/assessments/{aid}/clusters/{cid}/tier1-summary
      On-demand Tier-1 for a single cluster (clusters 4+).
"""
from __future__ import annotations

import asyncio
import sys
from typing import List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .exec_summary_endpoints import _get_assessment, _persist, _get_tenant  # noqa: F401

router = APIRouter(prefix='/api/v1/assessments', tags=['breach'])


def _legacy_helper(name: str, fallback):
    mod = sys.modules.get('src.api.breach_endpoints') or sys.modules.get('api.breach_endpoints')
    value = getattr(mod, name, None) if mod is not None else None
    return value if callable(value) else fallback


# ── Request models ─────────────────────────────────────────────────────────────

class PrefillRequest(BaseModel):
    model: str = 'qwen3:14b'
    top_n: int = Field(default=3, ge=1, le=10)
    force: bool = False


class SingleSummaryRequest(BaseModel):
    model: str = 'qwen3:14b'
    force: bool = False


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post('/{assessment_id}/tier1-prefill')
async def trigger_tier1_prefill(
    assessment_id: str,
    body: PrefillRequest,
    request: Request,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    tenant_id = _get_tenant(request)

    try:
        from src.core.tier1_prefill.prefill_engine import run_prefill
    except ImportError:
        from core.tier1_prefill.prefill_engine import run_prefill  # type: ignore

    result = await asyncio.to_thread(
        run_prefill,
        assessment,
        body.top_n,
        body.model,
        tenant_id,
        body.force,
    )
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    return JSONResponse({
        'assessment_id': assessment_id,
        **result,
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/tier1-summary')
async def tier1_single_summary(
    assessment_id: str,
    cluster_id: str,
    body: SingleSummaryRequest,
    request: Request,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    tenant_id = _get_tenant(request)

    try:
        from src.core.tier1_prefill.prefill_engine import run_single_cluster_prefill
    except ImportError:
        from core.tier1_prefill.prefill_engine import run_single_cluster_prefill  # type: ignore

    result = await asyncio.to_thread(
        run_single_cluster_prefill,
        assessment,
        cluster_id,
        body.model,
        tenant_id,
        body.force,
    )
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    if result.get('status') == 'not_found':
        raise HTTPException(status_code=404, detail='cluster_not_found')

    return JSONResponse({'assessment_id': assessment_id, **result})
