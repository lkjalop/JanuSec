"""Breach assessment endpoints — thin compatibility shim.

All route logic has moved to focused submodules:
  exec_summary_endpoints  — shared helpers + /executive-summary
  cluster_endpoints       — /tier1-prefill + /tier1-summary
  dispatch_endpoints      — persona-dispatch, sign-off, further-tasks,
                            timeline, notes, iocs, repeat-entities

Import from this module continues to work for backward compatibility.
"""
from fastapi import APIRouter

from .exec_summary_endpoints import router as _exec_router
from .cluster_endpoints import router as _cluster_router
from .dispatch_endpoints import router as _dispatch_router

router = APIRouter()
router.include_router(_exec_router)
router.include_router(_cluster_router)
router.include_router(_dispatch_router)

# Re-export shared helpers so legacy importers that do
# `from src.api.breach_endpoints import _get_assessment` keep working.
from .exec_summary_endpoints import (  # noqa: F401
    _get_assessment,
    _get_llm,
    _persist,
    _get_tenant,
)
from .dispatch_endpoints import tag_kill_chain_phase  # noqa: F401


def _cluster_rows(cluster, assessment):
    """Compatibility helper for legacy importers of breach_endpoints."""
    try:
        from src.core.tier1_prefill.prefill_engine import _get_rows_for_cluster
        return _get_rows_for_cluster(cluster, assessment)
    except Exception:
        rows = []
        try:
            refs = set(cluster.get('row_refs') or cluster.get('row_indices') or [])
            for row in assessment.get('normalized_rows') or assessment.get('rows') or []:
                if row.get('row_index') in refs:
                    rows.append(row)
            if rows:
                return rows
            return list(cluster.get('evidence_preview') or [])
        except Exception:
            return []
