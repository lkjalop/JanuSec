"""HopGraph test-helper endpoints.

Mounted at /api/v1/test/hopgraph/* only when TEST_HELPERS_ENABLED=1.
Extracted from server.py to keep that file smaller.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["test-helpers"])


def _get_hopgraph():
    """Resolve GLOBAL_HOPGRAPH from whichever import path works."""
    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH as _hg
        return _hg
    except Exception:
        pass
    return None


def _guard():
    if os.getenv("TEST_HELPERS_ENABLED", "0").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=404, detail="not_available")


@router.get("/api/v1/test/hopgraph/nodes")
def test_list_hopgraph_nodes(limit: int = 1000):
    _guard()
    hg = _get_hopgraph()
    if hg is None:
        return {"status": "mock", "nodes": []}
    try:
        keys = list(getattr(hg, "nodes", {}) or {})
        if limit > 0:
            keys = keys[:limit]
        return {"status": "ok", "nodes": keys}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/api/v1/test/hopgraph/node/{node_id}")
def test_get_hopgraph_node(node_id: str):
    _guard()
    hg = _get_hopgraph()
    if hg is None:
        return {"status": "mock", "node": node_id, "attrs": {}, "factors": []}
    try:
        attrs = dict(getattr(hg, "nodes", {}).get(node_id, {}))
        try:
            factors = (
                list(hg.get_node_factors(node_id))
                if hasattr(hg, "get_node_factors")
                else list(attrs.get("factors", []))
            )
        except Exception:
            factors = list(attrs.get("factors", []))
        return {"status": "ok", "node": node_id, "attrs": attrs, "factors": factors}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
