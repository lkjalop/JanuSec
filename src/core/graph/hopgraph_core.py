"""Unified HopGraph Core shim.

Re-exports the production-grade HopGraph and global instance from
`src/graph/hopgraph.py` under a stable core path. Use this for
pipeline final-stage correlation and explain operations.

Note: `hopgraph_lite` is intended for earlier cache/time-window checks
in the multi-stage pipeline, while `hopgraph_light` is a later-stage
lightweight tracker tuned for potential threat/event progression.
"""
from __future__ import annotations

from src.graph.hopgraph import HopGraph, GLOBAL_HOPGRAPH  # type: ignore


def get_core_graph() -> "HopGraph":
    """Return the process-global core HopGraph instance.

    Prefer this accessor when you need the durable, provenance-rich
    graph (WAL/snapshot/persistence). For cache-level temporal checks,
    use `src/core/graph/hopgraph_lite.py` instead.
    """
    return GLOBAL_HOPGRAPH


__all__ = ["HopGraph", "GLOBAL_HOPGRAPH", "get_core_graph"]

