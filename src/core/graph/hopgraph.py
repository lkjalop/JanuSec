"""Compatibility shim for core HopGraph imports.

Prefer using `src/core/graph/hopgraph_core.py` in new code to make the
intent explicit (production-grade core HopGraph). This module exists to
maintain backward-compatible imports that referenced a core path.
"""
from __future__ import annotations

from src.graph.hopgraph import HopGraph, GLOBAL_HOPGRAPH  # type: ignore


def get_core_graph() -> "HopGraph":
    return GLOBAL_HOPGRAPH


__all__ = ["HopGraph", "GLOBAL_HOPGRAPH", "get_core_graph"]

