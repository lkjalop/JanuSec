from __future__ import annotations
"""Unified API facade aggregating identity, network, cloud, and extended hopgraph.

Provides a consistent set of helper functions for ingestion, path finding, and
explanation across domains, plus correlation enrichment hooks.

This simplifies demo wiring: instead of importing each graph directly in API
routes or scripts, import these facade helpers.
"""
from typing import Any, Dict, List

try:
    from src.graph.hopgraph_ext import GLOBAL_EXT_HOPGRAPH  # type: ignore
except Exception:  # pragma: no cover
    from src.graph.hopgraph import GLOBAL_HOPGRAPH as GLOBAL_EXT_HOPGRAPH  # type: ignore

from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH  # type: ignore
from src.core.graph.network_hopgraph import GLOBAL_NETWORK_GRAPH  # type: ignore
from src.core.graph.cloud_hopgraph import GLOBAL_CLOUD_GRAPH  # type: ignore

Graphs = {
    'core': GLOBAL_EXT_HOPGRAPH,
    'identity': GLOBAL_IDENTITY_GRAPH,
    'network': GLOBAL_NETWORK_GRAPH,
    'cloud': GLOBAL_CLOUD_GRAPH,
}

# ---------------- Ingestion -----------------

def ingest_event_core(ev: Dict[str, Any]) -> None:
    try:
        Graphs['core'].ingest_event(ev)
    except Exception:
        pass

def ingest_identity(ev: Dict[str, Any]) -> None:
    try:
        GLOBAL_IDENTITY_GRAPH.ingest_identity_event(ev)
    except Exception:
        pass

def ingest_network(fl: Dict[str, Any]) -> None:
    try:
        GLOBAL_NETWORK_GRAPH.ingest_flow(fl)
    except Exception:
        pass

def ingest_cloud(res: Dict[str, Any]) -> None:
    try:
        GLOBAL_CLOUD_GRAPH.ingest_resource(res)
    except Exception:
        pass

# ---------------- Path / Explanation -----------------

def explain_core(start: str, **kw) -> Dict[str, Any]:
    try:
        return Graphs['core'].explain_chain(start, **kw)
    except Exception:
        return {'start': start, 'chains': [], 'subgraph': {}}

def identity_paths(start: str, limit: int = 5, depth: int = 5):
    return GLOBAL_IDENTITY_GRAPH.find_top_paths(start, limit=limit, depth=depth)

def identity_explain(path: List[str]):
    return GLOBAL_IDENTITY_GRAPH.explain_path(path)

def network_paths(entry: str, target: str, limit: int = 10, depth: int = 7):
    return GLOBAL_NETWORK_GRAPH.find_paths(entry, target, limit=limit, depth=depth)

def network_explain(path: List[str]):
    return GLOBAL_NETWORK_GRAPH.explain_path(path)

def cloud_paths(entry: str, target: str, limit: int = 10, depth: int = 8):
    return GLOBAL_CLOUD_GRAPH.find_paths(entry, target, limit=limit, depth=depth)

def cloud_explain(path: List[str]):
    return GLOBAL_CLOUD_GRAPH.explain_path(path)

__all__ = [
    'ingest_event_core','ingest_identity','ingest_network','ingest_cloud',
    'explain_core','identity_paths','identity_explain','network_paths','network_explain',
    'cloud_paths','cloud_explain','Graphs'
]
