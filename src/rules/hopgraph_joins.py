from __future__ import annotations
from typing import Any, Dict
try:
    from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH
except Exception:
    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH
    except Exception:
        GLOBAL_HOPGRAPH = None

def join_identity(left_key: str, right_key: str, attrs: Dict[str, Any] | None = None) -> None:
    """Create an identity join in HopGraph between two canonical keys."""
    if GLOBAL_HOPGRAPH is None:
        return
    try:
        GLOBAL_HOPGRAPH.add_edge(left_key, right_key, 'identity_join', source='rules', attrs=(attrs or {}))
    except Exception:
        pass

def join_process(left_key: str, right_key: str, attrs: Dict[str, Any] | None = None) -> None:
    if GLOBAL_HOPGRAPH is None:
        return
    try:
        GLOBAL_HOPGRAPH.add_edge(left_key, right_key, 'process_join', source='rules', attrs=(attrs or {}))
    except Exception:
        pass

def join_network(left_key: str, right_key: str, attrs: Dict[str, Any] | None = None) -> None:
    if GLOBAL_HOPGRAPH is None:
        return
    try:
        GLOBAL_HOPGRAPH.add_edge(left_key, right_key, 'network_join', source='rules', attrs=(attrs or {}))
    except Exception:
        pass

def join_sbom(left_key: str, right_key: str, attrs: Dict[str, Any] | None = None) -> None:
    if GLOBAL_HOPGRAPH is None:
        return
    try:
        GLOBAL_HOPGRAPH.add_edge(left_key, right_key, 'sbom_join', source='rules', attrs=(attrs or {}))
    except Exception:
        pass
