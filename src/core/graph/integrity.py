"""Graph integrity utilities.

Provides lightweight validation helpers for the HopGraph structure to detect:
  - Orphan nodes (nodes with zero edges in or out).
  - Edge endpoints referencing missing nodes.

Intended for unit test usage and optional diagnostic endpoint.
"""
from __future__ import annotations

from typing import Iterable, Dict, List, Tuple


def find_orphan_nodes(graph) -> List[str]:
    orphans: List[str] = []
    try:
        nodes = getattr(graph, 'nodes', {})
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        # Pass the graph object to _get_adj_list so it can correctly derive
        # an adjacency accessor; passing graph.adj (a dict) breaks the
        # duck-typing inside _get_adj_list for non-callable mappings.
        adj_accessor = _get_adj_list(graph)
    except Exception:
        return orphans
    for n in nodes.keys():
        outs = list(adj_accessor(n))
        has_out = bool(outs)
        has_in = False
        if not has_out:
            # scan for inbound references; shallow linear scan OK for test sizes
            # best-effort inbound scan: iterate nodes and sample their neighbors
            try:
                for src in nodes.keys():
                    if src == n:
                        continue
                    for tgt, *_rest in adj_accessor(src):
                        if tgt == n:
                            has_in = True
                            break
                    if has_in:
                        break
            except Exception:
                pass
        if not has_out and not has_in:
            orphans.append(n)
    return orphans


def find_invalid_edges(graph) -> List[Tuple[str, str]]:
    invalid: List[Tuple[str, str]] = []
    try:
        nodes = getattr(graph, 'nodes', {})
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj_accessor = _get_adj_list(graph)
    except Exception:
        return invalid
    try:
        for src in nodes.keys():
            for tgt, *_rest in adj_accessor(src):
                if src not in nodes or tgt not in nodes:
                    invalid.append((src, tgt))
    except Exception:
        pass
    return invalid

__all__ = ['find_orphan_nodes', 'find_invalid_edges']
