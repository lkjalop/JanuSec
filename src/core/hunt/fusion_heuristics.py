"""Fusion Heuristics Stubs

These functions operate on HopGraph Light view to derive hunt factors.
They return simple dicts so the hunt sidecar can assemble a factor table.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Dict, List

from .hopgraph_light import HopGraphLight


def lateral_chain_density(graph: HopGraphLight, max_depth: int = 4) -> dict[str, float]:
    """Compute ratio of multi-host chains vs total nodes.
    Placeholder heuristic: chains approximated by nodes with degree > 1.
    """
    stats = graph.stats()
    total_nodes = stats['nodes'] or 1
    # naive: use adjacency entries as proxy for branching
    branching = stats['adjacency_entries']
    density = branching / total_nodes
    return {'lateral_chain_density': round(density, 4)}

def multi_host_same_user(graph: HopGraphLight) -> dict[str, float]:
    """Placeholder: detect same user appearing on many assets quickly.
    We assume node id format may contain prefixes like user:alice host:web01
    """
    # Cheap scan — improvement: maintain index on add
    from collections import defaultdict
    user_to_hosts = defaultdict(set)
    # Access protected structures cautiously
    # (graph intentionally exposes internal via stats only; for stub we peek)
    g_nodes = graph._nodes  # type: ignore
    for node in g_nodes.values():  # type: ignore
        if node.kind == 'asset':
            continue
        if node.kind == 'user':
            # find edges where user is src leading to asset nodes
            pass
    # Fallback simple heuristic: count users present indirectly by id pattern
    for node in g_nodes.values():
        if node.kind == 'unknown' and node.id.startswith('user:'):
            parts = node.id.split(':',1)
            if len(parts) == 2:
                user_to_hosts[parts[1]].add('unknown_host')
    if not user_to_hosts:
        return {'multi_host_same_user_score': 0.0}
    max_hosts = max(len(v) for v in user_to_hosts.values())
    score = max_hosts / 10.0  # normalized crude scale
    return {'multi_host_same_user_score': round(min(score, 1.0), 4)}

def aggregate(graph: HopGraphLight) -> dict[str, float]:
    features: dict[str, float] = {}
    for fn in (lateral_chain_density, multi_host_same_user):
        try:
            features.update(fn(graph))
        except Exception:
            continue
    return features
