"""Simple multi-root merging pass for HopGraph-like structures.

This is a lightweight initial implementation that:
 - Accepts multiple root node IDs (e.g., suspicious entry points)
 - Performs BFS up to a specified depth and merges nodes with identical
   canonical attributes (e.g., file hash, process name) into logical groups.
 - Returns a summary dict with merged node counts and sample mappings.

This module intentionally keeps the algorithm simple and testable. Later
passes can enrich heuristics (entropy, asn rarity, temporal overlap).
"""
from __future__ import annotations
from collections import deque, defaultdict
from typing import Iterable, Dict, Any, List, Set


def simple_multi_merge(get_neighbors, roots: Iterable[str], max_depth: int = 3) -> Dict[str, Any]:
    """Perform a multi-root merge.

    get_neighbors: callable(node_id) -> iterable of neighbor node ids
    roots: starting node ids
    returns: summary with merged groups and mapping
    """
    visited: Set[str] = set()
    q = deque()
    for r in roots:
        q.append((r, 0, r))  # (node, depth, origin)
        visited.add(r)

    # naive grouping by node id signature; real merge would use attributes
    groups: Dict[str, List[str]] = defaultdict(list)
    origin_map: Dict[str, List[str]] = defaultdict(list)

    while q:
        node, depth, origin = q.popleft()
        sig = str(node)  # placeholder signature
        groups[sig].append(node)
        origin_map[origin].append(node)
        if depth >= max_depth:
            continue
        try:
            for nb in get_neighbors(node):
                if nb not in visited:
                    visited.add(nb)
                    q.append((nb, depth + 1, origin))
        except Exception:
            continue

    return {
        'roots': list(roots),
        'visited_count': len(visited),
        'groups': {k: v for k, v in groups.items()},
        'origin_map': {k: v for k, v in origin_map.items()},
    }

__all__ = ['simple_multi_merge']
