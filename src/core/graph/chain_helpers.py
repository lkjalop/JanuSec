from __future__ import annotations

from typing import Any, Dict, List

def build_multi_stage_chain(session_ids: List[str], overlap_matrix: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
    """Construct a tiny multi-stage chain DTO based on overlaps.

    Nodes: batches; Edges: directed where overlap>0, weight=overlap.
    Also summarizes stages (hops) for simple UI rendering.
    """
    nodes: List[Dict[str, Any]] = [{'id': sid, 'type': 'batch', 'label': sid} for sid in session_ids]
    edges: List[Dict[str, Any]] = []
    for a, row in (overlap_matrix or {}).items():
        for b, val in (row or {}).items():
            try:
                if a == b:
                    continue
                w = float(val)
                if w > 0:
                    edges.append({'src': a, 'dst': b, 'type': 'chain', 'weight': w})
            except Exception:
                continue
    # compute simple hop counts per node
    out_degree = {n['id']: 0 for n in nodes}
    in_degree = {n['id']: 0 for n in nodes}
    for e in edges:
        sa = e.get('src'); da = e.get('dst')
        if sa in out_degree:
            out_degree[sa] += 1
        if da in in_degree:
            in_degree[da] += 1
    stages = {'sources': [nid for nid, d in out_degree.items() if d > 0], 'sinks': [nid for nid, d in in_degree.items() if d > 0]}
    return {'nodes': nodes, 'edges': edges, 'stages': stages, 'node_count': len(nodes), 'edge_count': len(edges)}
