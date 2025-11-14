"""Adapter to the repo's attack reconstruction logic for Sultry integration.

This module tries to import the heavier `src.graph.reconstruction` and expose
`reconstruct_subgraph(seed_event, depth)` with a compact return shape. If the
heavy module is not importable, a small heuristic stub is provided.
"""
from typing import Any, Dict, List

try:
    from src.graph import reconstruction as full_recon
    HAS_FULL = True
except Exception:
    HAS_FULL = False


def reconstruct_subgraph(seed_event_id: str, depth: int = 3, attach_incident: bool = False) -> Dict[str, Any]:
    """Return a compact reconstructed attack graph around `seed_event_id`.

    The shape is: {nodes: [{id,type}], edges: [{src,dst,relation}], summary: {...}}
    """
    if HAS_FULL:
        # call into the repo's reconstruction entrypoint and translate shape
        res = full_recon.reconstruct(seed_event_id=seed_event_id, depth=depth, attach_incident=attach_incident)
        # attempt to map the full response into compact shape
        nodes = []
        edges = []
        for n in res.get('nodes', []):
            nodes.append({'id': n.get('id'), 'type': n.get('type')})
        for e in res.get('edges', []):
            edges.append({'src': e.get('source'), 'dst': e.get('target'), 'relation': e.get('relation')})
        return {'nodes': nodes, 'edges': edges, 'summary': res.get('summary', {})}

    # fallback stub: return a trivial single-node graph
    return {'nodes': [{'id': seed_event_id, 'type': 'event'}], 'edges': [], 'summary': {'depth': depth, 'note': 'stub'}}
