"""HopGraph explain endpoint for visualization and integration tests.

Route: GET /api/v1/graph/explain

When called with ?node=<id>, runs a real beam-search explain_chain query against
GLOBAL_HOPGRAPH and returns {start, chains}.  Without a node parameter, returns
a stable canned chain for Playwright/visual tests.
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from typing import Dict, Any, Optional

router = APIRouter(prefix='/api/v1/graph', tags=['HopGraph'])

try:
    import src.graph.hopgraph as _hopgraph_mod  # type: ignore; validates module exists at startup
    from src.graph.cooccurrence import get_top as coocc_get_top  # type: ignore
    _HOPGRAPH_AVAILABLE = True
except Exception:
    _hopgraph_mod = None  # type: ignore
    _HOPGRAPH_AVAILABLE = False


def _get_hopgraph():
    """Resolve GLOBAL_HOPGRAPH dynamically — always re-reads sys.modules so test fixtures
    that replace src.graph.hopgraph (and the conftest cleanup that restores it) don't leave
    a stale reference in this module's namespace."""
    import sys as _sys
    mod = _sys.modules.get('src.graph.hopgraph')
    if mod is None:
        return None
    return getattr(mod, 'GLOBAL_HOPGRAPH', None)

_NODES = [
    {'id': 'user:alice', 'label': 'Alice', 'type': 'user', 'risk': 0.12},
    {'id': 'host:web01', 'label': 'web01', 'type': 'host', 'risk': 0.35},
    {'id': 'proc:nginx', 'label': 'nginx', 'type': 'process', 'risk': 0.42},
    {'id': 'file:/var/www/app.py', 'label': 'app.py', 'type': 'file', 'risk': 0.55},
    {'id': 'db:orders', 'label': 'orders', 'type': 'database', 'risk': 0.71},
    {'id': 'server:payments', 'label': 'payments', 'type': 'service', 'risk': 0.83},
]

_LINKS = [
    {'source': 'user:alice', 'target': 'host:web01', 'contrib': 0.15},
    {'source': 'host:web01', 'target': 'proc:nginx', 'contrib': 0.28},
    {'source': 'proc:nginx', 'target': 'file:/var/www/app.py', 'contrib': 0.44},
    {'source': 'file:/var/www/app.py', 'target': 'db:orders', 'contrib': 0.61},
    {'source': 'db:orders', 'target': 'server:payments', 'contrib': 0.79},
]

def _make_chain():
    # convert links to hops expected by frontend (src/dst, contrib -> contrib_score)
    hops = []
    for l in _LINKS:
        hops.append({
            'src': l['source'],
            'dst': l['target'],
            'etype': 'edge',
            'weight': 1.0,
            'age_decay': 1.0,
            'contrib_score': l.get('contrib', 0.0)
        })
    # Add placeholder per-hop factor contributions for frontend
    for h in hops:
        h['factors'] = [
            {'name': 'age_decay', 'score': h.get('age_decay',1.0)},
            {'name': 'link_weight', 'score': h.get('weight',1.0)},
        ]
    return {'hops': hops, 'nodes': _NODES, 'links': _LINKS}

@router.get('/explain')
async def explain_chain(node: Optional[str] = Query(default=None, description='Start node ID for hopgraph chain query')) -> Dict[str, Any]:
    # Real hopgraph query when node param provided
    hg = _get_hopgraph() if _HOPGRAPH_AVAILABLE else None
    if node and hg is not None:
        try:
            result = hg.explain_chain(node)
            if 'start' not in result:
                result['start'] = node
            return result
        except Exception:
            pass
        return {'start': node, 'chains': [], 'subgraph': {'nodes': {}, 'edges': []}}

    # Deterministic canned chain for Playwright/visual tests (no node param)
    chain = _make_chain()
    result = {'chains': [chain], 'meta': {'deterministic': True, 'total_nodes': len(_NODES), 'total_links': len(_LINKS), 'version': 1}}
    if _HOPGRAPH_AVAILABLE:
        try:
            top = coocc_get_top(20)
            result['meta']['cooccurrence_top'] = [{'pair': list(k), 'count': c} for k, c, ts in top]
        except Exception:
            pass
    return result

__all__ = ['router']
