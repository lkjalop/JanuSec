"""Deterministic HopGraph explain endpoint for visualization tests.

Route: GET /api/v1/graph/explain

Returns a stable canned chain of nodes + links to support Playwright tests.
In future this should proxy real identity_hopgraph path explain queries.
"""
from __future__ import annotations

from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter(prefix='/api/v1/graph', tags=['HopGraph'])

try:
    # optional integration with real HopGraph explain
    from src.graph.hopgraph import HopGraph  # type: ignore
    from src.graph.cooccurrence import get_top as coocc_get_top  # type: ignore
    _HOPGRAPH_AVAILABLE = True
except Exception:
    _HOPGRAPH_AVAILABLE = False

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
async def explain_chain() -> Dict[str, Any]:
    chain = _make_chain()
    result = {'chains': [chain], 'meta': {'deterministic': True, 'total_nodes': len(_NODES), 'total_links': len(_LINKS), 'version': 1}}
    if _HOPGRAPH_AVAILABLE:
        try:
            hg = HopGraph.get_instance()
            # call a lightweight explain example (no args -> last snapshot deterministic)
            real = hg.explain_chain()  # assume signature exists in real HopGraph
            # annotate each hop with factors if present
            for ch in result['chains']:
                for hop in ch.get('hops',[]):
                    # try to find matching hop in real explain by src/dst
                    matches = [rh for rh in (real.get('hops') or []) if rh.get('src')==hop.get('src') and rh.get('dst')==hop.get('dst')]
                    if matches:
                        hop['factors'] = matches[0].get('factors', hop.get('factors'))
            # attach recent top co-occurrence pairs for context
            top = coocc_get_top(20)
            result['meta']['cooccurrence_top'] = [{'pair': list(k), 'count': c} for k,c,ts in top]
        except Exception:
            # fall back silently to deterministic chain
            pass
    return result

__all__ = ['router']
