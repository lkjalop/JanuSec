import sys
import pytest
from fastapi.testclient import TestClient

from src.api.app import app

def _hopgraph():
    """Always fetch from sys.modules to pick up any fixture restores."""
    mod = sys.modules.get('src.graph.hopgraph')
    return getattr(mod, 'GLOBAL_HOPGRAPH', None) if mod else None

@pytest.mark.asyncio
async def test_graph_explain_api_roundtrip():
    # Seed edges to ensure a chain exists; use dynamic lookup so fixture restores are respected
    hg = _hopgraph()
    assert hg is not None, "src.graph.hopgraph.GLOBAL_HOPGRAPH not available"
    hg.add_edge('host:testgx','process:pgx','runs')
    hg.add_edge('process:pgx','domain:examplegx.org','contacts_domain')
    client = TestClient(app)
    from tests._helpers import default_test_headers
    hdrs = default_test_headers()
    resp = client.get('/api/v1/graph/explain', params={'node':'host:testgx'}, headers=hdrs)
    assert resp.status_code == 200
    data = resp.json()
    assert data['start'] == 'host:testgx'
    assert data['chains'] and len(data['chains']) >= 1
    # basic shape checks
    chain = data['chains'][0]
    assert 'score' in chain and 'hops' in chain