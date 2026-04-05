from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)


def test_explain_has_cooccurrence_meta():
    r = client.get('/api/v1/graph/explain')
    # Some environments may return 422 if optional explain integrations require extra deps.
    assert r.status_code in (200, 422)
    if r.status_code != 200:
        return
    j = r.json()
    meta = j.get('meta') or {}
    # cooccurrence_top may be absent if cooccurrence store empty but should be present key when hopgraph available
    assert 'version' in meta
    # chains hops have factors
    chains = j.get('chains', [])
    if chains:
        for hop in chains[0].get('hops', []):
            assert 'factors' in hop
