from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client():
    from src.api import graph_session_endpoints as mod
    app = FastAPI()
    app.include_router(mod.router)
    return TestClient(app), mod


def test_graph_build_removes_demo_summary_and_demo_factor_in_live_mode(monkeypatch):
    _client_instance, mod = _client()
    monkeypatch.setattr(mod, '_allow_demo_graph_fallbacks', lambda: False)
    factors = mod._factor_tags({'a': {'b': 3}, 'b': {'a': 3}}, {'user': 'user', 'host': 'host', 'domain': 'domain'})
    assert factors
    assert all(f.get('reason') != 'demo tag' for f in factors)


def test_graph_enrichment_queue_hard_fails_without_llm_in_live_mode(monkeypatch):
    client, mod = _client()
    monkeypatch.setattr(mod, 'LLM_ENABLED', False)
    monkeypatch.setattr(mod, '_allow_demo_graph_fallbacks', lambda: False)
    resp = client.post('/api/v1/graph/enrich/queue', json={'session_id': 's1'})
    assert resp.status_code == 503
    assert resp.json()['detail'] == 'llm_enrichment_unavailable'
