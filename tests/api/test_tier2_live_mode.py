import os

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_tier2_hard_fails_in_live_mode_without_provider(monkeypatch):
    monkeypatch.setenv('ENV', 'prod')
    monkeypatch.setenv('TIER2_ALLOW_PLACEHOLDER', '0')

    from src.api import tier2_endpoints as mod

    class _Unavailable:
        def generate(self, *args, **kwargs):
            raise RuntimeError('should not be called')

    monkeypatch.setattr(mod, '_allow_tier2_placeholder', lambda: False)

    import src.integrations.llm_client as llm_client
    monkeypatch.setattr(llm_client, 'DEFAULT_CLIENT', _Unavailable(), raising=False)
    monkeypatch.setattr(llm_client, 'get_client_status', lambda client=None: {'available': False, 'provider': 'test'}, raising=False)

    app = FastAPI()
    app.include_router(mod.router)
    client = TestClient(app)

    resp = client.post('/api/v1/csv/tier2_summarize', json={'rows': [{'id': 1}]})
    assert resp.status_code == 503
    assert resp.json()['detail'] == 'tier2_provider_unavailable'
