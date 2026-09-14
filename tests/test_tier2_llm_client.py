import json
from fastapi.testclient import TestClient

from src.api.tier2_endpoints import router
from src.integrations.llm_client import DEFAULT_CLIENT


def test_local_llm_client_generates():
    # Ensure the DEFAULT_CLIENT is deterministic local client in test env
    text = DEFAULT_CLIENT.generate('unit test prompt', max_tokens=32)
    assert isinstance(text, dict)
    assert 'text' in text


def test_tier2_summarize_flow():
    # Use TestClient to call the router directly
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    payload = {'assessment_id': 'a1', 'rows': [{'id': 1, 'message': 'suspicious'}], 'org': 'default'}
    resp = client.post('/api/v1/csv/tier2_summarize', json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body.get('status') == 'ok'
    assert 'chunks' in body
    assert isinstance(body.get('chunks'), list)