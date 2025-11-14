import json
from fastapi.testclient import TestClient

from src.api.report_endpoints import router


def test_generate_report_include_model(monkeypatch):
    # Create a small app to mount the router for testing
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # Mock generate_summary to be deterministic
    def fake_generate_summary(prompt, max_tokens=512):
        return {'text': 'This is a deterministic executive summary.', 'model': 'mock-model-1', 'meta': {'tokens': 10}}

    monkeypatch.setattr('src.api.report_endpoints.generate_summary', fake_generate_summary)

    payload = {'title': 'Test', 'rows': [{'process_name': 'p', 'host': 'h1', 'verdict': 'suspicious', '_dread': {'score': 8}}], 'summary': {'rows':1}}
    resp = client.post('/api/v1/report/generate?include_model=true', json=payload)
    assert resp.status_code == 200
    j = resp.json()
    assert 'html' in j
    assert 'model_summary' in j
    assert 'model_html' in j
    assert j['model_summary']['text'].startswith('This is a deterministic')
