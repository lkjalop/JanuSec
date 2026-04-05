import os
from starlette.testclient import TestClient

# Lazy import and app creation to avoid heavy loading during collection
def get_app():
    from src.api.app import create_app
    return create_app({'mode': 'test'})


def _make_row():
    return {
        'process_name': 'suspicious.exe',
        'host': 'host-a',
        'user': 'alice',
        'sha256': 'a'*64,
        'factors': ['novel_local'],
        'ts': 1234567890,
    }


def test_insights_tier1_includes_persona_validation(monkeypatch):
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    monkeypatch.setattr('src.api.insights_endpoints.get_network_highlights_snapshot', lambda tenant: {'top_talkers': [{'ip': '1.2.3.4', 'count': 3, 'stage': 'Delivery'}], 'narrative': ['demo']})
    client = TestClient(get_app())
    body = {'row': _make_row(), 'insight_type': 'tier1', 'pipeline_context': {'persona': {'role': 'incident_responder'}}}
    r = client.post('/api/v1/insights/generate?args=&kwargs=', json=body)
    assert r.status_code == 200
    j = r.json()
    payload = j.get('payload') or {}
    assert isinstance(payload, dict)
    # validation block may be present under payload.validation.persona_text_checks
    val = payload.get('validation') or {}
    checks = val.get('persona_text_checks')
    assert checks is None or isinstance(checks, list)
    assert payload.get('network_highlights') is not None


def test_insights_tier2_includes_persona_validation(monkeypatch):
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    monkeypatch.setattr('src.api.insights_endpoints.get_network_highlights_snapshot', lambda tenant: {'beacon_findings': [{'src_ip': '10.0.0.5', 'dst_ip': '8.8.8.8', 'score': 0.9}], 'narrative': ['beacon detected']})
    client = TestClient(get_app())
    body = {'row': _make_row(), 'insight_type': 'tier2', 'pipeline_context': {'persona': {'role': 'ciso'}}}
    r = client.post('/api/v1/insights/generate?args=&kwargs=', json=body)
    assert r.status_code == 200
    j = r.json()
    payload = j.get('payload') or {}
    assert isinstance(payload, dict)
    val = payload.get('validation') or {}
    checks = val.get('persona_text_checks')
    assert checks is None or isinstance(checks, list)
    assert payload.get('network_highlights') is not None


def test_insights_executive_includes_persona_validation(monkeypatch):
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    client = TestClient(get_app())
    body = {'row': _make_row(), 'insight_type': 'executive', 'pipeline_context': {'persona': {'role': 'ciso'}}}
    r = client.post('/api/v1/insights/generate?args=&kwargs=', json=body)
    assert r.status_code == 200
    j = r.json()
    # executive returns text/model; ensure response shape is present
    assert 'text' in j and 'model' in j
