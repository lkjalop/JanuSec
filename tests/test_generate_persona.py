import json
from fastapi.testclient import TestClient
import pytest

from src.api.app import app

client = TestClient(app)


def make_assessment(assessment_id: str, row_index: int = 0):
    row = {'row_index': row_index, 'llm_summary': 'base summary', 'persona_reports': {}}
    assessment = {
        'assessment_id': assessment_id,
        'rows': {str(row_index): row},
        'llm_rows': [row],
        'options': {},
    }
    return assessment, row


@pytest.fixture(autouse=True)
def isolate_report_store(monkeypatch):
    # ensure REPORT_STORE is isolated for tests
    from src.api import deep_analyze_endpoints as dae
    dae.REPORT_STORE.clear()
    yield dae


def test_generate_persona_uses_cache_and_routes(monkeypatch, isolate_report_store):
    dae = isolate_report_store
    assessment_id = 'test-assess-1'
    assessment, row = make_assessment(assessment_id)
    dae.REPORT_STORE[assessment_id] = assessment

    # Track calls
    cached_called = {'val': False}
    llm_called = {'val': False}
    routed = {'val': False}

    def fake_cached_generate(persona, incident, temperature=None, **kwargs):
        cached_called['val'] = True
        return {'response': f'cached response for {persona}'}

    def fake_llm_generate(prompt, **kwargs):
        llm_called['val'] = True
        return {'text': 'direct llm response'}

    def fake_auto_route(target, persona, text, assessment):
        routed['val'] = True

    monkeypatch.setattr('src.reporting.llm_helper.cached_generate', fake_cached_generate)
    monkeypatch.setattr('src.integrations.llm_client.DEFAULT_CLIENT', type('C', (), {'generate': staticmethod(fake_llm_generate)}))
    monkeypatch.setattr('src.api.deep_analyze_endpoints._auto_route_incident', fake_auto_route)

    payload = {'assessment_id': assessment_id, 'row_index': 0, 'persona': 'soc'}
    resp = client.post('/api/v1/assessments/generate_persona', json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get('persona') == 'soc'

    # ensure cache used, llm generate not required
    assert cached_called['val'] is True
    # direct LLM should not be called because cached_generate returns a response
    assert llm_called['val'] is False

    # verify persona_reports stored
    updated = dae.REPORT_STORE[assessment_id]
    target_row = updated.get('llm_rows')[0]
    assert 'soc' in target_row.get('persona_reports', {})
    assert routed['val'] is True
