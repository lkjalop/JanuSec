import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from integrations.threat_intel_client import CLIENT


def test_lookup_endpoint_confidence(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_ENABLED','1')
    CLIENT._current_origin = 'misp'
    CLIENT._add_domain('malicious.example', ttl_hours=1)
    c = TestClient(app)
    r = c.get('/api/v1/intel/lookup', params={'type':'domain','value':'malicious.example'})
    assert r.status_code == 200
    j = r.json()
    assert j['found'] is True
    assert j['type'] == 'domain'
    assert j['confidence'] is not None


def test_explain_includes_techniques(monkeypatch):
    # Simulate factor techniques mapping
    CLIENT.factor_techniques['stable:powershell'] = ['T1059.001']
    # Insert synthetic decision into DECISION_CACHE
    from src.api import runtime_state
    runtime_state.cache_set('evt123', {'event_id': 'evt123', 'verdict': 'suspicious', 'confidence': 0.55, 'factors': ['baseline:intel_match','stable:powershell_spawn']})
    c = TestClient(app)
    r = c.get('/api/v1/decisions/evt123/explain')
    assert r.status_code == 200
    j = r.json()
    # Expect technique mapping for the powershell stem
    techs = j.get('techniques') or {}
    assert any('T1059' in tid for tids in techs.values() for tid in tids)
