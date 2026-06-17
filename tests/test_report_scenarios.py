import json

from fastapi.testclient import TestClient
from tests._helpers import default_test_headers

from src.api.server import DECISION_CACHE, _record_decision, app


def _seed_decision(event_id: str, factors):
    _record_decision(event_id, 'SUSPICIOUS', 0.6, factors)

client = TestClient(app)

def test_ingestion_report_with_scenarios():
    DECISION_CACHE.clear()
    _seed_decision('evt-scn-1', ['dns:tunnel_suspected','net:beacon_periodic','ssl:ja3_rare'])
    _seed_decision('evt-scn-2', ['endpoint:lolbin_certutil_suspicious','endpoint:persistence_candidate'])
    # format=json so we get the structured report (the default html serves the LIVE console)
    r = client.get('/api/v1/report/ingestion?format=json&include_scenarios=true&include_model=true', headers=default_test_headers())
    assert r.status_code == 200, r.text
    data = r.json()
    assert 'scenario_summary' in data
    scen = data['scenario_summary']
    assert scen['observed_count'] >= 1
    flagged = data['flagged_events']
    assert any('scenarios' in e for e in flagged)


def test_pasta_report_endpoint():
    DECISION_CACHE.clear()
    _seed_decision('evt-scn-3', ['dns:tunnel_suspected','ssl:ja3_known_bad'])
    r = client.get('/api/v1/report/pasta', headers=default_test_headers())
    assert r.status_code == 200
    payload = r.json()
    assert 'scenarios' in payload
    # ensure scenario id present
    ids = [s['id'] for s in payload['scenarios']]
    assert any(id.startswith('SCN-') for id in ids)


def test_threat_model_report_endpoint():
    DECISION_CACHE.clear()
    _seed_decision('evt-scn-4', ['dns:tunnel_suspected','ssl:ja3_known_bad'])
    r = client.get('/api/v1/report/threat_model', headers=default_test_headers())
    assert r.status_code == 200
    body = r.json()
    assert 'stride_categories' in body
    # Not asserting specific categories to keep test flexible
