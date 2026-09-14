import json
from fastapi.testclient import TestClient

from src.api.app import create_app
import src.api.deep_analyze_endpoints as dae


def setup_assessment_for_missing_db(aid: str):
    dae.REPORT_STORE[aid] = {
        'assessment_id': aid,
        'stage_status': [{'stage': 'ingest', 'result': 'ok'}],
        'llm_rows': [],
    }


def test_verify_missing_database_flags_missing(no_vector_no_hist):
    app = create_app()
    client = TestClient(app)
    aid = 'test-missing-db'
    setup_assessment_for_missing_db(aid)

    payload = {
        'decision_card': {
            'top_evidence': [
                { 'stage': 'ingest', 'path': 'stage_status[0].result', 'snippet': 'ok' }
            ]
        }
    }
    r = client.post(f"/api/v1/assessments/{aid}/llm/verify", json=payload)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get('missing_evidence_from_database') is True
    assert j.get('overall') == 'verified'
    per = j.get('per_evidence') or []
    assert len(per) == 1
    assert per[0].get('verified') is True


def test_verify_vector_search_can_verify(vector_stub):
    app = create_app()
    client = TestClient(app)
    aid = 'test-vector-hit'
    # empty assessment (no path will match)
    dae.REPORT_STORE[aid] = {'assessment_id': aid, 'stage_status': [], 'llm_rows': []}

    payload = {'decision_card': { 'top_evidence': [ { 'path': 'non.existent', 'snippet': 'this contains needle' } ] } }
    r = client.post(f"/api/v1/assessments/{aid}/llm/verify", json=payload)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get('missing_evidence_from_database') is False
    assert j.get('overall') in ('partial', 'verified')
    per = j.get('per_evidence') or []
    assert len(per) == 1
    assert per[0].get('verified') is True
    # ensure vector_hits present in evidence details
    assert 'vector_hits' in (per[0].get('evidence') or {})
    # fixture returns stub; confirm it was exercised
    assert any('needle' in (q or '') for q, _ in vector_stub.queries)
