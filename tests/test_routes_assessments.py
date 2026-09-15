"""Tests for src/api/routes/assessments.py router."""
import os
import json
import pytest

os.environ.setdefault('PLATFORM_LITE_INIT', '1')
os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
os.environ.setdefault('DISABLE_DB', '1')

API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')


@pytest.fixture(scope='module')
def client():
    from src.api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def _h():
    return {'x-api-key': API_KEY, 'Content-Type': 'application/json', 'x-tenant-id': 'default'}


# ── ask_for_logs ──────────────────────────────────────────────────────────────

def test_ask_for_logs_basic(client):
    r = client.post(
        '/api/v1/reports/test-report-001/ask_for_logs',
        headers=_h(),
        data=json.dumps({'recipient': 'analyst@corp.com', 'reason': 'Evidence for triage'}),
    )
    assert r.status_code == 200
    j = r.json()
    assert j['ok'] is True
    assert 'message' in j
    assert j['message']['to'] == 'analyst@corp.com'
    assert 'test-report-001' in j['message']['subject']


def test_ask_for_logs_defaults(client):
    """When no recipient is provided, should fall back to default address."""
    r = client.post(
        '/api/v1/reports/test-report-002/ask_for_logs',
        headers=_h(),
        data=json.dumps({}),
    )
    assert r.status_code == 200
    j = r.json()
    assert j['ok'] is True
    assert 'security@example.com' in j['message']['to']


def test_ask_for_logs_body_contains_report_id(client):
    r = client.post(
        '/api/v1/reports/REPORT-XYZ/ask_for_logs',
        headers=_h(),
        data=json.dumps({'recipient': 'a@b.com'}),
    )
    assert r.status_code == 200
    assert 'REPORT-XYZ' in r.json()['message']['body']


# ── generate_persona ──────────────────────────────────────────────────────────

def test_generate_persona_missing_id(client):
    r = client.post(
        '/api/v1/assessments/generate_persona',
        headers=_h(),
        data=json.dumps({'persona': 'soc'}),
    )
    assert r.status_code == 400
    assert r.json()['detail'] == 'missing_assessment_id'


def test_generate_persona_unknown_report(client):
    r = client.post(
        '/api/v1/assessments/generate_persona',
        headers=_h(),
        data=json.dumps({'assessment_id': 'nonexistent-abc', 'persona': 'soc'}),
    )
    assert r.status_code == 404
    assert r.json()['detail'] == 'report_not_found'


def test_generate_persona_with_seeded_report(client):
    """Seed REPORT_STORE and verify generate_persona returns a response."""
    try:
        from src.api import deep_analyze_endpoints as dae
    except Exception:
        pytest.skip('deep_analyze_endpoints not available')

    aid = 'test-assess-persona-001'
    dae.REPORT_STORE[aid] = {
        'per_row': [
            {'summary': 'User SFL-LT-0442 authenticated from an unusual location.', 'persona_reports': {}},
        ],
    }
    try:
        r = client.post(
            '/api/v1/assessments/generate_persona',
            headers=_h(),
            data=json.dumps({'assessment_id': aid, 'persona': 'soc', 'row_index': 0}),
        )
        # Accept 200 (LLM available) or 500 (LLM unavailable in test env)
        assert r.status_code in (200, 500)
        if r.status_code == 200:
            j = r.json()
            assert j['ok'] is True
            assert j['persona'] == 'soc'
            assert 'response' in j
    finally:
        dae.REPORT_STORE.pop(aid, None)


def test_generate_persona_invalid_row_index(client):
    try:
        from src.api import deep_analyze_endpoints as dae
    except Exception:
        pytest.skip('deep_analyze_endpoints not available')

    aid = 'test-assess-persona-002'
    dae.REPORT_STORE[aid] = {'per_row': [{'summary': 'row0'}]}
    try:
        r = client.post(
            '/api/v1/assessments/generate_persona',
            headers=_h(),
            data=json.dumps({'assessment_id': aid, 'persona': 'soc', 'row_index': 99}),
        )
        assert r.status_code == 400
        assert r.json()['detail'] == 'invalid_row_index'
    finally:
        dae.REPORT_STORE.pop(aid, None)


# ── hopgraph_report ───────────────────────────────────────────────────────────

def test_hopgraph_report_smoke(client):
    """Hopgraph endpoint should respond (503 is acceptable when module is absent)."""
    r = client.post(
        '/api/v1/assessments/hopgraph_report',
        headers=_h(),
        data=json.dumps({'assessment_id': 'smoke-test'}),
    )
    assert r.status_code in (200, 201, 422, 503)


def test_hopgraph_report_empty_payload(client):
    r = client.post(
        '/api/v1/assessments/hopgraph_report',
        headers=_h(),
        data=json.dumps({}),
    )
    assert r.status_code in (200, 201, 400, 422, 503)


# ── Route registration sanity ─────────────────────────────────────────────────

def test_routes_registered(client):
    """Verify the router's three paths appear in the running app."""
    paths = {getattr(r, 'path', '') for r in client.app.router.routes}
    assert '/api/v1/reports/{report_id}/ask_for_logs' in paths, \
        f"ask_for_logs not registered; sample routes: {sorted(paths)[:20]}"
    assert '/api/v1/assessments/generate_persona' in paths, \
        f"generate_persona not registered; sample routes: {sorted(paths)[:20]}"
    assert '/api/v1/assessments/hopgraph_report' in paths, \
        f"hopgraph_report not registered; sample routes: {sorted(paths)[:20]}"
