import json
import time
from starlette.testclient import TestClient

from src.api.app import create_app

app = create_app({'mode': 'test'})


def test_decision_execute_rbac_and_idempotency(monkeypatch):
    # Enforce RBAC by ensuring test/lite modes are not bypassing
    monkeypatch.setenv('FAST_TEST_MODE', '0')
    monkeypatch.setenv('PLATFORM_LITE_INIT', '0')
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')

    client = TestClient(app)

    body = {
        'actor': 'tester',
        'action': 'send_notification',
        'args': {
            'channel': '#security',
            'message': 'Hello world',
            'severity': 'low'
        }
    }

    # Missing API key should be unauthorized when ADMIN_API_KEY is set
    r1 = client.post('/api/v1/ingest/decision/execute', json=body)
    assert r1.status_code == 401
    assert isinstance(r1.json().get('detail'), dict)
    assert r1.json()['detail'].get('error_code') == 'unauthorized'

    # With valid admin key, should execute and set idempotent flag when provided
    headers = {'x-api-key': 'adminkey', 'Idempotency-Key': 'test-key-123'}
    r2 = client.post('/api/v1/ingest/decision/execute', json=body, headers=headers)
    assert r2.status_code == 200
    d2 = r2.json().get('detail') or {}
    assert d2.get('actor') == 'tester'
    assert d2.get('action') == 'send_notification'
    assert d2.get('idempotent') is True
    assert d2.get('status') in {'executed_ok', 'dry_ok'}
    first_result = d2.get('result')

    # Second call with same idempotency key should return cached result
    r3 = client.post('/api/v1/ingest/decision/execute', json=body, headers=headers)
    assert r3.status_code == 200
    d3 = r3.json().get('detail') or {}
    assert d3.get('idempotent') is True
    # Cached result should match initial result shape
    assert d3.get('result') == first_result


def test_events_query_endpoint_sqlite(monkeypatch, tmp_path):
    # Use sqlite backend in an isolated temp DB
    dbp = tmp_path / 'events.db'
    monkeypatch.setenv('EVENT_STORE_BACKEND', 'sqlite')
    monkeypatch.setenv('EVENT_STORE_SQLITE_PATH', str(dbp))

    client = TestClient(app)

    # Ingest a few Zeek-like events with canonical fields
    t0 = time.time()
    evs = [
        {
            'id_orig_h': '10.0.0.1',
            'id_resp_h': '10.0.0.2',
            'user': 'alice',
            'server_name': 'example.com',
            'host': 'host-a',
            'ts': t0,
        },
        {
            'id_orig_h': '10.0.0.3',
            'id_resp_h': '10.0.0.4',
            'user': 'alice',
            'server_name': 'example.net',
            'host': 'host-b',
            'ts': t0 + 1,
        },
        {
            'id_orig_h': '10.0.0.5',
            'id_resp_h': '10.0.0.6',
            'user': 'bob',
            'server_name': 'other.net',
            'host': 'host-c',
            'ts': t0 + 2,
        },
    ]
    for e in evs:
        r = client.post('/api/v1/ingest/zeek', json=e)
        assert r.status_code == 200

    # Query by user=alice and validate enrichment/narrative
    q = client.post('/api/v1/ingest/events/query', json={'user': 'alice'})
    assert q.status_code == 200
    payload = q.json().get('detail') or {}
    timeline = payload.get('timeline') or []
    enrich = payload.get('enrichment') or {}

    assert len(timeline) >= 2
    # Ensure ordering by ts ascending
    ts_vals = [ev.get('ts') for ev in timeline]
    assert ts_vals == sorted(ts_vals)

    # Enrichment contains filters/users and narrative mentions the filter
    assert enrich.get('filters', {}).get('user') == 'alice'
    assert 'users' in enrich and 'alice' in (enrich.get('users') or [])
    assert isinstance(enrich.get('narrative'), str) and 'filter=' in enrich.get('narrative')


def test_decisiongate_action_arg_validation(monkeypatch):
    # Ensure admin key enforced and missing args return 400 for actions that require them
    monkeypatch.setenv('FAST_TEST_MODE', '0')
    monkeypatch.setenv('PLATFORM_LITE_INIT', '0')
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')
    client = TestClient(app)

    # Missing ip for block_ip should return 400
    body_missing_ip = {'actor': 'tester', 'action': 'block_ip', 'args': {}}
    r = client.post('/api/v1/ingest/decision/execute', json=body_missing_ip, headers={'x-api-key': 'adminkey'})
    assert r.status_code == 400

    # Missing endpoint for isolate should return 400
    body_iso = {'actor': 'tester', 'action': 'isolate', 'args': {}}
    r2 = client.post('/api/v1/ingest/decision/execute', json=body_iso, headers={'x-api-key': 'adminkey'})
    assert r2.status_code == 400


def test_events_query_endpoint_jsonl(monkeypatch, tmp_path):
    # Force JSONL backend and write events into JSONL store, then query
    jp = tmp_path / 'events.jsonl'
    monkeypatch.setenv('EVENT_STORE_BACKEND', 'jsonl')
    monkeypatch.setenv('EVENT_STORE_PATH', str(jp))
    client = TestClient(app)

    # Write two events directly using ingest endpoint (generic mapping)
    e1 = {'ip': '1.2.3.4', 'user': 'charlie', 'host': 'h1', 'ts': time.time()}
    e2 = {'ip': '1.2.3.5', 'user': 'charlie', 'host': 'h2', 'ts': time.time() + 1}
    r1 = client.post('/api/v1/ingest/generic', json=e1)
    assert r1.status_code == 200
    r2 = client.post('/api/v1/ingest/generic', json=e2)
    assert r2.status_code == 200

    q = client.post('/api/v1/ingest/events/query', json={'user': 'charlie'})
    assert q.status_code == 200
    det = q.json().get('detail') or {}
    assert det.get('enrichment', {}).get('filters', {}).get('user') == 'charlie'
