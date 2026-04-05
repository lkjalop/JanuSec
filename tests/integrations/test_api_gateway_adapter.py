import json
import os
import pytest

from src.integrations.api_gateway_adapter import normalize_gateway_batch


API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_gateway_adapter_normalizes_fixture():
    with open('tests/fixtures/api_gateway_log.json', 'r', encoding='utf-8') as handle:
        raw = json.load(handle)
    normalized = normalize_gateway_batch(raw)
    assert normalized
    ev = normalized[0]
    assert ev.get('event_type') == 'api_request'
    assert ev.get('uri') == '/api/v1/payouts/approve'
    assert ev.get('method') == 'POST'
    assert ev.get('status') == 401
    assert ev.get('auth_user') == 'alice'
    assert ev.get('ip') == '198.51.100.10'


def test_gateway_logs_ingest(client):
    with open('tests/fixtures/api_gateway_log.json', 'r', encoding='utf-8') as handle:
        raw = json.load(handle)
    payload = {'events': normalize_gateway_batch(raw)}
    r = client.post('/api/v1/api_security/gateway_logs', json=payload, headers={'x-api-key': API_KEY})
    assert r.status_code in (200, 201)
    body = r.json()
    assert body.get('status') == 'ok'
    assert body.get('ingested') == len(payload['events'])
