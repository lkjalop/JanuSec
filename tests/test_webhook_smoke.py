import os
import json
import pytest

API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')

@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import create_app
    app = create_app({'mode': 'test'})
    from fastapi.testclient import TestClient
    return TestClient(app)


def _h():
    return { 'x-api-key': API_KEY, 'Content-Type': 'application/json' }


def test_slack_webhook_smoke(client):
    payload = { 'text': 'smoke test', 'channel': '#dev' }
    r = client.post('/api/v1/webhooks/test', headers=_h(), data=json.dumps({'service':'slack'}))
    # route returns 200 with a demo dispatch note
    assert r.status_code == 200


def test_teams_webhook_smoke(client):
    payload = { 'text': 'smoke test', 'channel': 'Dev' }
    r = client.post('/api/v1/webhooks/test', headers=_h(), data=json.dumps({'service':'teams'}))
    assert r.status_code == 200
