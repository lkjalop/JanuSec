from __future__ import annotations

import os
from fastapi.testclient import TestClient

def test_webhook_dispatch_ssrf_block(monkeypatch):
    # permissive in tests due to require_scopes guard
    os.environ['PLATFORM_LITE_INIT'] = '1'
    from src.api.app import create_app  # import after env set
    app = create_app({'mode': 'test'})
    client = TestClient(app)
    # Point slack webhook to localhost (should be blocked)
    monkeypatch.setenv('SLACK_WEBHOOK_URL', 'http://127.0.0.1:1234/hook')
    r = client.post('/api/v1/webhooks/dispatch', json={'service': 'slack', 'text': 'hello'})
    assert r.status_code == 400
    assert 'ssrf_blocked' in r.json().get('detail','')

