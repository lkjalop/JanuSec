from __future__ import annotations

import os
from fastapi.testclient import TestClient

def test_content_type_guard_blocks_non_json_on_post():
    os.environ['PLATFORM_LITE_INIT'] = '1'
    from src.api.app import app
    client = TestClient(app)
    # choose a simple POST json endpoint: webhook dispatch (guarded by admin scopes, but tests relax)
    r = client.post('/api/v1/webhooks/dispatch', data='not-json', headers={'Content-Type':'text/plain'})
    assert r.status_code in (400,415)
    # Guard should prefer 415 unsupported_media_type
    if r.status_code == 415:
        assert r.json().get('detail') == 'unsupported_media_type'

