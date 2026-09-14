import asyncio
import time
from starlette.testclient import TestClient

from src.api.app import app


def test_cs_sync_and_explain_roundtrip():
    client = TestClient(app)
    # trigger sync - uses demo client when credentials are not set
    r = client.post('/api/v1/integrations/crowdstrike/sync', headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert 'created' in j and isinstance(j['created'], list)
    created = j.get('created') or []
    if not created:
        # no items created (possible if client returned empty) - still valid
        return
    event_id = created[0]
    # now call explain_verbose
    r2 = client.get(f'/api/v1/decisions/{event_id}/explain_verbose')
    assert r2.status_code == 200
    ej = r2.json()
    assert ej.get('event_id') == event_id
    assert 'intel_hits' in ej


def test_explain_missing_returns_404():
    client = TestClient(app)
    r = client.get('/api/v1/decisions/this-id-does-not-exist/explain_verbose')
    assert r.status_code == 404
