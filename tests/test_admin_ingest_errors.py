import os
import pytest
from fastapi.testclient import TestClient

from src.api.app import app

client = TestClient(app)

def test_admin_ingest_requires_api_key():
    os.environ['ALLOW_DEV_API_KEY'] = '0'
    r = client.get('/api/v1/admin/ingest/status')
    assert r.status_code in (401, 403)

def test_admin_ingest_thresholds_bad_payload():
    os.environ['ALLOW_DEV_API_KEY'] = '1'
    headers = {'x-api-key':'devkey123'}
    r = client.post('/api/v1/admin/ingest/thresholds', json={'items': {}}, headers=headers)
    assert r.status_code == 400
    data = r.json()
    assert data.get('detail') == 'no_items'
