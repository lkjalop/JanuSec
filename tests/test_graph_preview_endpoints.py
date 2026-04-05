from fastapi.testclient import TestClient
import os

from src.api.app import app
from tests._helpers import default_test_headers

client = TestClient(app)

KEYS = ('mitre','stride','pasta','dread','mapping_details')


def test_identity_preview():
    payload = {'user': 'alice@corp.com', 'dest_host': 'host1'}
    r = client.post('/api/v1/graph/identity/preview?detail=summary', json=payload, headers=default_test_headers())
    assert r.status_code == 200, r.text
    data = r.json()
    for k in KEYS:
        assert k in data
    assert 'scoring' in data and isinstance(data['scoring'], dict)


def test_cloud_preview():
    payload = {'id': 'arn:aws:s3:::bucket1', 'public': True}
    r = client.post('/api/v1/graph/cloud/preview?detail=summary', json=payload, headers=default_test_headers())
    assert r.status_code == 200, r.text
    data = r.json()
    for k in KEYS:
        assert k in data
    assert 'scoring' in data and isinstance(data['scoring'], dict)


def test_network_preview():
    payload = {'src': '10.0.0.1', 'dst': '10.0.0.2'}
    r = client.post('/api/v1/graph/network/preview?detail=summary', json=payload, headers=default_test_headers())
    assert r.status_code == 200, r.text
    data = r.json()
    for k in KEYS:
        assert k in data
    assert 'scoring' in data and isinstance(data['scoring'], dict)
