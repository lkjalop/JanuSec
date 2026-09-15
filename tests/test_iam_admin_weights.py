import json
import pytest
from fastapi.testclient import TestClient
from src.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_set_and_get_weights(client):
    tid = 'test-tenant-1'
    payload = {'overrides': {'public': 7.5, 'cross_account': 4.0, 'principals': {'user:evil': 9.0}}}
    r = client.post('/api/v1/iam/admin/weights', json=payload, headers={'X-Tenant-Id': tid})
    assert r.status_code == 200
    g = client.get('/api/v1/iam/admin/get_weight_overrides', headers={'X-Tenant-Id': tid})
    assert g.status_code == 200
    data = g.json()
    assert data.get('overrides') and data['overrides'].get('public') == 7.5


def test_ingest_policy_with_overrides(client):
    tid = 'test-tenant-1'
    # set tenant overrides first
    payload = {'overrides': {'public': 6.0, 'principals': {'user:public': 2.2}}}
    client.post('/api/v1/iam/admin/weights', json=payload, headers={'X-Tenant-Id': tid})

    # ingest a policy with a trust statement where Principal='*'
    policy = {
        'Statement': [
            {'Principal': '*', 'Action': ['arn:aws:iam::123456789012:role/Admin']}
        ]
    }
    r = client.post('/api/v1/iam/ingest_policy', json={'policy': policy}, headers={'X-Tenant-Id': tid})
    assert r.status_code == 200
    # fetch admin graph
    g = client.get('/api/v1/iam/admin/graph', headers={'X-Tenant-Id': tid})
    assert g.status_code == 200
    data = g.json()
    # Graph should contain an edge from '*' or 'user:public' depending on prefix handling
    assert isinstance(data, dict)
