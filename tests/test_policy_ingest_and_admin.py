import os
import json
import time
from fastapi.testclient import TestClient

from src.api.app import create_app


def test_parse_policy_document_basic():
    from src.domains.iam.policy_ingest import parse_policy_document
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/SomeRole"},
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/TargetRole"
            }
        ]
    }
    pas, edges = parse_policy_document(policy)
    assert any('sts:AssumeRole' in a for (_p, acts) in pas for a in acts)
    assert len(edges) == 1
    e = edges[0]
    assert e['from'].startswith('arn:')
    assert e['to'].startswith('arn:')


def test_admin_endpoints_roundtrip(monkeypatch):
    # Enable test helpers so admin_guard passes
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    # Avoid heavy DB/network init during app startup
    monkeypatch.setenv('DISABLE_DB', '1')
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    app = create_app()
    client = TestClient(app)

    # post some feedback (include tenant in body to avoid any router query parsing issues)
    r = client.post('/api/v1/iam/admin/feedback', json={'note': 'test-feedback', 'tenant': 'global'})
    assert r.status_code == 200
    assert r.json().get('status') == 'ok'

    # get feedback
    r = client.get('/api/v1/iam/admin/feedback?tenant=global')
    assert r.status_code == 200
    data = r.json()
    assert data['tenant'] == 'global'
    assert isinstance(data.get('feedback'), list)

    # get evals (empty)
    r = client.get('/api/v1/iam/admin/evals?tenant=global')
    assert r.status_code == 200
    assert r.json().get('tenant') == 'global'
