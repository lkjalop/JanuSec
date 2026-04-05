from fastapi.testclient import TestClient
from src.api.app import create_app


def test_policy_ingest_and_admin_graph():
    app = create_app()
    client = TestClient(app)

    policy = {
        'Statement': [
            {'Effect': 'Allow', 'Action': ['iam:CreateAccessKey', 's3:PutObject'], 'Principal': {'AWS': ['user:svc1', 'user:svc2']}}
        ]
    }

    r = client.post('/api/v1/iam/ingest_policy', json={'policy': policy, 'principal_prefix': ''})
    assert r.status_code == 200

    # Admin graph dump (test helpers enabled in pytest env should allow access)
    r = client.get('/api/v1/iam/admin/graph')
    assert r.status_code == 200
    data = r.json()
    assert 'actions' in data and isinstance(data['actions'], dict)


def test_admin_feedback_and_evals_listed():
    app = create_app()
    client = TestClient(app)

    # post some feedback
    r = client.post('/api/v1/iam/feedback', json={'principal': 'user:svc1', 'action': 'iam:CreateAccessKey', 'verdict': 'fp', 'comment': 'test'})
    assert r.status_code == 200

    r = client.get('/api/v1/iam/admin/feedback')
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data.get('feedback', []), list)
