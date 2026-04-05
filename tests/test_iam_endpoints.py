from fastapi.testclient import TestClient
from src.api.app import create_app


def test_multi_hop_escalation():
    app = create_app()
    client = TestClient(app)

    # Upsert principals and their actions (levels)
    r = client.post('/api/v1/iam/principal', json={'principal': 'user:alice', 'actions': [['read', 1]]})
    assert r.status_code == 200
    r = client.post('/api/v1/iam/principal', json={'principal': 'role:dev', 'actions': [['assume', 2]]})
    assert r.status_code == 200
    r = client.post('/api/v1/iam/principal', json={'principal': 'role:ops', 'actions': [['admin', 10]]})
    assert r.status_code == 200

    # Build delegation edges: alice -> role:dev -> role:ops
    r = client.post('/api/v1/iam/edge', json={'src': 'user:alice', 'dst': 'role:dev'})
    assert r.status_code == 200
    r = client.post('/api/v1/iam/edge', json={'src': 'role:dev', 'dst': 'role:ops'})
    assert r.status_code == 200

    # Query escalation to admin-level (10)
    r = client.post('/api/v1/iam/escalation', json={'start_principal': 'user:alice', 'target_level': 10})
    assert r.status_code == 200
    data = r.json()
    assert data['start'] == 'user:alice'
    assert data['target_node'] == 'role:ops'
    assert data['path'] == ['user:alice', 'role:dev', 'role:ops']
    assert data['risk'] > 0


def test_edge_validation_and_not_found():
    app = create_app()
    client = TestClient(app)

    # invalid edge (same src/dst)
    r = client.post('/api/v1/iam/edge', json={'src': 'a', 'dst': 'a'})
    assert r.status_code == 400

    # unknown principal escalation
    r = client.post('/api/v1/iam/escalation', json={'start_principal': 'no-such', 'target_level': 5})
    assert r.status_code == 404


def test_weighted_escalation_prefers_lower_cost_path():
    app = create_app()
    client = TestClient(app)

    # Build two paths to admin: user->role:a->role:ops and user->role:b->role:ops
    client.post('/api/v1/iam/principal', json={'principal': 'user:bob', 'actions': [['read',1]]})
    client.post('/api/v1/iam/principal', json={'principal': 'role:a', 'actions': [['assume',3]]})
    client.post('/api/v1/iam/principal', json={'principal': 'role:b', 'actions': [['assume',3]]})
    client.post('/api/v1/iam/principal', json={'principal': 'role:ops', 'actions': [['admin',10]]})

    # Path A has high weight on edge role:a->role:ops
    client.post('/api/v1/iam/edge', json={'src':'user:bob','dst':'role:a','weight':1.0})
    client.post('/api/v1/iam/edge', json={'src':'role:a','dst':'role:ops','weight':10.0})
    # Path B has cheaper edges
    client.post('/api/v1/iam/edge', json={'src':'user:bob','dst':'role:b','weight':1.0})
    client.post('/api/v1/iam/edge', json={'src':'role:b','dst':'role:ops','weight':1.0})

    r = client.post('/api/v1/iam/escalation/risk', json={'start_principal':'user:bob','target_level':10})
    assert r.status_code == 200
    data = r.json()
    assert data['path'] == ['user:bob','role:b','role:ops']
    assert 'cost' in data and data['cost'] < 5.0
    assert 'risk' in data and 0.0 <= data['risk'] <= 1.0
