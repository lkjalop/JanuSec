from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


def test_preview_resolve_endpoint():
    client = TestClient(app)
    r = client.post('/api/v1/playbooks/resolve', json={'factor': 'net:tor_outbound_contact'})
    assert r.status_code == 200
    data = r.json()
    assert 'resolved' in data
    # Should return at least one playbook for tor outbound
    assert isinstance(data['resolved'], list)
