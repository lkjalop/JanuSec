from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def test_graph_session_path_and_phase_factors():
    payload = {
        'session_ids': ['fixed-A-1','fixed-B-2','fixed-C-3'],
        'correlate': True,
        'ewma': False
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    j = r.json()
    summary = j['summary']
    assert 'path_length' in summary
    assert 'distinct_phase_count' in summary
    factors = summary['factors']
    assert any(f.get('name') == 'path_length' for f in factors if isinstance(f, dict))
    assert any(f.get('name') == 'distinct_phase_count' for f in factors if isinstance(f, dict))
    # Ensure factors normalized to object form
    for f in factors:
        assert isinstance(f, dict) and 'name' in f
