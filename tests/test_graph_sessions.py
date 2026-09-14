import time
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_build_session_invalid_alpha(client):
    payload = {
        'session_ids': ['a', 'b'],
        'ewma': True,
        'ewma_alpha': 1.5,  # invalid >1
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 400


def test_build_session_returns_and_stores(client):
    payload = {
        'session_ids': ['batch-aaa', 'batch-bbb', 'batch-ccc'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'mapping': {'user': 'user', 'host': 'host'}
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200
    j = r.json()
    # Expect wrapper with session_id and structured summary
    assert 'session_id' in j
    assert 'summary' in j
    summary = j['summary']
    assert isinstance(summary, dict)
    # factors should be present; either structured dicts (batch_missing) or algorithmic strings
    assert 'factors' in summary
    assert isinstance(summary['factors'], list)
    # GET the stored session
    sid = j['session_id']
    r2 = client.get(f'/api/v1/graph/session/{sid}')
    assert r2.status_code == 200
    j2 = r2.json()
    # Require wrapper shape on GET: {'session_id': sid, 'summary': {...}}
    assert isinstance(j2, dict)
    assert 'session_id' in j2 and j2['session_id'] == sid
    assert 'summary' in j2 and isinstance(j2['summary'], dict)
    s2 = j2['summary']
    assert 'confidence' in s2
