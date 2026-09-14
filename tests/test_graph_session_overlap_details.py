import pytest
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def test_overlap_details_present():
    payload = {
        'session_ids': ['batch-overlap-A','batch-overlap-B'],
        'correlate': True,
        'ewma': False,
        'mapping': {'user':'user','host':'host','ip':'ip','file_hash':'file_hash','domain':'domain'}
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    summary = data.get('summary') or {}
    details = summary.get('overlap_details') or {}
    # At least one direction should appear; handle either A->B or B->A
    pair = details.get('batch-overlap-A', {}).get('batch-overlap-B', {}) or details.get('batch-overlap-B', {}).get('batch-overlap-A', {})
    assert pair, 'overlap_details missing for pair'
    assert 'user' in pair and 'alice' in pair['user']
    assert 'domain' in pair and 'shared.local' in pair['domain']
    # ip overlap 10.0.0.5
    assert 'ip' in pair and '10.0.0.5' in pair['ip']