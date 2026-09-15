import os
import time
import json
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
API_KEY = os.getenv('TEST_API_KEY','devkey123')
HEADERS = {'x-api-key': API_KEY}

def make_session_payload(users=None, hosts=None, ips=None, hashes=None, domains=None):
    return {
        'entities': {
            'user': users or [],
            'host': hosts or [],
            'ip': ips or [],
            'file_hash': hashes or [],
            'domain': domains or []
        }
    }

def test_persist_and_build_overlap(tmp_path, monkeypatch):
    # Ensure sessions dir isolated
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    from src.api import graph_session_endpoints as gse
    monkeypatch.setattr(gse, 'SESSION_PERSIST_DIR', str(tmp_path))

    s1 = make_session_payload(users=['alice'], hosts=['host1'], ips=['10.0.0.1'], hashes=['h1'], domains=['d1'])
    s2 = make_session_payload(users=['bob','alice'], hosts=['host2'], ips=['10.0.0.2','10.0.0.1'], hashes=['h2'], domains=['d2'])

    # Persist via inline sessions
    r = client.post('/api/v1/graph/session/build', headers=HEADERS, json={'sessions':[{'id':'s1','data':s1},{'id':'s2','data':s2}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'correlation' in body
    corr = body['correlation']
    # diagonal should be > 0
    assert corr[0][0] > 0 and corr[1][1] > 0
    # there is overlap on user 'alice' and ip '10.0.0.1' => off-diagonal > 0
    assert corr[0][1] >= 1

def test_ewma_adaptive_alpha(tmp_path, monkeypatch):
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    monkeypatch.setenv('ADAPTIVE_EWMA','1')
    from src.api import graph_session_endpoints as gse
    monkeypatch.setattr(gse, 'SESSION_PERSIST_DIR', str(tmp_path))
    monkeypatch.setattr(gse, 'ADAPTIVE_EWMA', True)

    s1 = make_session_payload(users=['u1'], ips=['1.1.1.1'])
    s2 = make_session_payload(users=['u2'], ips=['2.2.2.2'])
    r = client.post('/api/v1/graph/session/build', headers=HEADERS, json={'sessions':[{'id':'a','data':s1},{'id':'b','data':s2}], 'ewma': True})
    assert r.status_code == 200
    body = r.json()
    assert 'ewma_alpha' in body
    alpha = body['ewma_alpha']
    assert 0.0 <= alpha <= 1.0
