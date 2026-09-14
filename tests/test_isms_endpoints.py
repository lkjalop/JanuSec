from fastapi.testclient import TestClient
from src.api.app import app


def test_isms_evidence_and_report():
    client = TestClient(app)
    # Post two evidence items with tags
    r1 = client.post('/api/v1/isms/evidence', json={'summary': 'scan result', 'tags': ['ctrl-A', 'network'], 'desc': 'port scan detected'})
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1.get('ok') is True
    r2 = client.post('/api/v1/isms/evidence', json={'summary': 'config check', 'tags': ['ctrl-A', 'config'], 'desc': 'weak cipher'})
    assert r2.status_code == 200
    # List evidence
    lst = client.get('/api/v1/isms/evidence')
    assert lst.status_code == 200
    j = lst.json()
    assert j.get('count', 0) >= 2
    # Get report summary
    rep = client.get('/api/v1/isms/report')
    assert rep.status_code == 200
    rj = rep.json()
    assert rj.get('total_evidence', 0) >= 2
    assert isinstance(rj.get('controls'), list)
