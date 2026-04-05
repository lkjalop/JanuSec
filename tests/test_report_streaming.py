from src.api.app import create_app
from fastapi.testclient import TestClient


def test_report_streaming_large():
    app = create_app()
    client = TestClient(app)
    # build a large HTML via summary repeated
    big = 'x' * 20000
    payload = {'summary': big, 'rows': ['r']*1000}
    r = client.post('/api/v1/report/generate?format=html', json=payload)
    assert r.status_code == 200
    # ensure content length present or streaming delivered
    assert len(r.content) > 1000
