from src.api.report_endpoints import generate_report
from fastapi.testclient import TestClient
from src.api.app import create_app


def test_report_xss_sanitized():
    app = create_app()
    client = TestClient(app)
    payload = {'summary': '<script>alert(1)</script>', 'rows': []}
    r = client.post('/api/v1/report/generate?format=html', json=payload)
    assert r.status_code == 200
    assert '<script>' not in r.text
