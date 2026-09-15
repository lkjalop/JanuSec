from fastapi.testclient import TestClient

from src.api.server import app
from tests._helpers import default_test_headers


client = TestClient(app)


def test_ingestion_report_persists_and_replays():
    headers = default_test_headers()
    response = client.get('/api/v1/report/ingestion?include_alerts=false&format=json&persist=true', headers=headers)
    assert response.status_code == 200
    body = response.json()
    report_id = body.get('report_id')
    assert report_id

    listing = client.get('/api/v1/reports', headers=headers)
    assert listing.status_code == 200
    assert any(item.get('report_id') == report_id for item in listing.json().get('reports', []))

    artifact = client.get(f'/api/v1/reports/{report_id}', headers=headers)
    assert artifact.status_code == 200
    artifact_body = artifact.json()
    assert artifact_body['report_id'] == report_id
    assert artifact_body['payload']['report_id'] == report_id

    html = client.get(f'/api/v1/reports/{report_id}/artifact?format=html', headers=headers)
    assert html.status_code == 200
    assert 'severity distribution' in html.text.lower()


def test_generate_report_html_emits_report_id_header():
    headers = default_test_headers()
    payload = {
        'tenant_id': 'default',
        'title': 'Generated Report',
        'rows': [{'id': 'row-1', 'summary': 'sample'}],
        'summary': {'title': 'Generated Report'},
    }
    response = client.post('/api/v1/report/generate?format=html&persist=true', json=payload, headers=headers)
    assert response.status_code == 200
    report_id = response.headers.get('X-Report-Id')
    assert report_id

    artifact = client.get(f'/api/v1/reports/{report_id}', headers=headers)
    assert artifact.status_code == 200
    assert artifact.json()['payload']['report_id'] == report_id
