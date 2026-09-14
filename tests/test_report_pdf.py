import pytest
import json
import io

try:
    import weasyprint  # type: ignore
    HAS_WEASY = True
except Exception:
    HAS_WEASY = False


def make_payload():
    return {
        'title': 'Test Report',
        'rows': [{'process_name': 'test.exe', 'host': 'host1'}],
        'summary': {'rows': 1}
    }


@pytest.mark.skipif(not HAS_WEASY, reason='weasyprint not installed')
def test_generate_pdf_endpoint(test_client):
    payload = make_payload()
    resp = test_client.post('/api/v1/report/generate_pdf', json=payload)
    assert resp.status_code == 200
    assert resp.headers.get('content-type', '').startswith('application/pdf')
    # Check PDF magic bytes
    content = resp.content
    assert content[:4] == b'%PDF'
