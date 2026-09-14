import io
from fastapi.testclient import TestClient
from src.api.app import app


def test_upload_and_download_signed_report(tmp_path):
    client = TestClient(app)
    # Upload a small file
    data = b'example evidence content'
    files = {'file': ('evidence.txt', io.BytesIO(data), 'text/plain')}
    r = client.post('/api/v1/isms/evidence/upload', files=files, data={'summary': 'upload test'})
    assert r.status_code == 200
    js = r.json()
    assert js.get('ok') is True
    assert 'sha256' in js
    # List evidence includes uploaded manifest
    lst = client.get('/api/v1/isms/evidence')
    assert lst.status_code == 200
    assert lst.json().get('count', 0) >= 1
    # Download report with HMAC secret
    secret = 'test-secret'
    dl = client.get(f'/api/v1/isms/report/download?hmac_secret={secret}')
    assert dl.status_code == 200
    # Check signature header provided
    assert 'X-ISMS-HMAC-SIGNATURE' in dl.headers
    # A naive check: signature is hex string of length 64 for sha256
    sig = dl.headers['X-ISMS-HMAC-SIGNATURE']
    assert isinstance(sig, str) and len(sig) == 64
