from fastapi.testclient import TestClient
from src.api.app import app


def test_kape_upload_endpoint():
    client = TestClient(app)
    sample = "chrome.exe-1A2B3C4D.pf - LastRun: 2024-01-01 12:00:00 - Count: 5\nRun: MyApp = C:\\Tools\\myapp.exe /quiet"
    files = {'file': ('sample.kape', sample)}
    r = client.post('/api/v1/kape/upload?async_process=false&trigger_sandbox=true', files=files, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert j.get('processed', 0) >= 1
    # ensure upload persisted on disk
    import os
    uploads_dir = os.getenv('KAPE_UPLOAD_DIR', os.path.join('data','uploads','kape'))
    found = False
    if os.path.exists(uploads_dir):
        for p in os.listdir(uploads_dir):
            if 'sample.kape' in p:
                found = True
                break
    assert found
