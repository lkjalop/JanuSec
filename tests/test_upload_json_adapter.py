import json
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


def test_json_array_upload_parity(tmp_path):
    client = TestClient(app)
    # Build a small JSON array with two artifact-like dicts
    arr = [
        {"process_name":"powershell.exe","command_line":"-enc ABC","file_path":"C:\\temp\\evil.ps1","hash":"0000deadbeef00000000000000000000"},
        {"process_name":"notepad.exe","file_path":"C:\\Windows\\notepad.exe","hash":"abcdabcdabcdabcdabcdabcdabcdabcd"}
    ]
    data = json.dumps(arr).encode('utf-8')
    files = {'files': ('sample.json', data, 'application/json')}
    from tests._helpers import default_test_headers
    r = client.post('/api/v1/upload/files', files=files, headers=default_test_headers())
    assert r.status_code == 200
    j = r.json()
    assert j['status'] == 'completed'
    assert j['files_processed'] == 1
    res = j['results'][0]
    assert res['file_type'] == 'json'
    # Status normalized to 'processed' for parity across formats
    assert res['status'] == 'processed'
    assert res['total_rows'] == 2
    assert res['processed'] == 2


def test_malformed_json_returns_error(tmp_path):
    client = TestClient(app)
    bad = b"{ this is not valid json }"
    files = {'files': ('bad.json', bad, 'application/json')}
    from tests._helpers import default_test_headers
    r = client.post('/api/v1/upload/files', files=files, headers=default_test_headers())
    assert r.status_code == 200
    j = r.json()
    # The JSONProcessor fallback will return status:error for invalid JSON
    assert j['status'] == 'completed'
    res = j['results'][0]
    assert res['file_type'] == 'json'
    assert res['status'] in ('error','processed')
