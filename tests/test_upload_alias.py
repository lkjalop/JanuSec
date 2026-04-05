import json
import os

from fastapi.testclient import TestClient

from src.api.server import app
from tests._helpers import default_test_headers

client = TestClient(app)

def test_upload_tabular_alias_csv(tmp_path):
    data = 'col1,col2\nval1,val2\n'
    files = {'files': ('sample.csv', data, 'text/csv')}
    r = client.post('/api/v1/upload/tabular', files=files, headers=default_test_headers())
    assert r.status_code == 200, r.text
    js = r.json()
    assert js['status'] == 'completed'
    assert js['files_processed'] == 1
    assert any(f.get('file_type') == 'csv' for f in js['results'])


def test_upload_tabular_alias_excel_dependency():
    # Create a fake xlsx header to trigger excel detection but openpyxl may be missing.
    # Excel files are ZIP archives starting with PK
    fake = b'PK' + b'\x03\x04' + b'RANDOMCONTENT'
    files = {'files': ('sample.xlsx', fake, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
    r = client.post('/api/v1/upload/tabular', files=files, headers=default_test_headers())
    assert r.status_code == 200
    js = r.json()
    # Either processed as archive/unknown or error with openpyxl guidance
    assert js['files_processed'] == 1
    # Ensure we surface a result entry
    assert len(js['results']) == 1
    res = js['results'][0]
    assert 'status' in res
    # If error, helpful message
    if res['status'] == 'error':
        assert 'openpyxl' in (res.get('error','').lower()) or 'Failed to parse'.lower() in res.get('error','').lower()
