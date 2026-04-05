import io
import json
from pathlib import Path

from fastapi.testclient import TestClient
from src.api.app import app  # assuming app is defined here; adjust if different

client = TestClient(app)


def test_excel_upload_includes_headers_and_sample_rows():
    excel_path = Path('dump/Cyberstash_csv2.xlsx')
    if not excel_path.exists():
        raise RuntimeError('Test Excel file missing: dump/Cyberstash_csv2.xlsx')

    with excel_path.open('rb') as f:
        files = {'files': (excel_path.name, f.read(), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        r = client.post('/api/v1/upload/files', files=files, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    data = r.json()
    assert 'results' in data and isinstance(data['results'], list) and data['results'], 'No results returned'
    excel_result = data['results'][0]
    analysis = excel_result.get('analysis') or {}
    headers = analysis.get('headers')
    sample_rows = analysis.get('sample_rows')
    assert headers and isinstance(headers, list) and len(headers) > 0, 'Missing headers'
    assert sample_rows and isinstance(sample_rows, list) and len(sample_rows) > 0, 'Missing sample_rows'
    # If small workbook, full_rows should appear
    full_rows = analysis.get('full_rows')
    if analysis.get('row_count_estimate', 999999) <= 5000:
        assert isinstance(full_rows, list) and full_rows, 'Expected full_rows for small workbook'
    # Basic shape check: each row list length <= headers length
    if full_rows:
        assert all(isinstance(rw, list) for rw in full_rows)
        assert all(len(rw) <= len(headers) for rw in full_rows[:50])
