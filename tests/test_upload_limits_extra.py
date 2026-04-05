from __future__ import annotations

import io
import os
import zipfile
from fastapi.testclient import TestClient


def _client():
    os.environ['PLATFORM_LITE_INIT'] = '1'
    from src.api.app import create_app
    app = create_app({'mode': 'test'})
    return TestClient(app)


def test_csv_truncation_flag(monkeypatch):
    client = _client()
    monkeypatch.setenv('MAX_CSV_ROWS', '100')
    # Generate CSV with header + 1000 rows
    lines = ['a,b,c'] + [f"{i},{i+1},{i+2}" for i in range(1000)]
    data = ('\n'.join(lines)).encode('utf-8')
    files = {'files': ('big.csv', data, 'text/csv')}
    r = client.post('/api/v1/upload/files', files=files, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    j = r.json()
    res = j['results'][0]
    assert res['analysis']['truncated'] is True


def test_json_truncation_flag(monkeypatch):
    client = _client()
    monkeypatch.setenv('MAX_JSON_RECORDS', '50')
    # Build JSON array with 500 items
    import json
    payload = json.dumps([{'i': i} for i in range(500)]).encode('utf-8')
    files = {'files': ('big.json', payload, 'application/json')}
    r = client.post('/api/v1/upload/files', files=files, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    res = r.json()['results'][0]
    assert res['analysis']['truncated'] is True


def test_zip_caps_member_skipped(monkeypatch):
    client = _client()
    monkeypatch.setenv('MAX_ARCHIVE_MEMBERS', '1')
    # Create an in-memory ZIP with 3 small CSVs
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w') as z:
        for idx in range(3):
            z.writestr(f'm{idx}.csv', 'h1,h2\n1,2\n3,4\n')
    bio.seek(0)
    files = {'files': ('bundle.zip', bio.getvalue(), 'application/zip')}
    r = client.post('/api/v1/upload/files', files=files, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    res = r.json()['results'][0]
    summaries = res['analysis']['member_summaries']
    assert any(s.get('skipped') == 'limits_exceeded' for s in summaries)


def test_non_json_post_guard(monkeypatch):
    client = _client()
    # Post plain text to a JSON-expecting route
    r = client.post('/api/v1/integrations/slack/config', data='not-json', headers={'x-api-key': 'devkey123', 'Content-Type': 'text/plain'})
    assert r.status_code in (400, 415)

