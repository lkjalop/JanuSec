import io
import os
import gzip
import json
import zipfile
import random
import string

from typing import List

import pytest
from fastapi.testclient import TestClient


def _rand_rows(cols: List[str], n: int) -> List[List[str]]:
    rows: List[List[str]] = []
    for _ in range(n):
        r = []
        for c in cols:
            if 'hash' in c:
                r.append(''.join(random.choices('abcdef0123456789', k=32)))
            else:
                r.append('val_' + ''.join(random.choices(string.ascii_lowercase, k=5)))
        rows.append(r)
    return rows


@pytest.fixture(scope="module")
def client():
    from src.api.app import create_app  # import here so optional deps resolve lazily
    app = create_app({'mode': 'test'})
    return TestClient(app)


def _build_csv_bytes() -> bytes:
    cols = ['id', 'name', 'hash']
    rows = _rand_rows(cols, 15)
    buf = io.StringIO()
    buf.write(','.join(cols) + '\n')
    for r in rows:
        buf.write(','.join(r) + '\n')
    return buf.getvalue().encode()


def _build_json_bytes() -> bytes:
    data = [{"user": f"u{i}", "score": i * 3} for i in range(12)]
    return json.dumps(data).encode()


def _build_xlsx_bytes() -> bytes:
    try:
        import openpyxl  # type: ignore
    except Exception:  # pragma: no cover - dependency may be missing in minimal env
        pytest.skip("openpyxl not installed")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(['id', 'name', 'hash'])
    for r in _rand_rows(['id', 'name', 'hash'], 12):
        ws.append(r)
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def _build_ods_bytes() -> bytes:
    # Only attempt if pyexcel_ods3 available
    try:
        from pyexcel_ods3 import save_data  # type: ignore
    except Exception:  # pragma: no cover
        pytest.skip("pyexcel-ods3 not installed")
    from collections import OrderedDict
    data = OrderedDict()
    data.update({'Sheet1': [['id', 'name', 'hash']] + _rand_rows(['id','name','hash'], 10)})
    bio = io.BytesIO()
    save_data(bio, data)
    return bio.getvalue()


def _build_zip_csv_bundle() -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i in range(2):
            content = _build_csv_bytes()
            zf.writestr(f"part{i}.csv", content)
    return bio.getvalue()


def _gzip_bytes(payload: bytes) -> bytes:
    bio = io.BytesIO()
    with gzip.GzipFile(fileobj=bio, mode='wb') as gz:
        gz.write(payload)
    return bio.getvalue()


def _post_files(client: TestClient, files):
    return client.post(
        "/api/v1/upload/files",
        files=files,
        headers={"x-api-key": os.getenv("API_KEY", "devkey123")},
    )


def test_csv_ingestion(client: TestClient):
    csv_bytes = _build_csv_bytes()
    resp = _post_files(client, [("files", ("sample.csv", csv_bytes, "text/csv"))])
    assert resp.status_code == 200
    data = resp.json()
    r = data['results'][0]
    assert r['file_type'] == 'csv'
    assert r['status'] == 'processed'
    assert r['analysis']['row_count'] >= 10


def test_json_ingestion(client: TestClient):
    js_bytes = _build_json_bytes()
    resp = _post_files(client, [("files", ("records.json", js_bytes, "application/json"))])
    assert resp.status_code == 200
    r = resp.json()['results'][0]
    assert r['file_type'] == 'json'
    assert r['status'] == 'processed'
    assert r['analysis']['structure_type'] in {"array", "object"}


def test_xlsx_ingestion(client: TestClient):
    x_bytes = _build_xlsx_bytes()
    resp = _post_files(client, [("files", ("sample.xlsx", x_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))])
    assert resp.status_code == 200
    r = resp.json()['results'][0]
    assert r['file_type'] == 'excel'
    assert r['status'] == 'processed'
    assert r['analysis']['row_count_estimate'] >= 10


def test_ods_ingestion(client: TestClient):
    ods_bytes = _build_ods_bytes()
    resp = _post_files(client, [("files", ("sample.ods", ods_bytes, "application/vnd.oasis.opendocument.spreadsheet"))])
    # If dependency missing it would have skipped earlier
    assert resp.status_code == 200
    r = resp.json()['results'][0]
    # Could be processed or an explicit error if deps missing (skip ensures processed path)
    assert r['file_type'] == 'excel'
    assert r['status'] in {'processed'}


def test_zip_csv_bundle_ingestion(client: TestClient):
    z_bytes = _build_zip_csv_bundle()
    resp = _post_files(client, [("files", ("bundle.zip", z_bytes, "application/zip"))])
    assert resp.status_code == 200
    r = resp.json()['results'][0]
    assert r['file_type'] == 'archive'
    assert r['status'] == 'processed'
    assert r['analysis']['processed_members'] >= 1


def test_gzip_csv_ingestion(client: TestClient):
    gz_bytes = _gzip_bytes(_build_csv_bytes())
    resp = _post_files(client, [("files", ("compressed.csv.gz", gz_bytes, "application/gzip"))])
    assert resp.status_code == 200
    r = resp.json()['results'][0]
    # After decompression should classify as csv
    assert r['file_type'] == 'csv'
    assert r['status'] == 'processed'
