import asyncio
from io import BytesIO
from fastapi import UploadFile

from src.api.csv_endpoints import inspect_csv


def test_inspect_csv_basic():
    csv_content = b"user,host,ts\nAlice,H1,2025-11-07T12:30:00\nBob,H2,2025-11-07T12:31:00\nCharlie,H3,2025-11-07T12:32:00\n"
    uf = UploadFile(filename="sample.csv", file=BytesIO(csv_content))
    res = asyncio.get_event_loop().run_until_complete(inspect_csv(uf))
    assert res['delimiter'] == ','
    assert 'user' in res['headers']
    assert res['types']['user']['type'] == 'string'
    assert res['types']['ts']['type'] in {'datetime','string'}
    assert res['row_count'] == 3
    assert 'mapping_suggestions' in res
