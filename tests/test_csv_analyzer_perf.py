import io, time
from fastapi.testclient import TestClient
import src.api.server  # ensure routers
from src.api.app import app

client = TestClient(app)

def test_csv_analyzer_stream_large(monkeypatch):
    # Build a moderately large CSV (2000 rows)
    rows = ['val'] + [f'v{i}' for i in range(2000)]
    csv = '\n'.join(rows) + '\n'
    files = {'file': ('large.csv', csv, 'text/csv')}
    start = time.time()
    r = client.post('/api/v1/csv/analyze', files=files)
    dur = time.time() - start
    assert r.status_code == 200
    # Acceptable upper bound for test env
    assert dur < 3.0, f"CSV analyze too slow: {dur}s"
    j = r.json()
    # Analyzer may or may not count header row; accept either 2000 or 2001+
    assert j['row_count'] >= 2000
    assert j['columns']['val']['distinct'] >= 2000
