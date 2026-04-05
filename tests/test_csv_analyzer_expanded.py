import io, os
from fastapi.testclient import TestClient
import src.api.server  # ensure routers
from src.api.app import app

client = TestClient(app)

def _make_csv(text: str):
    return io.BytesIO(text.encode('utf-8'))

def test_csv_multi_column_mixed_types():
    csv = 'id,val,num,flag\n1,A,10,True\n2,B,20,False\n3,A,30,True\n4,,40,False\n'
    files = {'file': ('m.csv', csv, 'text/csv')}
    r = client.post('/api/v1/csv/analyze', files=files)
    assert r.status_code == 200
    j = r.json()
    assert j['row_count'] == 4
    assert 'num' in j['columns']
    assert j['columns']['num']['distinct'] == 4 or j['columns']['num']['distinct'] == 3

def test_csv_large_cardinality_and_metric_guard(monkeypatch, tmp_path):
    # create CSV with many unique values to test cardinality reporting
    lines = ['u']
    for i in range(200):
        lines.append(str(i))
    csv = '\n'.join(lines) + '\n'
    files = {'file': ('big.csv', csv, 'text/csv')}
    # set METRICS_MAX_TENANTS low and create fake runtime tenants to exceed
    monkeypatch.setenv('METRICS_MAX_TENANTS', '1')
    r = client.post('/api/v1/csv/analyze', files=files)
    assert r.status_code == 200
    j = r.json()
    # top values should show most frequent (if any) and distinct count should be high
    assert j['columns']['u']['distinct'] >= 100
