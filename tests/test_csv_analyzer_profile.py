import io, os
from fastapi.testclient import TestClient
import src.api.server  # ensure routers
from src.api.app import app

client = TestClient(app)

def _make_csv(text: str):
    return io.BytesIO(text.encode('utf-8'))

def test_csv_profile_basic():
    csv = 'user,host,proc\nalice,h1,p1\nalice,h2,p2\nbob,h1,p3\n,,'
    files = {'file': ('sample.csv', csv, 'text/csv')}
    r = client.post('/api/v1/csv/analyze', files=files)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j['row_count'] == 4
    assert 'user' in j['columns']
    user_prof = j['columns']['user']
    assert user_prof['distinct'] >= 2
    assert user_prof['nulls'] >= 1
    assert isinstance(user_prof['entropy'], float)

def test_csv_profile_entropy_range():
    csv = 'val\nA\nA\nA\nA\nA\n'
    files = {'file': ('x.csv', csv, 'text/csv')}
    r = client.post('/api/v1/csv/analyze', files=files)
    assert r.status_code == 200
    ent = r.json()['columns']['val']['entropy']
    assert ent <= 0.01

def test_csv_profile_top_values():
    csv = 'col\nA\nB\nC\nA\nB\nA\n'
    files = {'file': ('y.csv', csv, 'text/csv')}
    r = client.post('/api/v1/csv/analyze', files=files)
    assert r.status_code == 200
    top = r.json()['columns']['col']['top_values']
    assert top[0] == 'A'
