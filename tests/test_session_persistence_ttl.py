import os, time, json
from fastapi.testclient import TestClient
from pathlib import Path

from src.api.app import create_app
app = create_app({'mode': 'test'})

def test_session_persistence_and_reload(monkeypatch, tmp_path):
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    # point session dir to temp
    sess_dir = tmp_path / 'sessions'
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(sess_dir))
    client = TestClient(app)
    from src.api.runtime_state import get_file_batch_analysis, get_server_runtime_state
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb['batch-X'] = {'files': [{'sha256':'h1'},{'sha256':'h2'}]}
    r = client.post('/api/v1/graph/session/build', json={'session_ids':['batch-X'], 'correlate':True, 'ewma':True})
    assert r.status_code == 200
    sid = r.json().get('session_id')
    assert sid
    # file should exist
    path = sess_dir / f'{sid}.json'
    assert path.exists()
    # clear in-memory and GET should reload from disk
    fb.pop(f'session:{sid}', None)
    g = client.get(f'/api/v1/graph/session/{sid}')
    assert g.status_code == 200
    data = g.json()
    assert data.get('session_id') == sid

def test_ewma_ttl_pruning(monkeypatch):
    from src.api.runtime_state import get_server_runtime_state, cleanup_ewma_history, get_ewma_history
    monkeypatch.setenv('TEST_HELPERS_ENABLED','1')
    runtime = get_server_runtime_state(app)
    hist = get_ewma_history(runtime)
    # seed two entries: one old, one recent
    now = time.time()
    hist['A|B'] = (5.0, now - 90000)  # older than 1 day (86400)
    hist['C|D'] = (2.0, now)
    cleanup_ewma_history(runtime, ttl_seconds=86400)
    assert 'A|B' not in hist and 'C|D' in hist