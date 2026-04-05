import importlib
import json
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient


def test_hopgraph_snapshot_restore_http(tmp_path, monkeypatch):
    # enable persistence first
    db = tmp_path / 'test_hopgraph_http.db'
    monkeypatch.setenv('HOPGRAPH_PERSISTENCE_ENABLED', 'true')
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(db))

    # reload hopgraph_lite so it initializes backend
    from src.core.graph import hopgraph_lite
    importlib.reload(hopgraph_lite)
    g = hopgraph_lite.get_graph()
    assert getattr(g, 'backend', None) is not None

    # Ensure our API uses this graph instance by patching internal getter
    import src.api.hopgraph_persistence as hp
    hp._get_hopgraph = lambda: g

    # Import app and ensure GLOBAL_HOPGRAPH points to our test instance to avoid startup heavy init
    import src.api.app as appmod
    try:
        appmod.GLOBAL_HOPGRAPH = g
    except Exception:
        pass
    from src.api.app import app
    client = TestClient(app)

    # Observe some events via the in-memory API
    g.observe({'user': 'bob', 'host': 'host-B', 'edge_type': 'auth'})
    g.observe({'user': 'bob', 'proc': 'remotetool', 'edge_type': 'proc'})
    time.sleep(0.02)

    # Snapshot via HTTP
    r = client.post('/api/v1/hopgraph/snapshot')
    assert r.status_code == 200
    data = r.json()
    assert data.get('ok') is True
    snap = data.get('snapshot')
    assert 'nodes' in snap and 'edges' in snap

    # Clear graph state and then restore via HTTP
    try:
        hopgraph_lite._default_graph = None
    except Exception:
        pass
    # create a fresh graph instance and wire hp getter to it
    importlib.reload(hopgraph_lite)
    g2 = hopgraph_lite.get_graph()
    hp._get_hopgraph = lambda: g2

    # Restore using same snapshot
    rr = client.post('/api/v1/hopgraph/restore', json={'nodes': snap.get('nodes', {}), 'edges': snap.get('edges', [])})
    assert rr.status_code == 200
    assert rr.json().get('ok') is True

    # backend should now contain edges
    loaded = g2.backend.load_graph()
    assert len(loaded.get('edges', [])) >= 1
