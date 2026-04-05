import importlib
import time
from pathlib import Path


def test_hopgraph_snapshot_and_restore(tmp_path, monkeypatch):
    """Enable persistence, create a graph, snapshot via backend, reset and ensure reload."""
    db_path = tmp_path / 'test_hopgraph.db'
    monkeypatch.setenv('HOPGRAPH_PERSISTENCE_ENABLED', 'true')
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(db_path))

    # Import module after env var set so backend is enabled on init
    from src.core.graph import hopgraph_lite
    importlib.reload(hopgraph_lite)

    # Get graph and add observations
    g = hopgraph_lite.get_graph()
    assert g is not None
    # Backend should be present when env var is set
    assert getattr(g, 'backend', None) is not None

    # Add a couple of events that create nodes/edges
    g.observe({'user': 'alice', 'host': 'host-A', 'edge_type': 'auth'})
    g.observe({'user': 'alice', 'proc': 'pwnexec', 'edge_type': 'proc'})

    # small sleep to allow any internal write
    time.sleep(0.05)

    snap = g.backend.load_graph()
    assert 'nodes' in snap and 'edges' in snap
    assert len(snap['nodes']) >= 1
    assert len(snap['edges']) >= 1

    # Simulate restart: drop module-level default and reload module
    try:
        hopgraph_lite._default_graph = None
    except Exception:
        pass
    importlib.reload(hopgraph_lite)
    g2 = hopgraph_lite.get_graph()
    assert getattr(g2, 'backend', None) is not None
    loaded = g2.backend.load_graph()
    assert len(loaded.get('edges', [])) >= 1
