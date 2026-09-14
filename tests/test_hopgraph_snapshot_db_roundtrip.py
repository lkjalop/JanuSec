import os, importlib, tempfile, json
from pathlib import Path
from src.core.graph.persistence.simple_snapshot import persist_snapshot
from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend


def test_snapshot_persist_to_sqlite(tmp_path, monkeypatch):
    dbp = tmp_path / 'hopgraph.db'
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(dbp))
    # prepare a small snapshot
    snap = {'nodes': {'n1': {'type':'host','metadata':{'name':'h1'}}}, 'edges': [{'src':'n1','dst':'n2','etype':'connect','weight':1.0,'metadata':{}}]}
    res = persist_snapshot('tenant-test', snap)
    # res should be DB path when backend took over
    assert res and str(dbp) in str(res)
    # validate via backend
    be = SQLiteHopGraphBackend(str(dbp))
    loaded = be.load_graph('tenant-test')
    assert 'nodes' in loaded and 'n1' in loaded['nodes']