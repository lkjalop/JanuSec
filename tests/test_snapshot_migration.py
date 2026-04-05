import os, json
from pathlib import Path
from src.core.graph.persistence.simple_snapshot import persist_snapshot
from scripts.migrate_snapshots_to_db import migrate
from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend


def test_migrate_snapshots_to_db(tmp_path, monkeypatch):
    # create a fake snapshot file under data/hopgraph_snapshots/tenant-x/
    d = tmp_path / 'data' / 'hopgraph_snapshots' / 'tenant-x'
    d.mkdir(parents=True)
    snap_file = d / 'snapshot_1.json'
    snapshot = {'nodes': {'nA': {'type':'host','metadata':{'ip':'1.2.3.4'}}}, 'edges': [{'src':'nA','dst':'nB','etype':'conn','weight':1.0,'metadata':{}}]}
    with open(snap_file, 'w', encoding='utf8') as fh:
        json.dump({'ts': 1, 'tenant':'tenant-x', 'snapshot': snapshot}, fh)
    # set db path to tmp
    dbp = tmp_path / 'hopgraph.db'
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(dbp))
    n = migrate(str(tmp_path / 'data' / 'hopgraph_snapshots'), str(dbp))
    assert n >= 1
    be = SQLiteHopGraphBackend(str(dbp))
    loaded = be.load_graph('tenant-x')
    assert 'nA' in loaded.get('nodes', {})
