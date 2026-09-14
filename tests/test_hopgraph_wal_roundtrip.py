import os, time, json
from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend
from src.graph.hopgraph import HopGraph


def test_wal_roundtrip(tmp_path, monkeypatch):
    dbp = tmp_path / 'hopgraph.db'
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(dbp))
    # Create backend and write wal records via backend API
    be = SQLiteHopGraphBackend(str(dbp))
    recs = [
        {'seq':1,'op':'edge','src':'n1','dst':'n2','etype':'connect','ts':1000,'attrs':{},'w':1.0},
        {'seq':2,'op':'edge','src':'n2','dst':'n3','etype':'connect','ts':1001,'attrs':{},'w':1.0},
        {'seq':3,'op':'attr','node':'n3','attrs':{'type':'host'}}
    ]
    for r in recs:
        be.save_wal_record(r['seq'], r['op'], r, None)
    # Now load into HopGraph via load_snapshot (which replays wal)
    # create a HopGraph with snapshot paths pointing to tmp files
    hg = HopGraph(wal_path=str(tmp_path/'hopgraph_wal.log'), snapshot_path=str(tmp_path/'hopgraph_snapshot.json'))
    # attach backend so _append_wal knows about save
    hg.backend = be
    # Manually invoke load_snapshot which will read DB WAL via fallback; since load_snapshot reads file WAL,
    # call backend.load_wal and replay entries into hg
    wal = be.load_wal()
    for w in wal:
        rec = w.get('rec') or {}
        if rec.get('op') == 'edge':
            hg.add_edge(rec.get('src'), rec.get('dst'), rec.get('etype'), rec.get('srcv') or 'db', rec.get('ts'), rec.get('attrs'), rec.get('w'))
        elif rec.get('op') == 'attr':
            hg.add_node_attr(rec.get('node'), **(rec.get('attrs') or {}))
    # validate nodes/edges present
    assert 'n1' in hg.adj
    assert any(e[0]=='n2' for e in hg.adj.get('n1',[]))
    assert 'n3' in hg.nodes