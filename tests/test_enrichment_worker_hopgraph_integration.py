import os
import json
import time
import tempfile
from pathlib import Path

from src.graph.ingest import ingest_event
from src.graph.hopgraph import HopGraph, GLOBAL_HOPGRAPH
import graph.unified as _gu
from types import SimpleNamespace


def test_hopgraph_wal_written(tmp_path, monkeypatch):
    # Create a temporary wal file path
    wal_file = tmp_path / "test_hop_wal.log"
    # Point the global hopgraph WAL to our tmp file so UG routes to it
    hg = HopGraph(wal_path=str(wal_file))
    GLOBAL_HOPGRAPH.wal_path = str(wal_file)
    # Force the UnifiedGraph singleton to use our test hg instance so UG.add_edge
    # calls route to the tmp-file-backed HopGraph we created.
    _gu.UG._provider = SimpleNamespace(obj=hg, name='test', weight=100)
    # Ensure no pre-existing wal
    try:
        if wal_file.exists():
            wal_file.unlink()
    except Exception:
        pass

    # Ensure deterministic so ordering doesn't change
    monkeypatch.setenv('HOPGRAPH_DETERMINISTIC', '1')

    ev = {
        'src_host': 'host123',
        'dst_ip': '10.0.0.5',
        'domain': 'example.com',
        'process': 'evilproc',
        'ts': time.time(),
    }

    # Call ingest_event which should route to UG -> HopGraph add_edge -> append WAL
    ingest_event(ev, source='test_integration')

    # Read WAL file and assert at least one line exists with op edge
    assert wal_file.exists(), f"WAL file {wal_file} not created"
    data = wal_file.read_text(encoding='utf-8').strip().splitlines()
    assert len(data) >= 1
    # Parse last JSON record
    rec = json.loads(data[-1])
    assert rec.get('op') == 'edge'
    # ensure src/dst/etype present
    assert 'src' in rec and 'dst' in rec and 'etype' in rec
