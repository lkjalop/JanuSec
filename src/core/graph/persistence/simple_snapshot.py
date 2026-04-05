from __future__ import annotations
import os, time, json
from pathlib import Path
from typing import Optional

SNAPSHOT_BASE = os.path.join(os.getcwd(), 'data', 'hopgraph_snapshots')

def ensure_dir(path: str):
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

def persist_snapshot(tenant: Optional[str], snapshot: dict) -> str:
    """Persist a hopgraph snapshot for a tenant.

    If a SQLite backend is available (HOPGRAPH_DB_PATH or importable), write
    nodes and edges into that DB. Otherwise fallback to file-based snapshot.
    Returns the filepath or DB path used (best-effort string).
    """
    # Prefer SQLite backend when available
    try:
        db_path = os.getenv('HOPGRAPH_DB_PATH')
        if db_path:
            try:
                from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend
                backend = SQLiteHopGraphBackend(db_path)
                # snapshot expected to be {'nodes': {...}, 'edges': [...]}
                written_nodes = 0
                written_edges = 0
                for nid, meta in (snapshot.get('nodes') or {}).items():
                    try:
                        backend.save_node(nid, meta.get('type', 'unknown'), meta.get('metadata') or {}, tenant=tenant)
                        written_nodes += 1
                    except Exception:
                        continue
                for e in (snapshot.get('edges') or []):
                    try:
                        backend.save_edge(e.get('src'), e.get('dst'), e.get('etype') or 'edge', float(e.get('weight') or 1.0), e.get('metadata') or {}, tenant=tenant)
                        written_edges += 1
                    except Exception:
                        continue
                # debug trace for test investigation
                try:
                    import json
                    dbg = {'db_path': db_path, 'written_nodes': written_nodes, 'written_edges': written_edges}
                    with open('tmp_persist_debug.json','w',encoding='utf-8') as fh:
                        fh.write(json.dumps(dbg))
                except Exception:
                    pass
                return db_path
            except Exception:
                pass
    except Exception:
        pass
    # Fallback to file-based snapshot
    tdir = os.path.join(SNAPSHOT_BASE, tenant or 'global')
    ensure_dir(tdir)
    fname = f"snapshot_{int(time.time())}.json"
    path = os.path.join(tdir, fname)
    try:
        with open(path, 'w', encoding='utf8') as fh:
            json.dump({'ts': time.time(), 'tenant': tenant, 'snapshot': snapshot}, fh)
        return path
    except Exception:
        return ''

def cleanup_old_snapshots(ttl_seconds: int) -> int:
    """Remove snapshot files older than ttl_seconds. Returns number removed."""
    removed = 0
    cutoff = time.time() - ttl_seconds
    base = SNAPSHOT_BASE
    if not os.path.exists(base):
        return removed
    for root, dirs, files in os.walk(base):
        for f in files:
            if not f.endswith('.json'):
                continue
            p = os.path.join(root, f)
            try:
                st = os.path.getmtime(p)
                if st < cutoff:
                    os.remove(p)
                    removed += 1
            except Exception:
                continue
    return removed
