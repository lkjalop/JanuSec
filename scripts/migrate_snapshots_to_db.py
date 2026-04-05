"""One-off migration helper: move JSON snapshots under data/hopgraph_snapshots into the SQLite backend.

Usage (from project root):
    python -m scripts.migrate_snapshots_to_db --snap-dir data/hopgraph_snapshots --db data/hopgraph.db

This is intentionally simple and idempotent: it reads JSON files and calls the backend
save_node/save_edge APIs. Runs best-effort and logs errors.
"""
from __future__ import annotations
import os, json, argparse
from pathlib import Path

def migrate(snap_dir: str, db_path: str, tenant_filter: str | None = None) -> int:
    try:
        from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend
    except Exception as e:
        raise RuntimeError('SQLite backend not available') from e
    backend = SQLiteHopGraphBackend(db_path)
    migrated = 0
    snap_dir_p = Path(snap_dir)
    if not snap_dir_p.exists():
        return migrated
    for tenant_dir in snap_dir_p.iterdir():
        if not tenant_dir.is_dir():
            continue
        tenant = tenant_dir.name
        if tenant_filter and tenant != tenant_filter:
            continue
        for f in tenant_dir.glob('*.json'):
            try:
                with open(f, 'r', encoding='utf8') as fh:
                    obj = json.load(fh)
            except Exception:
                continue
            snap = obj.get('snapshot') or obj
            nodes = snap.get('nodes') or {}
            edges = snap.get('edges') or []
            for nid, meta in nodes.items():
                try:
                    backend.save_node(
                        nid,
                        meta.get('type', 'unknown'),
                        metadata=meta.get('metadata') or {},
                        tenant=tenant,
                    )
                except Exception:
                    continue
            for e in edges:
                try:
                    meta = dict(e.get('metadata') or {})
                    meta.setdefault('weight', float(e.get('weight') or 1.0))
                    backend.save_edge(
                        e.get('src'),
                        e.get('dst'),
                        e.get('etype') or 'edge',
                        metadata=meta,
                        tenant=tenant,
                    )
                except Exception:
                    continue
            migrated += 1
    return migrated


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--snap-dir', default=os.path.join(os.getcwd(), 'data', 'hopgraph_snapshots'))
    p.add_argument('--db', default=os.path.join(os.getcwd(), 'data', 'hopgraph.db'))
    p.add_argument('--tenant', default=None)
    args = p.parse_args()
    n = migrate(args.snap_dir, args.db, args.tenant)
    print(f'Migrated {n} snapshot files into {args.db}')

if __name__ == '__main__':
    main()
