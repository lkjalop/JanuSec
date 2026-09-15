"""Lightweight soak helper for SQLite HopGraph persistence.

Usage: python scripts/hopgraph_persist_soak.py --edges 5000 --snap 5 --prune 10
"""
from __future__ import annotations

import os
import time
import argparse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--edges', type=int, default=2000)
    ap.add_argument('--snap', type=int, default=0, help='snapshot interval seconds')
    ap.add_argument('--prune', type=int, default=0, help='prune interval seconds')
    args = ap.parse_args()

    os.environ['HOPGRAPH_PERSISTENCE_ENABLED'] = 'true'
    os.environ.setdefault('HOPGRAPH_DB_PATH', 'data/hopgraph.db')
    if args.snap:
        os.environ['HOPGRAPH_SNAPSHOT_INTERVAL_SECONDS'] = str(args.snap)
    if args.prune:
        os.environ['HOPGRAPH_PRUNE_INTERVAL_SECONDS'] = str(args.prune)

    from src.core.graph import hopgraph_lite
    g = hopgraph_lite.get_graph()
    now = time.time()
    for i in range(args.edges):
        src = f'user:soak{i%50}'
        dst = f'ip:10.0.{(i//255)%255}.{i%255}'
        g.add_edge(src, dst, 'contacts', source='soak', ts=now + i, attrs={'i': i})
        if i and i % 1000 == 0:
            print('added', i, 'edges')
            time.sleep(0.01)
    # Allow background loops (if any) to run
    time.sleep(1.0)
    try:
        g.save_snapshot()
    except Exception:
        pass
    print('Soak completed. Edges (approx):', len(getattr(g, 'edges_ts', {})))

if __name__ == '__main__':
    main()

