"""Process-level helper to persist hopgraph data then check loaded state.

Usage:
  python scripts/persist_and_check.py persist --db ./data/test_hopgraph.db
  python scripts/persist_and_check.py check --db ./data/test_hopgraph.db
"""
import os
import sys
import argparse


def persist(db_path: str):
    os.environ['HOPGRAPH_PERSISTENCE_ENABLED'] = 'true'
    os.environ['HOPGRAPH_DB_PATH'] = db_path
    # Ensure local imports pick up env
    from src.core.graph import hopgraph_lite
    importlib = __import__('importlib')
    importlib.reload(hopgraph_lite)
    g = hopgraph_lite.get_graph()
    # Ingest some events
    g.observe({'user': 'alice', 'host': 'host-A', 'edge_type': 'auth'})
    g.observe({'user': 'alice', 'proc': 'pwnexec', 'edge_type': 'proc'})
    # If backend exists, confirm it saved
    be = getattr(g, 'backend', None)
    if be:
        snap = be.load_graph()
        print('persisted_nodes', len(snap.get('nodes', {})))
        print('persisted_edges', len(snap.get('edges', [])))
    else:
        print('no_backend')


def check(db_path: str):
    os.environ['HOPGRAPH_PERSISTENCE_ENABLED'] = 'true'
    os.environ['HOPGRAPH_DB_PATH'] = db_path
    from src.core.graph import hopgraph_lite
    importlib = __import__('importlib')
    importlib.reload(hopgraph_lite)
    g = hopgraph_lite.get_graph()
    be = getattr(g, 'backend', None)
    if be:
        snap = be.load_graph()
        print('loaded_nodes', len(snap.get('nodes', {})))
        print('loaded_edges', len(snap.get('edges', [])))
    else:
        print('no_backend')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['persist', 'check'])
    p.add_argument('--db', required=True)
    args = p.parse_args()
    if args.mode == 'persist':
        persist(args.db)
    else:
        check(args.db)


if __name__ == '__main__':
    main()
