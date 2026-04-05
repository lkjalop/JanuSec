"""Minimal HTTP server exposing snapshot/restore for HopGraph persistence tests.

Run: python scripts/hopgraph_snapshot_server.py --port 8081
"""
import os
import time
import argparse
from fastapi import FastAPI, HTTPException
import uvicorn

app = FastAPI()


def get_graph():
    from src.core.graph import hopgraph_lite
    importlib = __import__('importlib')
    importlib.reload(hopgraph_lite)
    return hopgraph_lite.get_graph()


@app.post('/snapshot')
def snapshot():
    try:
        from src.core.graph import hopgraph_lite
        g = hopgraph_lite.get_graph()
        if getattr(g, 'backend', None):
            data = g.backend.load_graph()
            return {'ok': True, 'snapshot': data}
        # Fallback
        return {'ok': True, 'snapshot': {'nodes': {}, 'edges': []}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/restore')
def restore(payload: dict):
    try:
        from src.core.graph import hopgraph_lite
        g = hopgraph_lite.get_graph()
        snap = payload.get('snapshot') or payload
        if getattr(g, 'backend', None):
            be = g.backend
            for nid, n in (snap.get('nodes') or {}).items():
                be.save_node(nid, n.get('type', 'unknown'), n.get('metadata', {}))
            for e in snap.get('edges', []):
                be.save_edge(e.get('src'), e.get('dst'), e.get('etype', 'link'), e.get('weight', 1.0), e.get('metadata', {}))
            return {'ok': True}
        raise HTTPException(status_code=500, detail='no_backend')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8081)
    args = parser.parse_args()
    uvicorn.run('scripts.hopgraph_snapshot_server:app', host='0.0.0.0', port=args.port, log_level='info')


if __name__ == '__main__':
    main()
