"""Inspect HopGraph node and edge type counts for a dataset.

Usage:
  python -m scripts.inspect_graph_nodes --dataset data/benchmarking/benchmarks/benchmark_campaign_v3_1000_aligned2
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True)
    args = ap.parse_args()
    ds = Path(args.dataset)
    ev_path = ds / 'events.jsonl'
    if not ev_path.exists():
        print('No events.jsonl at', ev_path)
        return
    try:
        from src.graph.hopgraph import HopGraph
        hg = HopGraph(wal_path='data/benchmarking/inspect_wal.log', snapshot_path='data/benchmarking/inspect_snap.json')
    except Exception:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH as hg  # type: ignore
    # ingest
    with ev_path.open('r', encoding='utf-8') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                ev = json.loads(ln)
                if 'timestamp' not in ev and 'ts' in ev:
                    ev['timestamp'] = ev['ts']
                if 'file_hash' not in ev and 'sha256' in ev:
                    ev['file_hash'] = ev['sha256']
                if 'domain' not in ev and 'qname' in ev:
                    ev['domain'] = ev['qname']
                hg.ingest_event(ev, source='inspect')
            except Exception:
                continue
    # summarize
    node_type_counts = {}
    for nid, meta in hg.nodes.items():
        ntype = meta.get('type') or (nid.split(':',1)[0] if ':' in nid else 'unknown')
        node_type_counts[ntype] = node_type_counts.get(ntype, 0) + 1
    edge_type_counts = {}
    for src, lst in hg.adj.items():
        for (_dst, et, _ts, _srcv, _w) in lst:
            edge_type_counts[et] = edge_type_counts.get(et, 0) + 1
    print(json.dumps({
        'dataset': ds.name,
        'node_types': node_type_counts,
        'edge_types': edge_type_counts,
        'total_nodes': sum(node_type_counts.values()),
        'total_edges': sum(edge_type_counts.values())
    }, indent=2))

if __name__ == '__main__':
    main()
