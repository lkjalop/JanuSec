"""Dump explain_chain output for a dataset incident for debugging timestamp/node mismatches.

Usage: python -m scripts.dump_explain_debug --dataset <path> --start-host host119 --max-depth 6 --top-k 10
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True)
    p.add_argument('--start-host', required=True)
    p.add_argument('--max-depth', type=int, default=6)
    p.add_argument('--top-k', type=int, default=10)
    args = p.parse_args()

    ds = Path(args.dataset)
    ev_file = ds / 'events.jsonl'
    if not ev_file.exists():
        print('no events file', ev_file); return

    try:
        from src.graph.hopgraph import HopGraph
        hg = HopGraph(wal_path='data/benchmarking/debug_wal.log', snapshot_path='data/benchmarking/debug_snap.json')
    except Exception:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH as hg  # type: ignore

    with ev_file.open('r', encoding='utf-8') as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln: continue
            try:
                ev = json.loads(ln)
                if 'timestamp' not in ev and 'ts' in ev:
                    ev['timestamp'] = ev['ts']
                if 'file_hash' not in ev and 'sha256' in ev:
                    ev['file_hash'] = ev['sha256']
                if 'domain' not in ev and 'qname' in ev:
                    ev['domain'] = ev['qname']
                hg.ingest_event(ev, source='debug')
            except Exception:
                continue

    start_node = f"host:{args.start_host}"
    res = hg.explain_chain(start_node, max_depth=args.max_depth, top_k=args.top_k, beam_width=8)
    out = Path('data/benchmarking/debugs')
    out.mkdir(parents=True, exist_ok=True)
    Path(out / f'explain_{args.start_host}.json').write_text(json.dumps(res, indent=2))
    print('Wrote explain dump to', out / f'explain_{args.start_host}.json')

if __name__ == '__main__':
    main()
