"""Instrumented run to measure CPU time, wall time, and memory used for a benchmark batch.

Writes a CSV with measured metrics.
"""
from __future__ import annotations
import argparse, json, time, os
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

def measure_run(dataset_path: Path):
    # import hopgraph
    try:
        from src.graph.hopgraph import HopGraph
        hg = HopGraph(wal_path='data/benchmarking/tmp_wal.log', snapshot_path='data/benchmarking/tmp_snapshot.json')
    except Exception:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH as hg

    # load events
    ev_file = dataset_path / 'events.jsonl'
    events = []
    with ev_file.open('r', encoding='utf-8') as f:
        for ln in f:
            if not ln.strip():
                continue
            events.append(json.loads(ln))

    proc = psutil.Process(os.getpid()) if HAS_PSUTIL else None
    mem_before = proc.memory_info().rss if proc else 0
    t0 = time.time(); c0 = time.process_time()
    for ev in events:
        try:
            hg.ingest_event(ev, source='instrument')
        except Exception:
            pass
    t1 = time.time(); c1 = time.process_time()
    mem_after = proc.memory_info().rss if proc else 0

    return {
        'wall_seconds': t1 - t0,
        'cpu_seconds': c1 - c0,
        'mem_before_bytes': mem_before,
        'mem_after_bytes': mem_after,
        'events': len(events)
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    res = measure_run(Path(args.dataset))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(res, indent=2), encoding='utf-8')
    print('Wrote instrumented metrics to', args.out)

if __name__ == '__main__':
    main()
