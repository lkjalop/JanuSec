#!/usr/bin/env python3
"""Measure memory usage and explain_chain latency after bulk ingest.

Adds optional CPU/memory accounting (via psutil if available) and emits a
compact JSON summary with per-event cost signals suitable for $/event
estimation on cloud instances.
"""
import time
import tracemalloc
import sys
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.graph.hopgraph import GLOBAL_HOPGRAPH


def _percentiles(values, ps=(50, 95)):
    if not values:
        return {p: 0.0 for p in ps}
    s = sorted(values)
    out = {}
    for p in ps:
        k = max(0, min(len(s) - 1, int(round((p/100.0) * (len(s)-1)))))
        out[p] = s[k]
    return out


def run(n=5000):
    tracemalloc.start()
    try:
        import psutil
        proc = psutil.Process()
        cpu_start = proc.cpu_times()
        rss_start = proc.memory_info().rss
    except Exception:
        psutil = None
        proc = None
        cpu_start = None
        rss_start = None
    t_ingest0 = time.time()
    for i in range(n):
        ev = {'timestamp': time.time(), 'host': f'host:{i%1000}', 'process': f'proc{i}'}
        GLOBAL_HOPGRAPH.ingest_event(ev, source='stress_measure')
    t_ingest1 = time.time()
    current, peak = tracemalloc.get_traced_memory()
    print(f'ingested {n} events in {t_ingest1-t_ingest0:.2f}s')
    print(f'memory current={current/1024/1024:.2f}MB peak={peak/1024/1024:.2f}MB')

    # measure explain latency on a few hosts
    hosts = [f'host:{i}' for i in range(5)]
    lat_ms = []
    for h in hosts:
        t0 = time.time()
        _ = GLOBAL_HOPGRAPH.explain_chain(start=h, max_depth=3, beam_width=4, top_k=3)
        t1 = time.time()
        took_ms = (t1-t0)*1000
        lat_ms.append(took_ms)
        print(f'explain {h} took {took_ms:.1f}ms')

    tracemalloc.stop()
    cpu_sec_user = cpu_sec_system = None
    rss_after = None
    if proc is not None and cpu_start is not None:
        try:
            cpu_end = proc.cpu_times()
            cpu_sec_user = (cpu_end.user - cpu_start.user)
            cpu_sec_system = (cpu_end.system - cpu_start.system)
            rss_after = proc.memory_info().rss
        except Exception:
            pass

    pct = _percentiles(lat_ms)
    summary = {
        'events': n,
        'ingest_seconds': (t_ingest1 - t_ingest0),
        'memory_current_mb': current/1024/1024,
        'memory_peak_mb': peak/1024/1024,
        'latency_ms': {
            'per_host': lat_ms,
            'p50': pct.get(50, 0.0),
            'p95': pct.get(95, 0.0)
        },
        'cpu_seconds_user': cpu_sec_user,
        'cpu_seconds_system': cpu_sec_system,
        'rss_start_bytes': rss_start,
        'rss_after_bytes': rss_after
    }
    try:
        print(json.dumps(summary, indent=2))
    except Exception:
        pass


if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run(n)
