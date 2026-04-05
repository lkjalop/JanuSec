"""Run a long stress ingestion into GLOBAL_HOPGRAPH, measure memory and explain latencies.

Usage: python -u scripts/stress_run_long.py [N]
Defaults to N=50000
"""
import sys
import time
import tracemalloc
import csv
from random import randint, choice
import argparse
import os
try:
    import psutil
except Exception:
    psutil = None

ROOT = __file__ + '..'
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph.hopgraph import GLOBAL_HOPGRAPH


def make_event(i):
    return {
        'event_id': f'evt-{i}',
        'timestamp': int(time.time()),
        'src': f'host:host-{i%1000}',
        'dst': f'ip:10.0.{i%255}.{i%255}',
        'type': 'conn',
        'meta': {'score': randint(1, 100)}
    }


def explain_sampled_hosts(sample_hosts, iterations=50, csv_writer=None):
    latencies = []
    for i in range(iterations):
        h = choice(sample_hosts)
        t0 = time.perf_counter()
        GLOBAL_HOPGRAPH.explain_chain(start=h, max_depth=4, beam_width=6, top_k=5)
        ms = (time.perf_counter() - t0) * 1000
        latencies.append(ms)
        if csv_writer:
            csv_writer.writerow([time.time(), h, f'{ms:.6f}'])
    return latencies


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('n', nargs='?', type=int, default=50000)
    parser.add_argument('--per-explain-csv', dest='per_csv', help='Path to write per-explain latencies CSV', default=None)
    parser.add_argument('--snapshot-interval', dest='snap_int', type=int, default=0, help='Trigger save_snapshot() every SNAP_INTERVAL inserts (0 disables)')
    parser.add_argument('--probe-every', dest='probe_every', type=int, default=0, help='Run explain probes every PROBE_EVERY inserts (0 disables)')
    parser.add_argument('--probe-iterations', dest='probe_iters', type=int, default=20, help='Number of explain iterations per probe')
    parser.add_argument('--rss-sample-every', dest='rss_every', type=int, default=0, help='Record RSS memory every N inserts (0 disables)')
    parser.add_argument('--rss-csv', dest='rss_csv', help='Path to write RSS time-series CSV', default=None)
    args = parser.parse_args()
    n = args.n
    per_csv = args.per_csv
    snap_int = args.snap_int

    print('Stress run, N=', n, 'per-explain-csv=', per_csv, 'snapshot_interval=', snap_int)
    tracemalloc.start()
    t0 = time.time()
    sample_hosts = set()
    csv_fh = None
    csv_writer = None
    if per_csv:
        os.makedirs(os.path.dirname(os.path.abspath(per_csv)) or '.', exist_ok=True)
        csv_fh = open(per_csv, 'w', newline='')
        csv_writer = csv.writer(csv_fh)
        csv_writer.writerow(['ts', 'host', 'latency_ms'])
    rss_fh = None
    rss_writer = None
    if args.rss_csv and args.rss_every and psutil:
        os.makedirs(os.path.dirname(os.path.abspath(args.rss_csv)) or '.', exist_ok=True)
        rss_fh = open(args.rss_csv, 'w', newline='')
        rss_writer = csv.writer(rss_fh)
        rss_writer.writerow(['ts', 'rss_bytes'])

    for i in range(n):
        ev = make_event(i)
        GLOBAL_HOPGRAPH.ingest_event(ev)
        sample_hosts.add(ev['src'])
        if snap_int and ((i+1) % snap_int == 0):
            try:
                GLOBAL_HOPGRAPH.save_snapshot()
            except Exception:
                pass
        if args.rss_every and args.rss_every > 0 and args.rss_csv and ((i+1) % args.rss_every == 0):
            try:
                if psutil:
                    rss = psutil.Process().memory_info().rss
                    if rss_writer:
                        rss_writer.writerow([time.time(), rss])
                else:
                    # psutil not available; skip RSS sampling
                    pass
            except Exception:
                pass
        if args.probe_every and args.probe_every > 0 and ((i+1) % args.probe_every == 0):
            try:
                # run a small probe and write per-explain rows if requested
                sample_hosts_probe = list(sample_hosts)[:200]
                explain_sampled_hosts(sample_hosts_probe, iterations=args.probe_iters, csv_writer=csv_writer)
            except Exception:
                pass
        if (i+1) % 5000 == 0:
            now = time.time()
            curr, peak = tracemalloc.get_traced_memory()
            print(f'Inserted {i+1}/{n} in {now-t0:.1f}s; mem curr={curr/1024/1024:.2f}MB peak={peak/1024/1024:.2f}MB')

    total_time = time.time() - t0
    curr, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print('Insertion done in', total_time)
    print('mem curr', curr/1024/1024, 'MB peak', peak/1024/1024, 'MB')

    sample_hosts = list(sample_hosts)[:200]
    print('Explaining sampled hosts count=', len(sample_hosts))
    latencies = explain_sampled_hosts(sample_hosts, iterations=200, csv_writer=csv_writer)
    lat_sorted = sorted(latencies)
    p50 = lat_sorted[len(lat_sorted)//2]
    p95 = lat_sorted[int(len(lat_sorted)*0.95)]

    print(f'Explain p50={p50:.2f}ms p95={p95:.2f}ms')

    out = 'stress_run_summary.csv'
    with open(out, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['n', 'total_time_s', 'mem_curr_mb', 'mem_peak_mb', 'p50_ms', 'p95_ms'])
        w.writerow([n, f'{total_time:.2f}', f'{curr/1024/1024:.2f}', f'{peak/1024/1024:.2f}', f'{p50:.2f}', f'{p95:.2f}'])

    if csv_fh:
        try:
            csv_fh.close()
        except Exception:
            pass

    print('Wrote', out)


if __name__ == '__main__':
    main()
