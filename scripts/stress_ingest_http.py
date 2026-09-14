"""HTTP-based stress harness: posts sample events to running server and calls graph build.
Usage: python scripts/stress_ingest_http.py --url http://127.0.0.1:8080 --workers 4 --runs 20
"""
import os
import sys
import time
import argparse
import requests
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

API_KEY = os.environ.get('API_KEY', 'devkey123')
HEADERS = {'x-api-key': API_KEY}

SAMPLE = {
    'event_id': 'stress-evt',
    'ts': time.time(),
    'host': 'stress-host',
    'user': 'stress-user',
    'process': 'powershell.exe',
    'command_line': 'powershell -NoProfile -Command "echo 1"'
}

INGEST_PATH = '/api/v1/ingest/sysmon'
BUILD_PATH = '/api/v1/graph/session/build'


def single_run(base_url: str, idx: int, timeout: float = 10.0):
    start = time.time()
    try:
        r = requests.post(base_url.rstrip('/') + INGEST_PATH, json={**SAMPLE, 'event_id': f'stress-{idx}-{int(start)}'}, headers=HEADERS, timeout=timeout)
        ingest_ok = (r.status_code == 200)
    except Exception as e:
        return {'idx': idx, 'ok': False, 'stage': 'ingest', 'error': str(e), 'latency': time.time()-start}
    try:
        payload = {'session_ids': [f'batch-{idx}'], 'correlate': True, 'ewma': True}
        rb = requests.post(base_url.rstrip('/') + BUILD_PATH, json=payload, headers=HEADERS, timeout=timeout)
        build_ok = (rb.status_code == 200)
    except Exception as e:
        return {'idx': idx, 'ok': False, 'stage': 'build', 'error': str(e), 'latency': time.time()-start}
    return {'idx': idx, 'ok': ingest_ok and build_ok, 'ingest_ok': ingest_ok, 'build_ok': build_ok, 'latency': time.time()-start}


def run_stress(base_url: str, workers: int, runs: int):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(single_run, base_url, i) for i in range(runs)]
        for f in as_completed(futures):
            try:
                res = f.result()
            except Exception as e:
                res = {'ok': False, 'error': str(e)}
            results.append(res)
            print('.', end='', flush=True)
    print('\n')
    return results


def summarize(results):
    total = len(results)
    oks = [r for r in results if r.get('ok')]
    latencies = [r.get('latency') for r in results if r.get('latency')]
    fail_count = total - len(oks)
    print(f"Total runs: {total}, Success: {len(oks)}, Failures: {fail_count}")
    if latencies:
        p50 = statistics.median(latencies)
        p90 = statistics.quantiles(latencies, n=10)[8]
        p99 = max(latencies)
        print(f"p50={p50:.3f}s p90={p90:.3f}s p99={p99:.3f}s mean={statistics.mean(latencies):.3f}s")
    print('\nCSV: idx,ok,ingest_ok,build_ok,latency')
    for r in results:
        print(f"{r.get('idx')},{int(bool(r.get('ok')) )},{int(bool(r.get('ingest_ok')) )},{int(bool(r.get('build_ok')) )},{r.get('latency'):.3f}")


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--url', default='http://127.0.0.1:8080', help='Base URL of running server')
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--runs', type=int, default=20)
    args = p.parse_args()
    print('Stress test to', args.url)
    res = run_stress(args.url, args.workers, args.runs)
    summarize(res)
