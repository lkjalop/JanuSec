"""Stress harness: run concurrent ingestion + graph.build cycles in-process using TestClient.
Outputs per-run CSV lines and a summary.
"""
import os
import sys
import time
import random
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient

try:
    from src.api.app import app
except Exception as e:
    print('Failed to import app:', e)
    raise

# sample payloads (same as integration)
SYS_MON = {
    'event_id': 'sysmon-1',
    'ts': time.time(),
    'event_type': 'process_create',
    'host': 'host-1.example',
    'user': 'Alice',
    'process': 'cmd.exe',
    'command_line': 'cmd.exe /c whoami'
}

CLOUDTRAIL_EVENT = {
    'eventVersion': '1.05',
    'userIdentity': {'type': 'IAMUser', 'principalId': 'EX_PRINCIPAL_ID', 'arn': 'arn:aws:iam::123456789012:user/Alice'},
    'eventTime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'eventName': 'CreateUser',
    'awsRegion': 'us-east-1',
    'sourceIPAddress': '203.0.113.5',
    'requestParameters': {},
}

EMAIL_SAMPLE = {
    'message_id': 'msg-1',
    'from': 'attacker@example.com',
    'to': ['victim@example.com'],
    'subject': 'Important update',
    'body': 'Please click the link',
    'ts': time.time(),
}

LOLBIN = {
    'event_id': 'lolbin-1',
    'process': 'powershell.exe',
    'command_line': 'powershell -NoProfile -EncodedCommand ...',
    'host': 'host-1.example',
    'ts': time.time()
}

samples = [SYS_MON, CLOUDTRAIL_EVENT, EMAIL_SAMPLE, LOLBIN]
kinds = ['sysmon','cloudtrail','email','lolbin']

# discover ingest endpoints from app
INGEST_PATHS = [getattr(r,'path','') for r in app.routes if getattr(r,'path','').startswith('/api/v1/ingest')]
INGEST_PATHS = sorted(set(INGEST_PATHS))
print('Found ingest paths:', INGEST_PATHS)

API_KEY = os.environ.get('API_KEY','devkey123')

def pick_path_for(kind):
    candidates = [p for p in INGEST_PATHS if kind in p or ('cloud' in p and 'cloudtrail' in kind) or ('email' in p and 'mail' in p)]
    if not candidates and INGEST_PATHS:
        return INGEST_PATHS[0]
    return candidates[0] if candidates else None

# worker function
def do_run(run_id):
    # create a fresh TestClient to avoid thread-safety edge cases
    client = TestClient(app)
    payload_idx = random.randrange(len(samples))
    payload = samples[payload_idx]
    kind = kinds[payload_idx]
    path = pick_path_for(kind)
    if not path:
        return {'run': run_id, 'error': 'no_ingest_path'}
    headers = {'x-api-key': API_KEY}
    start = time.perf_counter()
    try:
        r = client.post(path, json=payload, headers=headers)
        post_status = r.status_code
    except Exception as e:
        post_status = None
        post_err = str(e)
    post_time = (time.perf_counter() - start) * 1000.0
    # call graph build
    start2 = time.perf_counter()
    build_payload = {'session_ids': [f'batch-{run_id}-a', f'batch-{run_id}-b'], 'correlate': True, 'ewma': True}
    try:
        b = client.post('/api/v1/graph/session/build', json=build_payload, headers=headers)
        build_status = b.status_code
    except Exception as e:
        build_status = None
        build_err = str(e)
    build_time = (time.perf_counter() - start2) * 1000.0
    total = (time.perf_counter() - start) * 1000.0
    out = {
        'run': run_id,
        'kind': kind,
        'post_status': post_status,
        'post_time_ms': round(post_time,2),
        'build_status': build_status,
        'build_time_ms': round(build_time,2),
        'total_ms': round(total,2),
    }
    return out

def main(workers=4, runs=20):
    print(f'Starting stress test: workers={workers}, runs={runs}')
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(do_run, i): i for i in range(runs)}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
                print(f"{r['run']},{r.get('kind')},{r.get('post_status')},{r.get('post_time_ms')},{r.get('build_status')},{r.get('build_time_ms')},{r.get('total_ms')}")
            except Exception as e:
                print('ERR_FUT', e)
    # summary
    post_times = [r['post_time_ms'] for r in results if r.get('post_time_ms') is not None]
    build_times = [r['build_time_ms'] for r in results if r.get('build_time_ms') is not None]
    total_times = [r['total_ms'] for r in results if r.get('total_ms') is not None]
    successes = [r for r in results if r.get('post_status')==200 and r.get('build_status')==200]
    print('\nSummary:')
    print('Total runs:', len(results))
    print('Successes:', len(successes))
    if post_times:
        print('Post ms: min', min(post_times), 'p50', statistics.median(post_times), 'p95', round(sorted(post_times)[int(len(post_times)*0.95)-1] if len(post_times)>1 else post_times[0],2), 'max', max(post_times))
    if build_times:
        print('Build ms: min', min(build_times), 'p50', statistics.median(build_times), 'p95', round(sorted(build_times)[int(len(build_times)*0.95)-1] if len(build_times)>1 else build_times[0],2), 'max', max(build_times))
    if total_times:
        print('Total ms: min', min(total_times), 'p50', statistics.median(total_times), 'p95', round(sorted(total_times)[int(len(total_times)*0.95)-1] if len(total_times)>1 else total_times[0],2), 'max', max(total_times))

if __name__=='__main__':
    main(workers=4, runs=20)
#!/usr/bin/env python3
"""Synthetic bulk ingest generator for HopGraph to measure ingest throughput.
"""
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.graph.hopgraph import GLOBAL_HOPGRAPH


def generate_and_ingest(n=10000):
    t0 = time.time()
    for i in range(n):
        ev = {'timestamp': time.time(), 'host': f'host:{i%1000}', 'process': f'proc{i}', 'file_hash': None}
        GLOBAL_HOPGRAPH.ingest_event(ev, source='stress')
    dt = time.time() - t0
    print(f'Inserted {n} events in {dt:.2f}s ({n/dt:.0f} ops/s)')


if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    generate_and_ingest(n)
