#!/usr/bin/env python
"""Load test script: simulate 10K event ingests and optional session builds.

Usage (PowerShell):
  python scripts/load_test_events.py --url http://localhost:8080 --api-key devkey123 --events 10000 --session-build

Outputs throughput stats and average latency per ingest + optional session build summary.
"""
import os, time, json, random, argparse, statistics
import string
import requests

ALPH = string.ascii_lowercase + string.digits

def rand_hash() -> str:
    return ''.join(random.choice('0123456789abcdef') for _ in range(64))

def rand_domain() -> str:
    left = ''.join(random.choice(ALPH) for _ in range(random.randint(6,18)))
    return f"{left}.example.com"

def make_event(i: int) -> dict:
    h = rand_hash()
    return {
        'event_id': f'evt-{i}-{h[:8]}',
        'ts': time.time(),
        'sha256': h,
        'host': f"host-{random.randint(1,200)}",
        'user': f"user{random.randint(1,50)}",
        'domain': rand_domain(),
        'factors': ['high_entropy'] if random.random() < 0.02 else [],
        'size': random.randint(1024, 10_485_760),
        'type': 'file_event'
    }

def ingest_event(base: str, api_key: str, ev: dict) -> float:
    url = f"{base.rstrip('/')}/api/v1/stream/ingest"
    hdr = {'x-api-key': api_key}
    start = time.time()
    try:
        requests.post(url, json=ev, headers=hdr, timeout=5)
    except Exception:
        pass
    return time.time() - start

def build_session(base: str, api_key: str, batches: list[str]) -> dict:
    url = f"{base.rstrip('/')}/api/v1/graph/session/build"
    hdr = {'x-api-key': api_key}
    payload = {'session_ids': batches, 'correlate': True, 'ewma': False}
    try:
        r = requests.post(url, json=payload, headers=hdr, timeout=15)
        if r.ok:
            return r.json()
    except Exception:
        return {}
    return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default=os.getenv('LOAD_TEST_URL','http://localhost:8080'))
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--events', type=int, default=10000)
    ap.add_argument('--session-build', action='store_true')
    ap.add_argument('--session-every', type=int, default=2000, help='Build session every N events')
    args = ap.parse_args()

    latencies = []
    batch_ids = []
    start_all = time.time()
    for i in range(1, args.events + 1):
        ev = make_event(i)
        dt = ingest_event(args.url, args.api_key, ev)
        latencies.append(dt)
        # Simulate file batch identifiers (fake) to build sessions periodically
        if i % args.session_every == 0 and args.session_build:
            # Use synthetic batch ids aligned with events
            batch_ids.append(f"batch-{i}")
            sess = build_session(args.url, args.api_key, batch_ids[-10:])
            if sess:
                print(f"[session] built: id={sess.get('session_id')} confidence={sess.get('summary',{}).get('confidence')} factors={len(sess.get('summary',{}).get('factors',[]))}")
    elapsed = time.time() - start_all
    total = len(latencies)
    p50 = statistics.median(latencies) if latencies else 0
    p95 = statistics.quantiles(latencies, n=100)[94] if len(latencies) >= 100 else max(latencies) if latencies else 0
    avg = statistics.mean(latencies) if latencies else 0
    print(json.dumps({
        'events': total,
        'elapsed_sec': round(elapsed,3),
        'eps': round(total/elapsed,2) if elapsed>0 else 0,
        'avg_latency_sec': round(avg,4),
        'p50_latency_sec': round(p50,4),
        'p95_latency_sec': round(p95,4),
        'sessions_built': len(batch_ids) if args.session_build else 0
    }, indent=2))

if __name__ == '__main__':
    main()
