#!/usr/bin/env python3
"""
Controlled stress test for the ingestion endpoint.
Posts small batches to /api/v1/endpoints/log_batch with increasing concurrency to observe backpressure and guardrails.

Usage: python scripts/stress_ingest_test.py
"""
from __future__ import annotations
import asyncio
import json
import random
import time
from urllib import request, error
import json as _json

API = 'http://localhost:8080'
INGEST_PATH = '/api/v1/endpoints/log_batch'

# Build a simple sample payload similar to what run_scenarios sends
def make_event(i: int):
    return {
        'event_id': f'stress-{int(time.time()*1000)}-{i}-{random.randint(0,9999)}',
        'proc_name': 'stress.exe',
        'cmdline': 'stress --test',
        'tenant_id': 'default',
        'factors': ['stress:test'],
    }

def make_batch(n: int = 5):
    return {'items': [make_event(i) for i in range(n)]}

def sync_post(path: str, payload: dict, timeout: int = 10):
    data = json.dumps(payload).encode('utf-8')
    req = request.Request(API + path, data=data, method='POST')
    req.add_header('Content-Type','application/json')
    try:
        with request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8')
    except error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)


def sync_get(path: str, timeout: int = 8):
    req = request.Request(API + path, method='GET')
    try:
        with request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8')
    except error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)

async def worker(task_id: int, iterations: int, batch_size: int, sem: asyncio.Semaphore, stats: dict):
    for it in range(iterations):
        async with sem:
            payload = make_batch(batch_size)
            start = time.perf_counter()
            # run in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            code, body = await loop.run_in_executor(None, sync_post, INGEST_PATH, payload, 15)
            dur = time.perf_counter() - start
            stats['total'] += 1
            stats.setdefault('latencies', []).append(dur)
            stats.setdefault('codes', []).append(code)
            if code >= 400:
                stats['errors'] += 1
            if it % 10 == 0:
                print(f'worker {task_id} iter {it} code {code} dur {dur:.3f}')

async def run_test(rounds:int=5, start_c:int=10, max_c:int=200, batch_size:int=5, iters_per_worker:int=10):
    # ramp concurrency across rounds
    concurrencies = [int(start_c + (max_c-start_c) * (r/(rounds-1))) for r in range(rounds)]
    print('Planned concurrencies:', concurrencies)
    overall = {}
    for c in concurrencies:
        print('\n=== Running concurrency:', c)
        sem = asyncio.Semaphore(c)
        # We'll spawn c workers, each doing `iters_per_worker` iterations
        stats = {'total':0, 'errors':0, 'latencies':[], 'codes':[]}
        tasks = [asyncio.create_task(worker(i, iters_per_worker, batch_size, sem, stats)) for i in range(c)]
        t0 = time.perf_counter()
        await asyncio.gather(*tasks)
        t1 = time.perf_counter()
        total = stats['total']
        errs = stats['errors']
        codes = stats.get('codes', [])
        lat = stats.get('latencies', [])
        print(f'concurrency {c} completed total={total} errors={errs} duration={t1-t0:.2f}s')
        # summarize codes
        code_counts = {}
        for code in codes:
            code_counts[code] = code_counts.get(code,0) + 1
        print('status codes:', code_counts)
        if lat:
            lat_sorted = sorted(lat)
            def p(n):
                idx = int(len(lat_sorted)*n)
                idx = min(idx, len(lat_sorted)-1)
                return lat_sorted[idx]
            print('latency p50 {:.3f}s p90 {:.3f}s p99 {:.3f}s'.format(p(0.5), p(0.9), p(0.99)))
        overall[c] = {'total': total, 'errors': errs, 'codes': code_counts, 'duration': t1-t0}
        # capture health and metrics snapshot
        # Use GET for health and metrics endpoints
        try:
            code_h, body_h = sync_get('/api/v1/health')
        except Exception:
            code_h, body_h = 0, ''
        try:
            code_m, body_m = sync_get('/api/v1/metrics/self_test')
        except Exception:
            code_m, body_m = 0, ''
        overall[c]['health'] = {'status_code': code_h, 'body': body_h}
        overall[c]['metrics_self_test'] = {'status_code': code_m, 'body': body_m}
        # Try to scrape Prometheus /metrics if present and capture guardrail-like counters
        try:
            code_p, body_p = sync_get('/metrics')
        except Exception:
            code_p, body_p = 0, ''
        overall[c]['prometheus'] = {'status_code': code_p}
        if code_p == 200 and body_p:
            overall[c]['prometheus']['raw'] = body_p[:20000]
            # extract counters containing guardrail, dlq, decisions keywords
            counters = {}
            for line in body_p.splitlines():
                if line.startswith('#'):
                    continue
                parts = line.split()
                if not parts:
                    continue
                name = parts[0]
                if any(k in name for k in ('guardrail','dlq','decisions','dlq_size','dlq_failures','guardrail')):
                    try:
                        counters[name] = float(parts[-1])
                    except Exception:
                        counters[name] = parts[-1]
            overall[c]['prometheus']['counters'] = counters
        # persist per-round summary (append)
        try:
            with open('scripts/stress_results.json', 'w') as fh:
                _json.dump(overall, fh, indent=2)
        except Exception:
            pass
        # Stop early if more than 10% errors
        if total>0 and errs/total > 0.1:
            print('High error rate detected; stopping test early')
            break
        # small cool-down between rounds
        await asyncio.sleep(1)
    print('\n=== Overall summary ===')
    for c,res in overall.items():
        print(c, res)

if __name__ == '__main__':
    asyncio.run(run_test(rounds=6, start_c=10, max_c=200, batch_size=6, iters_per_worker=20))
