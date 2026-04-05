"""
Stress test harness for multi-domain ingestion + reconstruction
- Repeats the integration flow concurrently to simulate load
- Optionally prewarm Ollama by hitting the LLM endpoint(s) if configured

Usage: python scripts/stress_multi_domain.py --workers 8 --runs 100
"""
import sys
from pathlib import Path
import json
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ensure repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient
try:
    from src.api.app import app
except Exception as e:
    print('ERROR importing app:', e)
    raise

client = TestClient(app)

# reuse helpers from integration script
from scripts.integration_multi_domain_check import post_ingest, build_session


def single_run(i, verbose=False):
    now = int(time.time())
    batch_sys = f'batch-sysmon-{i}'
    batch_cloud = f'batch-cloudtrail-{i}'
    batch_email = f'batch-email-{i}'
    batch_lol = f'batch-lol-{i}'
    sys_events = [{'type':'sysmon','ts': now, 'host': f'h{i}', 'process':'cmd.exe'}]
    cloud_events = [{'type':'cloudtrail','ts': now, 'user': f'user{i}', 'sourceIPAddress': '1.2.3.'+str(i%255)}]
    email_events = [{'type':'email','ts': now, 'from': 'phish@test','to': 'victim@test','message_id': f'm{i}'}]
    lol_events = [{'type':'lolbin','ts': now, 'binary':'regsvr32.exe'}]
    try:
        r1 = post_ingest(batch_sys, sys_events)
        r2 = post_ingest(batch_cloud, cloud_events)
        r3 = post_ingest(batch_email, email_events)
        r4 = post_ingest(batch_lol, lol_events)
        r = build_session([batch_sys,batch_cloud,batch_email,batch_lol])
        ok = (r.status_code == 200)
        return ok, r.status_code, r.text[:200]
    except Exception as e:
        return False, 0, str(e)


def prewarm_ollama():
    # best-effort: hit llm tier1 endpoint if present
    try:
        r = client.post('/api/v1/ai/tier1', json={'prompt':'prewarm'}, headers={'x-api-key':'testkey123'})
        print('Ollama prewarm:', r.status_code)
    except Exception:
        pass


def run_stress(workers, runs, prewarm=False):
    if prewarm:
        prewarm_ollama()
    failures = 0
    latencies = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(single_run, i): i for i in range(runs)}
        for fut in as_completed(futures):
            i = futures[fut]
            start = time.time()
            ok, code, text = fut.result()
            lat = time.time() - start
            latencies.append(lat)
            if not ok:
                failures += 1
                print(f'Run {i} failed code={code} text={text}')
    print('Stress summary: runs=', runs, 'failures=', failures, 'p95_latency=', sorted(latencies)[int(0.95*len(latencies))])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--runs', type=int, default=50)
    parser.add_argument('--prewarm', action='store_true')
    args = parser.parse_args()
    run_stress(args.workers, args.runs, prewarm=args.prewarm)
