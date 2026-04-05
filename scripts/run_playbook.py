"""Adversary Playbook Harness Runner (Phase 1)

Usage:
  python scripts/run_playbook.py --playbook scripts/harness_playbook_sample.yaml --tenant demo --speed 20

--speed accelerates simulated seconds per real second (default 10x)
Generates: metrics/emulation/latest_trace.json & latest_summary.json
"""
from __future__ import annotations
import argparse, asyncio, yaml, os, time, json, uuid
from typing import Any, Dict, List
import httpx

API_BASE = os.getenv('API_BASE','http://localhost:8000')
TRACE_PATH = 'metrics/emulation/latest_trace.json'
SUMMARY_PATH = 'metrics/emulation/latest_summary.json'

async def ingest_event(client: httpx.AsyncClient, evt: Dict[str, Any], tenant: str | None):
    payload = {
        'id': evt.get('id') or str(uuid.uuid4()),
        'event_type': evt.get('event_type'),
        'severity': evt.get('severity','low'),
        'details': evt
    }
    headers = {}
    if tenant:
        headers['X-Tenant-ID'] = tenant
    r = await client.post(f'{API_BASE}/api/v1/events', json=payload, headers=headers)
    try:
        j = r.json()
    except Exception:
        j = {'error': r.text}
    return j

async def fetch_decision(client: httpx.AsyncClient, event_id: str, retries: int = 30, delay: float = 0.3):
    for _ in range(retries):
        r = await client.get(f'{API_BASE}/api/v1/decisions/{event_id}')
        if r.status_code == 200:
            return r.json()
        await asyncio.sleep(delay)
    return None

def parse_time_offset(ts: str) -> float:
    # Format like '40s' or '2m'
    if ts.endswith('ms'):
        return float(ts[:-2]) / 1000.0
    if ts.endswith('s'):
        return float(ts[:-1])
    if ts.endswith('m'):
        return float(ts[:-1]) * 60
    return float(ts)

def load_playbook(path: str) -> Dict[str, Any]:
    with open(path,'r',encoding='utf-8') as f:
        return yaml.safe_load(f)

async def run_playbook(playbook: Dict[str, Any], tenant: str | None, speed: float):
    stages = playbook.get('stages',[])
    start_real = time.time()
    trace: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=10) as client:
        # Sort by t
        norm = []
        for s in stages:
            t = parse_time_offset(str(s.get('t','0s')))
            norm.append((t, s))
        norm.sort(key=lambda x: x[0])
        base_offset = norm[0][0] if norm else 0.0
        for rel_t, evt in norm:
            sim_delta = rel_t - base_offset
            # Wait until simulated time reached (accelerated by speed)
            elapsed = time.time() - start_real
            target = sim_delta / max(0.0001, speed)
            to_sleep = target - elapsed
            if to_sleep > 0:
                await asyncio.sleep(to_sleep)
            res = await ingest_event(client, evt, tenant)
            ev_id = res.get('event_id') or evt.get('id')
            decision = await fetch_decision(client, ev_id)
            trace.append({
                'stage_event': evt,
                'ingest_response': res,
                'decision': decision,
                'sim_time_s': sim_delta
            })
    return trace

def summarize_trace(playbook: Dict[str,Any], trace: List[Dict[str,Any]]) -> Dict[str,Any]:
    expected = set(playbook.get('labels',{}).get('expected_factors',[]))
    optional = set(playbook.get('labels',{}).get('optional_correlation',[]))
    det_factors = set()
    first_detection_time = None
    for entry in trace:
        dec = entry.get('decision') or {}
        factors = dec.get('factors') or []
        for f in factors:
            if f.startswith('lane_') or f.startswith('corr_'):
                det_factors.add(f)
        if first_detection_time is None and factors:
            first_detection_time = entry.get('sim_time_s')
    coverage_hits = expected.intersection(det_factors)
    uncovered = expected - det_factors
    corr_hits = optional.intersection(det_factors)
    return {
        'playbook_id': playbook.get('id'),
        'expected': sorted(list(expected)),
        'detected_lane_or_corr': sorted(list(det_factors)),
        'coverage_hits': sorted(list(coverage_hits)),
        'uncovered': sorted(list(uncovered)),
        'optional_correlation_hits': sorted(list(corr_hits)),
        'first_detection_time_s': first_detection_time,
        'coverage_ratio': (len(coverage_hits)/len(expected)) if expected else 1.0,
    }

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--playbook', required=True)
    ap.add_argument('--tenant', default=None)
    ap.add_argument('--speed', type=float, default=10.0, help='Simulated seconds per real second')
    args = ap.parse_args()

    os.makedirs('metrics/emulation', exist_ok=True)
    pb = load_playbook(args.playbook)
    trace = await run_playbook(pb, args.tenant, args.speed)
    with open(TRACE_PATH,'w',encoding='utf-8') as f:
        json.dump(trace, f, indent=2)
    summary = summarize_trace(pb, trace)
    with open(SUMMARY_PATH,'w',encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    asyncio.run(main())
