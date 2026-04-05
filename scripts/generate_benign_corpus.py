"""Generate Benign Corpus & (Optionally) Ingest into Platform

Produces a JSONL file of synthetic benign events for FP baseline measurement.
Optionally posts events to /api/v1/events and captures resulting decisions
into a parallel JSONL file for downstream FP density analysis.

Usage:
  python scripts/generate_benign_corpus.py --count 300 --out metrics/precision/benign_before.jsonl --ingest --decisions metrics/precision/benign_before_decisions.jsonl

"""
from __future__ import annotations
import argparse, json, os, random, time, uuid, asyncio
from typing import Dict, Any, List
import httpx

HOSTS = ["work1","work2","jump1","db1","ci-runner","build-box","intranet"]
USERS = ["alice","bob","carol","svc-backup","deploy","jenkins"]
PROCS = ["bash","python","node","java","powershell","git","tar","systemd"]
JA3_COMMON = ["commonja3001","commonja3002","commonja3003"]

RANDOM_WORDS = ["sync","update","backup","rotate","temp","cache","heartbeat","poll","refresh"]

def random_event(i: int) -> Dict[str, Any]:
    etype = random.choices(["proc","net","auth"],[0.45,0.35,0.20])[0]
    base: Dict[str, Any] = { 'id': str(uuid.uuid4()), 'event_type': etype }
    if etype == 'proc':
        base.update({
            'host': random.choice(HOSTS),
            'proc': random.choice(PROCS),
            'parent': random.choice(["systemd","init","bash","python","supervisord"]),
            'cmd': random.choice(RANDOM_WORDS) + ' ' + random.choice(RANDOM_WORDS)
        })
    elif etype == 'net':
        base.update({
            'src_host': random.choice(HOSTS),
            'dst_ip': f"203.0.113.{random.randint(1,200)}",
            'ja3': random.choice(JA3_COMMON),
            'bytes_out': random.randint(200, 4000)
        })
    else:  # auth
        base.update({
            'user': random.choice(USERS),
            'src_host': random.choice(HOSTS),
            'dst_host': random.choice(HOSTS),
            'outcome': random.choice(["success","success","fail"])  # mild fail rate
        })
    return base

async def ingest_and_capture(events: List[Dict[str, Any]], tenant: str | None, decisions_path: str):
    os.makedirs(os.path.dirname(decisions_path), exist_ok=True)
    async with httpx.AsyncClient(timeout=8) as client, open(decisions_path,'w',encoding='utf-8') as outf:
        for ev in events:
            headers = {}
            if tenant:
                headers['X-Tenant-ID'] = tenant
            payload = {
                'id': ev['id'],
                'event_type': ev['event_type'],
                'severity': 'low',
                'details': ev
            }
            try:
                r = await client.post('http://localhost:8000/api/v1/events', json=payload, headers=headers)
            except Exception:
                continue
            # Poll decision
            for _ in range(25):
                dr = await client.get(f"http://localhost:8000/api/v1/decisions/{ev['id']}")
                if dr.status_code == 200:
                    try:
                        outf.write(json.dumps(dr.json())+'\n')
                    except Exception:
                        pass
                    break
                await asyncio.sleep(0.15)

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--count', type=int, default=300)
    ap.add_argument('--out', default='metrics/precision/benign_before.jsonl')
    ap.add_argument('--tenant', default='demo')
    ap.add_argument('--ingest', action='store_true')
    ap.add_argument('--decisions', default='')
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    events = [random_event(i) for i in range(args.count)]
    with open(args.out,'w',encoding='utf-8') as f:
        for ev in events:
            f.write(json.dumps(ev)+'\n')
    if args.ingest and args.decisions:
        await ingest_and_capture(events, args.tenant, args.decisions)
    print(f"Wrote {len(events)} benign events to {args.out}")
    if args.ingest and args.decisions:
        print(f"Captured decisions to {args.decisions}")

if __name__ == '__main__':
    asyncio.run(main())
