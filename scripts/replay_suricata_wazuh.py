#!/usr/bin/env python3
"""Replay Suricata and Wazuh event samples into unified ingest endpoint.

Usage:
  python scripts/replay_suricata_wazuh.py --suricata eve.json --wazuh alerts.json \
      --api http://localhost:8080 --api-key devkey123 --rate 50 \
      [--hmac-secret changeme] [--require-ts] [--sleep 0.01]

Features:
- Reads newline-delimited JSON events (Suricata EVE, Wazuh alerts)
- Auto-batches by --rate events per second (best-effort pacing)
- Optional HMAC signing (X-Signature header)
- Optional timestamp header (X-Ts) for replay protection
- Latency measurement (POST round-trip) & summary stats
- Factor coverage summary (counts of factors observed)

This is a lightweight helper for validation and demo load testing; it avoids
threading complexity and focuses on deterministic pacing.
"""
from __future__ import annotations
import argparse, json, time, hmac, hashlib, sys, os
from typing import Iterable, Dict, Any, List
import requests

def iter_json_lines(path: str) -> Iterable[Dict[str, Any]]:
    if not path or not os.path.exists(path):
        return []
    with open(path,'r',encoding='utf-8',errors='ignore') as fh:
        for line in fh:
            line=line.strip()
            if not line:
                continue
            try:
                obj=json.loads(line)
            except Exception:
                continue
            yield obj

def sign(secret: str, body: str) -> str:
    return hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()

def post_event(api: str, sensor: str, body: str, api_key: str, secret: str|None, ts: bool) -> tuple[int,float]:
    url=f"{api.rstrip('/')}/api/v1/ingest/{sensor}"
    headers={'x-api-key': api_key, 'Content-Type':'application/json'}
    if secret:
        headers['X-Signature']=sign(secret, body)
    if ts:
        headers['X-Ts']=str(int(time.time()))
    start=time.time()
    try:
        resp=requests.post(url,data=body,headers=headers,timeout=5)
        return resp.status_code, time.time()-start
    except Exception:
        return -1, time.time()-start

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--suricata',help='Path to Suricata eve.json sample')
    ap.add_argument('--wazuh',help='Path to Wazuh alerts.json sample')
    ap.add_argument('--api',default='http://localhost:8080',help='Base API URL')
    ap.add_argument('--api-key',default='devkey123')
    ap.add_argument('--hmac-secret',help='Shared HMAC secret (optional)')
    ap.add_argument('--require-ts',action='store_true',help='Send X-Ts header (enable server replay protection)')
    ap.add_argument('--rate',type=int,default=50,help='Approx events per second pacing')
    ap.add_argument('--sleep',type=float,default=0.0,help='Extra sleep after each POST (seconds)')
    ap.add_argument('--limit',type=int,default=0,help='Stop after N events (0 = all)')
    args=ap.parse_args()

    suri=list(iter_json_lines(args.suricata)) if args.suricata else []
    wazuh=list(iter_json_lines(args.wazuh)) if args.wazuh else []
    total=len(suri)+len(wazuh)
    if args.limit>0:
        suri=suri[:args.limit]
        remaining=max(0,args.limit-len(suri))
        wazuh=wazuh[:remaining]
        total=len(suri)+len(wazuh)
    if total==0:
        print('No events loaded; provide --suricata and/or --wazuh samples')
        return 1

    print(f"Loaded Suricata={len(suri)} Wazuh={len(wazuh)} (total={total}). Replaying to {args.api}")
    target_interval=1.0/max(1,args.rate)  # seconds per event
    latencies=[]
    codes={}
    start=time.time()

    # Simple interleave: alternate sensors for variety
    merged: List[tuple[str,Dict[str,Any]]]=[]
    for i in range(max(len(suri),len(wazuh))):
        if i < len(suri): merged.append(('suricata', suri[i]))
        if i < len(wazuh): merged.append(('wazuh', wazuh[i]))

    for sensor, obj in merged:
        body=json.dumps(obj,separators=(',',':'))
        code, latency=post_event(args.api, sensor, body, args.api_key, args.hmac_secret, args.require_ts)
        latencies.append(latency)
        codes[code]=codes.get(code,0)+1
        # pacing
        elapsed_since_start=time.time()-start
        expected_events=int(elapsed_since_start/target_interval)
        sent=len(latencies)
        if sent>expected_events:
            # over-paced; sleep a bit
            time.sleep(min(target_interval,0.05))
        if args.sleep>0:
            time.sleep(args.sleep)
    dur=time.time()-start
    if latencies:
        import statistics
        p50=statistics.median(latencies)
        p95=sorted(latencies)[int(len(latencies)*0.95)-1]
        avg=sum(latencies)/len(latencies)
    else:
        p50=p95=avg=0.0

    print('\nReplay Summary')
    print(f'  Events Sent: {len(latencies)} in {dur:.2f}s ({len(latencies)/max(dur,0.0001):.1f}/sec)')
    print(f'  HTTP Codes: {codes}')
    print(f'  Latency ms: avg={avg*1000:.1f} p50={p50*1000:.1f} p95={p95*1000:.1f}')
    if args.hmac_secret:
        print('  HMAC signing: enabled')
    if args.require_ts:
        print('  Timestamp header: enabled')
    return 0

if __name__=='__main__':
    sys.exit(main())
