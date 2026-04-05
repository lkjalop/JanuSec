#!/usr/bin/env python3
"""Reconstruct multi-domain attack batch into summarized artifact.

Reads fixture: tests/fixtures/e2e_multi_domain_attack.json
Outputs JSON summary to stdout (or --out path) with:
  event_count
  domain_counts
  ordered_types
  factors (expected)
  hopgraph_nodes / edges (if API reachable and --live flag used)
  correlation_summary (placeholder)
"""
from __future__ import annotations
import json, os, sys, argparse, time
from collections import Counter

EXPECTED_FACTORS = [
    'email:domain_homograph','identity:credential_stuffing','remote:jump_host_chain',
    'endpoint:unsigned_exec','net:flow_microcluster_exfil','data:large_extract',
    'cloud:public_bucket','app:api_abuse','corr_multi_domain_chain'
]

DEF_FIXTURE = 'tests/fixtures/e2e_multi_domain_attack.json'

def load_fixture(path: str):
    with open(path,'r',encoding='utf-8') as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--fixture', default=DEF_FIXTURE)
    ap.add_argument('--out', default='-')
    ap.add_argument('--live', action='store_true', help='If set, POST events to local API for a live reconstruction (requires server)')
    ap.add_argument('--api-base', default='http://localhost:8080')
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    args = ap.parse_args()

    data = load_fixture(args.fixture)
    evs = data.get('events', [])
    types = [e.get('type') for e in evs]
    c = Counter(types)
    summary = {
        'attack_id': data.get('attack_id'),
        'event_count': len(evs),
        'domain_counts': dict(c),
        'ordered_types': types,
        'expected_factors': EXPECTED_FACTORS,
        'generated_ts': time.time(),
        'live_posted': False,
    }
    if args.live:
        import requests
        headers = {'x-api-key': args.api_key}
        for e in evs:
            t = e.get('type')
            payload = e.get('payload') or {}
            endpoint_map = {
                'email': '/api/v1/email/ingest',
                'identity': '/api/v1/identity/ingest',
                'remote_access': '/api/v1/remote_access/ingest',
                'endpoint': '/api/v1/endpoints/log_batch',
                'network': '/api/v1/network/ingest',
                'cloud': '/api/v1/cloud/ingest',
                'data_access': '/api/v1/data/ingest',
                'app': '/api/v1/app/ingest'
            }
            ep = endpoint_map.get(t)
            if not ep:
                continue
            url = args.api_base + ep
            if t == 'endpoint':
                payload = {'events':[{'host': payload.get('host'), 'process': {'name': payload.get('process'), 'command': payload.get('command')}, 'details': {'user': payload.get('user')}}]}
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=5)
                r.raise_for_status()
            except Exception as exc:
                summary.setdefault('post_errors', []).append({'endpoint': ep, 'error': str(exc)})
        summary['live_posted'] = True
        # Attempt to fetch recent decisions for correlation factor presence
        try:
            r = requests.get(args.api_base + '/api/v1/decisions/recent?limit=10', headers=headers, timeout=5)
            if r.ok:
                decs = r.json().get('decisions', [])
                for d in decs:
                    fs = d.get('factors') or []
                    if any(f.startswith('corr_') for f in fs):
                        summary['correlation_decision_id'] = d.get('event_id')
                        summary['correlation_factors'] = fs
                        break
        except Exception:
            pass
    out_json = json.dumps(summary, indent=2)
    if args.out == '-' or not args.out:
        print(out_json)
    else:
        with open(args.out,'w',encoding='utf-8') as f:
            f.write(out_json)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
