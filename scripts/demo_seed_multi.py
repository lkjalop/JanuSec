"""Demo multi-source seed script.

Simulates credential theft → lateral movement → DNS exfil across
Zeek, Suricata, and Wazuh using the unified ingestion controller.

Usage:
  python scripts/demo_seed_multi.py --base http://localhost:8080 --api-key devkey123

"""
from __future__ import annotations
import argparse, time, requests, random, json

STEPS = [
    ('credential_theft', 'zeek', [
        {'id_orig_h':'10.0.5.7','id_resp_h':'10.0.1.10','host':'dc01.internal','user':'alice','ts':time.time(), 'query':'login.internal'},
        {'id_orig_h':'10.0.5.7','id_resp_h':'10.0.1.11','host':'fs01.internal','user':'alice','ts':time.time()+1,'query':'cifs.internal'}
    ]),
    ('suricata_alerts', 'suricata', [
        {'src_ip':'10.0.5.7','dest_ip':'10.0.1.20','alert':{'signature':'Possible Lateral Movement Tool'},'severity':3,'ts':time.time()+2},
        {'src_ip':'10.0.5.7','dest_ip':'10.0.1.22','alert':{'signature':'Suspicious SMB Write'},'severity':2,'ts':time.time()+3}
    ]),
    ('privilege_escalation', 'wazuh', [
        {'agent':{'name':'fs01.internal'},'user':'alice','rule':'Unauthorized privilege escalation attempt','ts':time.time()+4},
        {'agent':{'name':'dc01.internal'},'user':'alice','rule':'Policy privilege modification','ts':time.time()+5}
    ]),
    ('dns_exfil', 'zeek', [
        {'id_orig_h':'10.0.5.7','id_resp_h':'8.8.8.8','query':'q1.data-leak.example.com','ts':time.time()+6},
        {'id_orig_h':'10.0.5.7','id_resp_h':'8.8.8.8','query':'q2.data-leak.example.com','ts':time.time()+7},
        {'id_orig_h':'10.0.5.7','id_resp_h':'8.8.8.8','query':'q3.data-leak.example.com','ts':time.time()+8}
    ])
]

def post(base: str, api_key: str, sensor: str, events):
    url = f"{base.rstrip('/')}/api/v1/ingest/{sensor}"
    headers = {'x-api-key': api_key, 'content-type':'application/json'}
    r = requests.post(url, headers=headers, data=json.dumps(events))
    if not r.ok:
        print('POST', sensor, 'failed', r.status_code, r.text[:200])
    else:
        print('POST', sensor, 'ok', r.json())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', default='http://localhost:8080')
    ap.add_argument('--api-key', default='devkey123')
    ap.add_argument('--delay', type=float, default=1.0, help='Delay seconds between scenario steps')
    args = ap.parse_args()
    for label, sensor, evs in STEPS:
        print(f"== Step: {label} ({sensor}) events={len(evs)}")
        post(args.base, args.api_key, sensor, evs)
        time.sleep(args.delay)
    # Final status fetch
    try:
        r = requests.get(f"{args.base.rstrip('/')}/api/v1/ingest/status", headers={'x-api-key':args.api_key})
        if r.ok:
            print('Final status:', json.dumps(r.json(), indent=2)[:800])
    except Exception:
        pass

if __name__ == '__main__':
    main()
