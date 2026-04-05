"""Generate synthetic events and artifact batches to exercise pipeline for demo.

Usage (PowerShell example):
  python scripts/generate_demo_events.py --host http://localhost:8080 --mode all

Modes:
  events   -> sends process events (benign + rare lineage + burst)
  artifacts-> submits an artifact batch with mixed risk
  all      -> both
"""
from __future__ import annotations
import argparse, time, json, sys
import http.client
from urllib.parse import urlparse


def _post_json(base: str, path: str, payload: dict):
    url = urlparse(base)
    conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=10)
    body = json.dumps(payload).encode()
    conn.request('POST', path, body, headers={'Content-Type':'application/json'})
    resp = conn.getresponse()
    data = resp.read().decode()
    if resp.status >= 300:
        print(f"POST {path} failed {resp.status}: {data[:200]}")
    else:
        print(f"POST {path} -> {resp.status}")
    conn.close()
    return resp.status, data

def send_events(base: str):
    print('[*] Sending benign process event')
    _post_json(base,'/api/v1/events',{
        'id':'demo-benign-1','event_type':'process_start','details':{'process':{'name':'notepad.exe','parent_name':'explorer.exe'}}
    })
    print('[*] Sending rare lineage event (wscript.exe -> rundll32.exe)')
    _post_json(base,'/api/v1/events',{
        'id':'demo-rare-1','event_type':'process_start','details':{'process':{'name':'rundll32.exe','parent_name':'wscript.exe'}}
    })
    print('[*] Sending repeat lineage to stabilize (factor should disappear after cutoff)')
    for i in range(6):
        _post_json(base,'/api/v1/events',{
            'id':f'demo-rare-repeat-{i}','event_type':'process_start','details':{'process':{'name':'rundll32.exe','parent_name':'wscript.exe'}}
        })
    print('[*] Sending potential burst on host H1')
    for i in range(10):
        _post_json(base,'/api/v1/events',{
            'id':f'demo-burst-{i}','event_type':'process_start','details':{'process':{'name':f'p{i}.exe','parent_name':'init'},'host_id':'H1'}
        })

def send_artifacts(base: str):
    print('[*] Submitting artifact batch')
    batch = {
        'items': [
            {'path':'C:/Users/user/Downloads/plink.exe','name':'plink.exe','command_line':'plink.exe -R 8080:localhost:80','zone_id':3,'artifact_type':'executable'},
            {'path':'C:/temp/evil.exe','name':'evil.exe','entropy_high_section':True,'signed':False,'compile_recent_anomaly':True,'artifact_type':'executable'},
            {'path':'C:/Users/user/Documents/invoice.docm','name':'invoice.docm','macro_autoexec':True,'macro_obfuscated':True,'artifact_type':'document'}
        ],
        'batch_id':'demo-batch'
    }
    _post_json(base,'/api/v1/artifacts/analyze_batch', batch)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='http://localhost:8080')
    ap.add_argument('--mode', choices=['events','artifacts','all'], default='all')
    args = ap.parse_args()
    if args.mode in ('events','all'):
        send_events(args.host)
    if args.mode in ('artifacts','all'):
        send_artifacts(args.host)
    print('[*] Done. Retrieve decisions via /debug/decision/<id> or artifact report via /api/v1/artifacts/latest_report')

if __name__ == '__main__':
    main()
