"""Zeek Tail Forwarder

Continuously tails Zeek JSON logs (conn.log.json, dns.log.json, etc.) and posts
normalized events to the JanuSec batch endpoint.

Usage (PowerShell):
  python scripts/zeek_tail_forwarder.py --logs D:\Zeek\logs\current --api http://localhost:8000 --state forward_state.json

State file keeps per-file byte offsets for restart continuity.
"""
from __future__ import annotations
import argparse, json, os, time, sys, pathlib, requests, hashlib
from typing import Dict, Any

DEFAULT_FILES = ['conn.log', 'dns.log']

def load_state(path: pathlib.Path) -> dict:
    if not path.exists(): return {}
    try: return json.loads(path.read_text(encoding='utf-8'))
    except Exception: return {}

def save_state(path: pathlib.Path, state: dict):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=2), encoding='utf-8')
    tmp.replace(path)

def map_conn(rec: dict) -> dict:
    uid = rec.get('uid') or hashlib.sha1(json.dumps(rec,sort_keys=True).encode()).hexdigest()[:10]
    return {
        'id': f"zeek-{uid}",
        'host': rec.get('id.orig_h'),
        'dest_ip': rec.get('id.resp_h'),
        'dest_port': rec.get('id.resp_p'),
        'proto': rec.get('proto'),
        'service': rec.get('service'),
        'duration': rec.get('duration'),
        'orig_bytes': rec.get('orig_bytes'),
        'resp_bytes': rec.get('resp_bytes'),
        'tags': ['zeek','conn']
    }

def map_dns(rec: dict) -> dict:
    uid = rec.get('uid') or hashlib.sha1(json.dumps(rec,sort_keys=True).encode()).hexdigest()[:10]
    return {
        'id': f"zeek-dns-{uid}",
        'host': rec.get('id.orig_h'),
        'query': rec.get('query'),
        'rcode': rec.get('rcode'),
        'answers': rec.get('answers'),
        'tags': ['zeek','dns']
    }

def post_batch(api: str, events: list[dict]):
    if not events: return 0
    url = api.rstrip('/') + '/api/v1/endpoints/log_batch'
    try:
        r = requests.post(url, json={'events': events, 'classify': True, 'send_alerts': False, 'include_rules': True}, timeout=3)
        return r.status_code
    except Exception:
        return 0

def tail_once(log_dir: pathlib.Path, files: list[str], state: dict, batch_size: int, api: str):
    batch: list[dict] = []
    changed = False
    for fname in files:
        path = log_dir / fname
        if not path.exists():
            continue
        off = state.get(fname, 0)
        size = path.stat().st_size
        if size < off:
            off = 0  # rotated or truncated
        if size == off:
            continue
        with path.open('r', encoding='utf-8') as f:
            f.seek(off)
            for line in f:
                line=line.strip()
                if not line: continue
                try: rec = json.loads(line)
                except Exception: continue
                if fname.startswith('conn'):
                    batch.append(map_conn(rec))
                elif fname.startswith('dns'):
                    batch.append(map_dns(rec))
                if len(batch) >= batch_size:
                    post_batch(api, batch)
                    batch.clear()
            new_off = f.tell()
        state[fname] = new_off
        changed = True
    if batch:
        post_batch(api, batch)
    return changed

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--logs', required=True, help='Zeek log directory (current)')
    ap.add_argument('--api', default='http://localhost:8000', help='Platform API base')
    ap.add_argument('--interval', type=float, default=2.0)
    ap.add_argument('--files', nargs='*', default=DEFAULT_FILES)
    ap.add_argument('--state', default='zeek_forward_state.json')
    ap.add_argument('--batch-size', type=int, default=50)
    args = ap.parse_args()

    log_dir = pathlib.Path(args.logs)
    if not log_dir.exists():
        print('Log directory not found', file=sys.stderr)
        sys.exit(2)
    state_path = pathlib.Path(args.state)
    state = load_state(state_path)
    print(f"Starting Zeek tail forwarder -> {args.api} watching {args.files}")
    try:
        while True:
            changed = tail_once(log_dir, args.files, state, args.batch_size, args.api)
            if changed:
                save_state(state_path, state)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        save_state(state_path, state)
        print('Stopped.')

if __name__ == '__main__':
    main()
