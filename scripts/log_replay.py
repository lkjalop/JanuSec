"""Replay a JSONL or JSON array of events to the FAST_LIVE_MODE ingest endpoint.

Example:
  python -m scripts.log_replay --file sample.jsonl --batch-size 200 --interval 0.25 --include-rules --send-alerts
"""
from __future__ import annotations

import argparse, json, time, sys, itertools, math, urllib.request

def load_events(path: str):
    with open(path,'r',encoding='utf-8') as f:
        first = f.read(1); f.seek(0)
        if first == '[':
            data = json.load(f)
            if not isinstance(data, list):
                raise SystemExit('Root must be JSON array')
            for obj in data:
                if isinstance(obj, dict):
                    yield obj
        else:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    yield obj

def chunk(iterable, size):
    it = iter(iterable)
    while True:
        buf = list(itertools.islice(it, size))
        if not buf: break
        yield buf

def post_batch(url: str, batch, classify: bool, include_rules: bool, send_alerts: bool):
    payload = json.dumps({
        'events': batch,
        'classify': classify,
        'include_rules': include_rules,
        'send_alerts': send_alerts
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
        return resp.read().decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True)
    ap.add_argument('--endpoint', default='http://localhost:8000/api/v1/endpoints/log_batch')
    ap.add_argument('--batch-size', type=int, default=100)
    ap.add_argument('--interval', type=float, default=1.0)
    ap.add_argument('--classify', action='store_true'); ap.add_argument('--no-classify', dest='classify', action='store_false'); ap.set_defaults(classify=True)
    ap.add_argument('--include-rules', action='store_true')
    ap.add_argument('--send-alerts', action='store_true')
    args = ap.parse_args()
    events = list(load_events(args.file))
    if not events:
        print('No events loaded', file=sys.stderr); return 1
    total = len(events); batches = math.ceil(total/args.batch_size)
    print(f"Replaying {total} events in {batches} batches -> {args.endpoint}")
    start = time.time(); sent=0
    for i, b in enumerate(chunk(events, args.batch_size), start=1):
        try:
            post_batch(args.endpoint, b, args.classify, args.include_rules, args.send_alerts)
        except Exception as e:
            print(f"Batch {i} failed: {e}", file=sys.stderr)
            continue
        sent += len(b)
        print(f"Batch {i}/{batches} sent size={len(b)} cumulative={sent}")
        if i < batches: time.sleep(args.interval)
    dur = time.time()-start; rate = sent/dur if dur>0 else sent
    print(f"Done sent={sent} duration={dur:.2f}s rate={rate:.1f} ev/s")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
