#!/usr/bin/env python3
"""
Zeek pcap/log replay: parse conn.log and dns.log (TSV with Zeek headers or NDJSON)
and push converted events through JanuSec at controlled batch size/rate.

Usage:
  python scripts/zeek_replay.py --api http://localhost:8080 --conn /path/conn.log --dns /path/dns.log \
    --batch 100 --rate 500 --sleep 0.1
"""
from __future__ import annotations
import argparse
import time
import sys
from typing import Any, Dict, Iterable, List

import requests


def _parse_zeek_tsv(path: str) -> Iterable[Dict[str, Any]]:
    fields: List[str] | None = None
    sep = '\t'
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line:
                continue
            if line.startswith('#'):
                if line.startswith('#separator'):
                    parts = line.split('\t')
                    if len(parts) > 1:
                        # Zeek escapes separator; default to tab if parse fails
                        try:
                            sep = bytes(parts[-1], 'utf-8').decode('unicode_escape')
                        except Exception:
                            sep = '\t'
                elif line.startswith('#fields'):
                    parts = line.split('\t')
                    fields = parts[1:]
                continue
            if fields is None:
                continue
            vals = line.split(sep)
            rec = {fields[i]: (vals[i] if i < len(vals) else '') for i in range(len(fields))}
            yield rec


def _parse_ndjson(path: str) -> Iterable[Dict[str, Any]]:
    import json
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _smart_parse(path: str) -> Iterable[Dict[str, Any]]:
    # Peek first non-empty non-comment line
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            if s.startswith('#'):
                break
            if s.startswith('{'):
                return _parse_ndjson(path)
            break
    # default to TSV
    return _parse_zeek_tsv(path)


def _conn_to_event(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': f"zeek-conn-{rec.get('uid') or int(time.time()*1000)}",
        'ts': time.time(),
        'host': rec.get('id.orig_h') or 'UNKNOWN',
        'proc_name': 'zeek:conn',
        'dest_ip': rec.get('id.resp_h'),
        'dest_port': int(rec.get('id.resp_p') or 0) if str(rec.get('id.resp_p') or '').isdigit() else 0,
        'proto': rec.get('proto') or 'tcp',
        'duration': float(rec.get('duration') or 0) if str(rec.get('duration') or '').replace('.','',1).isdigit() else 0.0,
        'orig_bytes': int(rec.get('orig_bytes') or 0) if str(rec.get('orig_bytes') or '').isdigit() else 0,
        'resp_bytes': int(rec.get('resp_bytes') or 0) if str(rec.get('resp_bytes') or '').isdigit() else 0,
        'service': rec.get('service') or '-',
        'tags': ['zeek','conn'],
    }


def _dns_to_event(rec: Dict[str, Any]) -> Dict[str, Any]:
    # Zeek DNS fields may include: query, qclass_name, rcode_name, id.orig_h
    rcode = rec.get('rcode_name') or rec.get('rcode') or ''
    query = rec.get('query') or rec.get('dns_query') or ''
    return {
        'id': f"zeek-dns-{rec.get('uid') or int(time.time()*1000)}",
        'ts': time.time(),
        'host': rec.get('id.orig_h') or 'UNKNOWN',
        'proc_name': 'zeek:dns',
        'dest_ip': rec.get('id.resp_h') or '8.8.8.8',
        'dest_port': 53,
        'dns_rcode': rcode,
        'dns_query': query,
        'tags': ['zeek','dns'],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://localhost:8080')
    ap.add_argument('--conn', help='Path to Zeek conn.log (TSV or NDJSON)')
    ap.add_argument('--dns', help='Path to Zeek dns.log (TSV or NDJSON)')
    ap.add_argument('--batch', type=int, default=100)
    ap.add_argument('--rate', type=int, default=500, help='target events/sec (best-effort)')
    ap.add_argument('--sleep', type=float, default=0.1, help='sleep between batches')
    args = ap.parse_args()

    api = args.api.rstrip('/')

    events: List[Dict[str, Any]] = []
    if args.conn:
        for rec in _smart_parse(args.conn):
            events.append(_conn_to_event(rec))
    if args.dns:
        for rec in _smart_parse(args.dns):
            events.append(_dns_to_event(rec))

    if not events:
        print('No events parsed; provide --conn and/or --dns', file=sys.stderr)
        return 2

    # Replay in batches
    total = len(events)
    sent = 0
    idx = 0
    start = time.time()
    while idx < total:
        batch = events[idx: idx + args.batch]
        idx += len(batch)
        try:
            r = requests.post(f"{api}/api/v1/endpoints/log_batch", json={'events': batch, 'classify': True}, timeout=30)
            if r.status_code != 200:
                print(f"batch error status={r.status_code}", file=sys.stderr)
            else:
                sent += len(batch)
        except Exception as exc:
            print(f"batch error: {exc}", file=sys.stderr)
        time.sleep(args.sleep)
        # crude throttle check
        elapsed = time.time() - start
        if elapsed > 0:
            cur_rate = sent / elapsed
            if cur_rate > args.rate:
                time.sleep(min(1.0, (cur_rate / args.rate) * args.sleep))

    dur = time.time() - start
    print(f"Replayed {sent}/{total} events in {dur:.1f}s ({sent/max(1.0,dur):.1f} eps)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
