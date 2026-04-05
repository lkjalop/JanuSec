"""Lightweight Netflow/CSV parser fallback.

This module implements a best-effort parser for Netflow CSV exports or
simple Netflow v5-like CSV rows. For production IPFIX parsing a proper
library should be used; this acts as a practical fallback for tests.
"""
from __future__ import annotations

from typing import Iterable, Dict


def parse_netflow_csv_lines(lines: Iterable[str]) -> Iterable[Dict[str, any]]:
    # Expect header line with names like srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes
    headers = None
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if headers is None:
            headers = [h.strip() for h in line.split(',')]
            # ensure we have a header; if it's actual data, we'll try to parse anyway
            if any(h.lower() in ('srcaddr','src_ip','src') for h in headers):
                continue
        parts = [p.strip() for p in line.split(',')]
        if headers and len(parts) == len(headers):
            rec = dict(zip(headers, parts))
        else:
            # Fallback to positional mapping
            keys = ['srcaddr','dstaddr','srcport','dstport','protocol','packets','bytes']
            rec = {k: parts[i] if i < len(parts) else '' for i,k in enumerate(keys)}

        ev = {
            'type': 'netflow.record',
            'timestamp': None,
            'src_ip': rec.get('srcaddr') or rec.get('src_ip') or rec.get('src'),
            'dst_ip': rec.get('dstaddr') or rec.get('dst_ip') or rec.get('dst'),
            'src_port': int(rec.get('srcport')) if rec.get('srcport') and rec.get('srcport').isdigit() else None,
            'dst_port': int(rec.get('dstport')) if rec.get('dstport') and rec.get('dstport').isdigit() else None,
            'protocol': rec.get('protocol'),
            'packets': int(rec.get('packets')) if rec.get('packets') and rec.get('packets').isdigit() else None,
            'bytes': int(rec.get('bytes')) if rec.get('bytes') and rec.get('bytes').isdigit() else None,
            'raw': rec,
        }
        yield ev
"""Minimal Netflow/IPFIX parser stub.

This provides normalization helpers for netflow-like records. Replace
with a real parser (e.g. using nfstream or pyflowtools) when integrating.
"""
from typing import Dict, Any


def parse_netflow_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'type': 'netflow',
        'src_ip': record.get('src_addr') or record.get('src_ip'),
        'dst_ip': record.get('dst_addr') or record.get('dst_ip'),
        'src_port': record.get('src_port'),
        'dst_port': record.get('dst_port'),
        'bytes': int(record.get('bytes') or record.get('octets') or 0),
        'packets': int(record.get('packets') or 0),
        'ts': record.get('ts'),
    }
