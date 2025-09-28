"""Zeek log adapter (Phase 1 skeleton).

Expected JSON line inputs (pre-converted from TSV): conn.log, dns.log, http.log.
Focus: conn.log mapping initially.
"""
from __future__ import annotations
import json
from typing import Iterable, Dict, Any

CONN_FIELDS = {
    'ts':'ts', 'id.orig_h':'orig_host', 'id.resp_h':'resp_host', 'id.resp_p':'resp_p',
    'proto':'proto','service':'service','duration':'duration','orig_bytes':'orig_bytes','resp_bytes':'resp_bytes'
}

def parse_conn(line: str) -> Dict[str,Any] | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out = {}
    for zf, k in CONN_FIELDS.items():
        if zf in obj:
            out[k] = obj[zf]
    # Map to normalized event structure subset
    ev = {
        'ts': out.get('ts'),
        'host': out.get('orig_host'),
        'user': 'zeek',
        'proc_name': f"zeek:{out.get('service') or out.get('proto') or 'conn'}",
        'dest_ip': out.get('resp_host'),
        'dest_port': out.get('resp_p'),
        'proto': out.get('proto'),
        'tags': ['zeek','conn']
    }
    return ev
