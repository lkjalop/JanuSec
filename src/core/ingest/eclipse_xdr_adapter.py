"""Eclipse XDR Adapter

Transforms inbound Eclipse.XDR event payloads (single or batch) into the
canonical internal event schema expected by the event pipeline / policy layer.

Only extracts minimal fields required for current factors + policy. Raw payload
is truncated to MAX_RAW bytes (env override) to avoid excessive storage.
"""
from __future__ import annotations
from typing import Any, Dict, List
import os, hashlib, time

MAX_RAW = int(os.getenv('MAX_RAW_PAYLOAD_BYTES','32768'))

CANONICAL_FIELDS = [
    'tenant_id','event_id','ts','process_name','command_line','parent_process',
    'domain','dst_ip','dst_port','bytes_out','sbom_component'
]

def _gen_event_id(tenant: str | None, payload: Dict[str, Any]) -> str:
    base = (tenant or 'default') + '|' + str(payload.get('timestamp') or payload.get('ts') or time.time()) + '|' + (payload.get('domain') or payload.get('command_line') or '')[:80]
    return hashlib.sha256(base.encode()).hexdigest()[:32]

def normalize_single(raw: Dict[str, Any], tenant: str | None) -> Dict[str, Any]:
    """Return canonical internal event.

    Input is an Eclipse.XDR event (fields vary). We map conservative set.
    """
    event_id = raw.get('id') or raw.get('event_id') or raw.get('uuid')
    if not event_id:
        event_id = _gen_event_id(tenant, raw)
    ts = raw.get('ts') or raw.get('timestamp') or raw.get('time')
    # Convert iso8601/str to epoch ms best-effort
    if isinstance(ts, str):
        try:
            from datetime import datetime
            # Attempt multiple formats
            for fmt in ('%Y-%m-%dT%H:%M:%S.%fZ','%Y-%m-%dT%H:%M:%SZ','%Y-%m-%d %H:%M:%S'):
                try:
                    dt = datetime.strptime(ts, fmt)
                    ts = int(dt.timestamp()*1000)
                    break
                except Exception:
                    continue
        except Exception:
            ts = int(time.time()*1000)
    if isinstance(ts, (int,float)) and ts < 10_000_000_000:  # seconds -> ms
        ts = int(ts*1000)
    cmd = raw.get('command_line') or raw.get('cmd') or raw.get('process_command')
    proc = raw.get('process_name') or raw.get('process') or (cmd.split()[0] if isinstance(cmd,str) and cmd else None)
    parent = raw.get('parent_process') or raw.get('ppid_name')
    dom = raw.get('domain') or raw.get('dns_query')
    dst_ip = raw.get('dst_ip') or raw.get('remote_ip')
    dst_port = raw.get('dst_port') or raw.get('remote_port')
    bytes_out = raw.get('bytes_out') or raw.get('out_bytes') or raw.get('tx_bytes')
    sbom_component = raw.get('component') or raw.get('sbom_component')
    raw_copy = raw.copy()
    raw_bytes = str(raw_copy).encode('utf-8','ignore')
    if len(raw_bytes) > MAX_RAW:
        # Truncate marker
        raw_copy = {'truncated': True, 'sha256': hashlib.sha256(raw_bytes).hexdigest()}
    return {
        'tenant_id': tenant,
        'event_id': event_id,
        'ts': int(ts) if isinstance(ts,(int,float)) else int(time.time()*1000),
        'process_name': proc,
        'command_line': cmd,
        'parent_process': parent,
        'domain': dom,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'bytes_out': bytes_out,
        'sbom_component': sbom_component,
        'raw': raw_copy
    }

def parse(body: Any, tenant: str | None) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [normalize_single(ev, tenant) for ev in body if isinstance(ev, dict)]
    if isinstance(body, dict):
        return [normalize_single(body, tenant)]
    return []
