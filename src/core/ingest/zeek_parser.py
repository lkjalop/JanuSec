"""Zeek TSV parser for conn.log-like files.

This parser reads a Zeek TSV line (headerless or with header) and emits
normalized event dicts suitable for the ingestion worker.
"""
from __future__ import annotations

from typing import Dict, Iterable, List


def parse_zeek_tsv_lines(lines: Iterable[str]) -> Iterable[Dict[str, any]]:
    # Zeek logs often start with '#fields' header lines, and the log type can
    # be inferred via the fields present. We'll attempt to map conn, http,
    # dns, and files logs to richer canonical events.
    headers: List[str] | None = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#separator'):
            continue
        if line.startswith('#fields'):
            headers = line.split()[1:]
            continue
        if line.startswith('#'):
            continue
        parts = line.split('\t')
        if headers and len(parts) == len(headers):
            rec = dict(zip(headers, parts))
        else:
            # fallback mapping to conn-like fields
            keys = ['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto']
            rec = {k: parts[i] if i < len(parts) else '' for i,k in enumerate(keys)}

        # Heuristic: determine log type
        if 'uri' in (headers or []) or 'method' in (headers or []):
            # http log
            ev = {
                'type': 'zeek.http',
                'timestamp': float(rec.get('ts') or 0.0),
                'uid': rec.get('uid'),
                'src_ip': rec.get('id.orig_h'),
                'src_port': int(rec.get('id.orig_p')) if rec.get('id.orig_p') else None,
                'dst_ip': rec.get('id.resp_h'),
                'dst_port': int(rec.get('id.resp_p')) if rec.get('id.resp_p') else None,
                'method': rec.get('method'),
                'uri': rec.get('uri'),
                'host': rec.get('host'),
                'status_code': rec.get('status_code'),
                'raw': rec,
            }
            yield ev
            continue

        if 'qtype' in (headers or []) or 'qclass' in (headers or []):
            # dns log
            ev = {
                'type': 'zeek.dns',
                'timestamp': float(rec.get('ts') or 0.0),
                'uid': rec.get('uid'),
                'src_ip': rec.get('id.orig_h'),
                'dst_ip': rec.get('id.resp_h'),
                'query': rec.get('query') or rec.get('qname'),
                'qtype': rec.get('qtype'),
                'rcode': rec.get('rcode'),
                'answers': rec.get('answers'),
                'raw': rec,
            }
            yield ev
            continue

        if 'filename' in (headers or []) or 'md5' in (headers or []):
            # files log
            ev = {
                'type': 'zeek.files',
                'timestamp': float(rec.get('ts') or 0.0),
                'uid': rec.get('uid'),
                'src_ip': rec.get('id.orig_h'),
                'dst_ip': rec.get('id.resp_h'),
                'filename': rec.get('filename'),
                'md5': rec.get('md5'),
                'sha1': rec.get('sha1'),
                'raw': rec,
            }
            yield ev
            continue

        # default: treat as connection
        ev = {
            'type': 'zeek.conn',
            'timestamp': float(rec.get('ts') or 0.0),
            'uid': rec.get('uid'),
            'src_ip': rec.get('id.orig_h') or rec.get('src_ip'),
            'src_port': int(rec.get('id.orig_p') or 0) if rec.get('id.orig_p') else None,
            'dst_ip': rec.get('id.resp_h') or rec.get('dst_ip'),
            'dst_port': int(rec.get('id.resp_p') or 0) if rec.get('id.resp_p') else None,
            'proto': rec.get('proto'),
            'raw': rec,
        }
        yield ev
"""Minimal Zeek log parser stub.

This file contains a lightweight parser stub that accepts a Zeek conn.log
style line or dict and returns a normalized event dict. Replace with
full parser when integrating real Zeek logs.
"""
from typing import Dict, Any


def parse_zeek_conn(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Zeek conn record to common fields.

    Expected minimal input keys: `id_orig_h`, `id_resp_h`, `service`, `duration`, `proto`.
    """
    out = {
        'type': 'zeek_conn',
        'src_ip': record.get('id.orig_h') or record.get('src_ip') or record.get('id_orig_h'),
        'dst_ip': record.get('id.resp_h') or record.get('dst_ip') or record.get('id_resp_h'),
        'service': record.get('service') or record.get('proto') or record.get('service_name'),
        'duration': float(record.get('duration') or 0.0),
        'timestamp': record.get('ts') or record.get('ts_usec') or None,
    }
    return out
