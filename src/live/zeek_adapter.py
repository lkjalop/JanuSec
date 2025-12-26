"""Zeek log adapter (Phase 2).

Expected JSON line inputs (pre-converted from TSV): conn.log, dns.log, http.log, ssl.log.
Adds http/dns/ssl parsing alongside conn mapping and extracts JA3/JA3S and
HTTP User-Agent fields for downstream hunters.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Dict

# Best-effort import: log heartbeat updates for DNS/conn when events parsed
try:
    from src.core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
except Exception:  # pragma: no cover - lite environments
    try:
        from core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
    except Exception:
        _hb_update = None  # type: ignore

CONN_FIELDS = {
    'ts': 'ts',
    'id.orig_h': 'orig_host',
    'id.resp_h': 'resp_host',
    'id.resp_p': 'resp_p',
    'proto': 'proto',
    'service': 'service',
    'duration': 'duration',
    'orig_bytes': 'orig_bytes',
    'resp_bytes': 'resp_bytes',
}

DNS_FIELDS = {
    'ts': 'ts',
    'id.orig_h': 'orig_host',
    'id.resp_h': 'resp_host',
    'query': 'query',
    'qtype_name': 'qtype',
    'rcode_name': 'rcode',
}

HTTP_FIELDS = {
    'ts': 'ts',
    'id.orig_h': 'orig_host',
    'id.resp_h': 'resp_host',
    'id.resp_p': 'resp_p',
    'method': 'method',
    'host': 'host',
    'uri': 'uri',
    'user_agent': 'user_agent',
    'status_code': 'status',
}

SSL_FIELDS = {
    'ts': 'ts',
    'id.orig_h': 'orig_host',
    'id.resp_h': 'resp_host',
    'id.resp_p': 'resp_p',
    'ja3': 'ja3',
    'ja3s': 'ja3s',
    'version': 'version',
    'cipher': 'cipher',
}

def parse_conn(line: str) -> dict[str,Any] | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
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
        'tags': ['zeek', 'conn']
    }
    # Record Zeek conn heartbeat
    try:
        if _hb_update:
            _hb_update('zeek_conn')
    except Exception:
        pass
    return ev


def parse_dns(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
    for zf, k in DNS_FIELDS.items():
        if zf in obj:
            out[k] = obj[zf]
    qname = obj.get('query') or obj.get('qname')
    ev = {
        'ts': out.get('ts'),
        'host': out.get('orig_host'),
        'dest_ip': out.get('resp_host'),
        'event_type': 'dns',
        'dns_query': qname,
        'dns_qtype': out.get('qtype'),
        'dns_rcode': out.get('rcode'),
        'tags': ['zeek', 'dns'],
    }
    # Record DNS heartbeat
    try:
        if _hb_update:
            _hb_update('dns')
    except Exception:
        pass
    return ev


def parse_http(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
    for zf, k in HTTP_FIELDS.items():
        if zf in obj:
            out[k] = obj[zf]
    ua = obj.get('user_agent') or obj.get('user-agent')
    uri = obj.get('uri') or obj.get('uri_path')
    host = obj.get('host')
    return {
        'ts': out.get('ts'),
        'host': out.get('orig_host'),
        'dest_ip': out.get('resp_host'),
        'dest_port': out.get('resp_p'),
        'event_type': 'http',
        'http_method': out.get('method'),
        'http_host': host,
        'http_uri': uri,
        'http_user_agent': ua,
        'tags': ['zeek', 'http'],
    }


def parse_ssl(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
    for zf, k in SSL_FIELDS.items():
        if zf in obj:
            out[k] = obj[zf]
    return {
        'ts': out.get('ts'),
        'host': out.get('orig_host'),
        'dest_ip': out.get('resp_host'),
        'dest_port': out.get('resp_p'),
        'event_type': 'ssl',
        'ja3': out.get('ja3'),
        'ja3s': out.get('ja3s'),
        'ssl_version': out.get('version'),
        'ssl_cipher': out.get('cipher'),
        'tags': ['zeek', 'ssl'],
    }


def parse_zeek_line(kind: str, line: str) -> dict[str, Any] | None:
    """Dispatch parsing based on log kind: conn|dns|http|ssl.

    Returns a normalized event dict or None if parsing fails.
    """
    kind_l = (kind or '').strip().lower()
    if kind_l == 'conn':
        return parse_conn(line)
    if kind_l == 'dns':
        return parse_dns(line)
    if kind_l == 'http':
        return parse_http(line)
    if kind_l == 'ssl':
        return parse_ssl(line)
    # try auto-detect minimal fields
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if 'query' in obj or 'qname' in obj:
        return parse_dns(line)
    if 'user_agent' in obj or 'method' in obj:
        return parse_http(line)
    if 'ja3' in obj or 'ja3s' in obj:
        return parse_ssl(line)
    # basic ssh (for HASSH) if Zeek ssh.log-like fields present
    if 'kex_algs' in obj or 'encr_algs' in obj or 'mac_algs' in obj:
        try:
            # HASSH spec uses a normalized concat; here we provide a simplified variant
            import hashlib
            parts = [str(obj.get('kex_algs','')).lower(), str(obj.get('encr_algs','')).lower(), str(obj.get('mac_algs','')).lower(), str(obj.get('comp_algs','')).lower()]
            concat = ';'.join(parts)
            hassh = hashlib.md5(concat.encode()).hexdigest()
            return {
                'ts': obj.get('ts'),
                'host': obj.get('id.orig_h') or obj.get('orig_h'),
                'dest_ip': obj.get('id.resp_h') or obj.get('resp_h'),
                'event_type': 'ssh',
                'hassh': hassh,
                'tags': ['zeek','ssh']
            }
        except Exception:
            return None
    return parse_conn(line)

__all__ = ['parse_conn', 'parse_dns', 'parse_http', 'parse_ssl', 'parse_zeek_line']
