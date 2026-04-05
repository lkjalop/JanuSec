"""Canonical field mapping & header suggestion library.

Extended to include broader platform canonical fields required for early
customer ingestion readiness (timestamp, source_type, action, outcome, ip_src,
ip_dst). Aliases map heterogeneous vendor headers to these canonical names.
Confidence scoring (simple heuristic) is provided via `suggest_with_confidence`
for header inference workflows.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

CANONICAL_FIELDS = {
    'timestamp',      # event timestamp (float|str convertible)
    'source_type',    # adapter/feed identifier (e.g. zeek_dns, edr_process)
    'ip_src',         # source IP
    'ip_dst',         # destination IP
    'user',
    'host',
    'process',
    'file_hash',
    'domain',
    'action',         # verb/activity (e.g. connect, execute, write)
    'outcome'         # result/status (e.g. success, fail, denied)
}

_ALIASES = {
    # User
    'username': 'user', 'email': 'user', 'user_name': 'user', 'acct': 'user',
    # Host / process
    'hostname': 'host', 'host_name': 'host', 'proc': 'process', 'process_name': 'process', 'exe': 'process',
    # File / hash
    'sha256': 'file_hash', 'hash': 'file_hash', 'file_sha256': 'file_hash', 'filehash': 'file_hash',
    # Domain / network
    'fqdn': 'domain', 'query': 'domain', 'domain_name': 'domain',
    'dest_ip': 'ip_dst', 'destination_ip': 'ip_dst', 'dip': 'ip_dst', 'remote_ip': 'ip_dst',
    'src_ip': 'ip_src', 'source_ip': 'ip_src', 'sip': 'ip_src', 'local_ip': 'ip_src', 'ip': 'ip_src',
    # Timestamp
    '@timestamp': 'timestamp', 'event_time': 'timestamp', 'time': 'timestamp', 'ts': 'timestamp',
    # Source type
    'sensor': 'source_type', 'feed': 'source_type', 'adapter': 'source_type', 'source': 'source_type',
    # Action / outcome
    'operation': 'action', 'activity': 'action', 'event_action': 'action', 'verb': 'action',
    'result': 'outcome', 'status': 'outcome', 'outcome': 'outcome', 'disposition': 'outcome'
}

def suggest(field: str) -> Optional[str]:
    """Return canonical field name or None if no mapping found."""
    f = (field or '').strip().lower()
    if not f:
        return None
    if f in CANONICAL_FIELDS:
        return f
    return _ALIASES.get(f)

def suggest_with_confidence(field: str) -> Tuple[Optional[str], float]:
    """Return (canonical, confidence) where confidence in [0.0,1.0].

    Heuristic scoring:
    - Exact canonical match: 1.0
    - Alias match: 0.85
    - Suffix/prefix heuristic (e.g. *_ip, ip_*): 0.60
    - Fallback None
    """
    canonical = suggest(field)
    if canonical:
        return canonical, 1.0 if field.lower() == canonical else 0.85
    f = field.lower()
    # Simple heuristic expansions
    if f.endswith('_ip'):
        return 'ip_src', 0.60
    if f.startswith('ip_'):
        return 'ip_src', 0.55
    if f.endswith('_domain'):
        return 'domain', 0.55
    return None, 0.0

def build_mapping(headers: Dict[str, str]) -> Dict[str, str]:
    """Build mapping canonical->original_header using simple first-match policy."""
    out: Dict[str, str] = {}
    for k, _v in headers.items():  # _v may be sample value
        s = suggest(k)
        if s and s not in out:
            out[s] = k
    return out

def build_mapping_with_confidence(headers: Dict[str, str]) -> Dict[str, Dict[str, float | str]]:
    """Return mapping details {canonical: {header: str, confidence: float}} for UI."""
    out: Dict[str, Dict[str, float | str]] = {}
    for k, _v in headers.items():
        c, conf = suggest_with_confidence(k)
        if c and c not in out:
            out[c] = {'header': k, 'confidence': conf}
    return out

__all__ = ['suggest', 'suggest_with_confidence', 'build_mapping', 'build_mapping_with_confidence', 'CANONICAL_FIELDS']
