from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

DEFAULT_PATH = os.getenv('LOG_HEARTBEAT_PATH', 'data/log_heartbeat.json')
DEFAULT_TTL = int(os.getenv('LOG_HEARTBEAT_TTL_SECONDS', '600') or 600)
DEFAULT_TTLS = {
    'firewall': 3600,
    'dns': 3600,
    'netflow': 1800,
    'ids_ips': 1800,
    'zeek_conn': 1800,
    'pcap': 0,          # supplemental
    'proxy_waf': 0,     # supplemental
    'sysmon': 0         # supplemental (EID 3)
}


def update(source: str, ts: Optional[float] = None, path: Optional[str] = None) -> None:
    """Record a heartbeat for a given log source.

    - `source`: short key such as 'network', 'endpoint', 'email', 'cloud', 'siem'.
    - `ts`: optional epoch seconds; defaults to now.
    - `path`: optional override path for heartbeat file.
    """
    p = path or DEFAULT_PATH
    now = float(ts or time.time())
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
    except Exception:
        pass
    data: Dict[str, Any] = {}
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
    except Exception:
        data = {}
    sources: Dict[str, Any] = data.get('sources') or {}
    srec = sources.get(source) or {}
    srec['last_ts'] = now
    srec['count'] = int(srec.get('count', 0)) + 1
    sources[source] = srec
    data['sources'] = sources
    data['last_ok_ts'] = max([s.get('last_ts', 0.0) for s in sources.values()] + [0.0])
    try:
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception:
        pass


def status(ttl_seconds: Optional[int] = None, path: Optional[str] = None) -> Dict[str, Any]:
    """Return heartbeat status suitable for dependency_status banner.

    Shape:
    {
      'available': bool,               # True if any source fresh within TTL
      'last_ok_ts': float | None,
      'seconds_since_ok': float | None,
      'sources': [{ 'name': str, 'last_ts': float, 'seconds_since_ok': float }],
      'missing_sources': [str]         # Sources known via env LOG_HEARTBEAT_SOURCES but stale
    }
    """
    p = path or DEFAULT_PATH
    ttl = int(ttl_seconds or DEFAULT_TTL)
    # Allow per-source TTL overrides via JSON
    try:
        import json as _json
        ttls_env = os.getenv('LOG_HEARTBEAT_TTLS_JSON')
        per_ttl = DEFAULT_TTLS.copy()
        if ttls_env:
            per_ttl.update(_json.loads(ttls_env))
    except Exception:
        per_ttl = DEFAULT_TTLS.copy()
    now = time.time()
    data: Dict[str, Any] = {}
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
    except Exception:
        data = {}
    sources_map: Dict[str, Any] = data.get('sources') or {}
    sources_list: List[Dict[str, Any]] = []
    any_fresh = False
    for name, rec in sources_map.items():
        last_ts = float(rec.get('last_ts') or 0.0)
        secs = max(0.0, now - last_ts) if last_ts > 0 else None
        ttl_for = int(per_ttl.get(name, ttl) or ttl)
        # Severity rules: critical when mandatory source exceeds TTL; warn when approaching TTL; info otherwise.
        mandatory = ttl_for > 0
        severity = None
        if secs is not None and mandatory:
            if secs > ttl_for:
                severity = 'critical'
            elif secs > (0.5 * ttl_for):
                severity = 'warning'
            else:
                severity = 'info'
        elif not mandatory:
            severity = 'supplemental'
        sources_list.append({'name': name, 'last_ts': last_ts, 'seconds_since_ok': secs, 'ttl': ttl_for, 'severity': severity})
        if secs is not None and secs <= ttl:
            any_fresh = True
    last_ok_ts = float(data.get('last_ok_ts') or 0.0) if data else 0.0
    seconds_since_ok = max(0.0, now - last_ok_ts) if last_ok_ts > 0 else None
    # Optional expected source list via env for missing detection
    expected = [s.strip() for s in os.getenv('LOG_HEARTBEAT_SOURCES','').split(',') if s.strip()]
    missing_sources: List[str] = []
    if expected:
        for s in expected:
            rec = sources_map.get(s)
            # Prefer per-source TTL
            ttl_for = int(per_ttl.get(s, ttl) or ttl)
            if not rec or (now - float(rec.get('last_ts') or 0.0)) > ttl_for:
                missing_sources.append(s)
    # Build gap list with messages
    gaps: List[Dict[str, Any]] = []
    for src in sources_list:
        ttl_for = int(src.get('ttl') or ttl)
        secs = src.get('seconds_since_ok')
        if secs is None:
            continue
        if ttl_for <= 0:
            continue
        if secs > ttl_for:
            msg = None
            name = src.get('name')
            if name == 'firewall':
                msg = 'Perimeter firewall logs stale >1h (critical gap)'
            elif name == 'dns':
                msg = 'DNS resolver logs stale >1h (pre-scan/C2 visibility gap)'
            elif name == 'netflow':
                msg = 'NetFlow/IPFIX stale >30m (scan visibility gap)'
            elif name == 'ids_ips':
                msg = 'IDS/IPS alerts stale >30m (corroboration gap)'
            elif name == 'zeek_conn':
                msg = 'Zeek conn.log stale >30m (protocol/flags gap)'
            else:
                msg = f"Log source '{name}' stale beyond TTL"
            gaps.append({'name': name, 'seconds_since_ok': secs, 'ttl': ttl_for, 'severity': 'critical', 'message': msg})
    return {
        'available': any_fresh,
        'last_ok_ts': last_ok_ts if last_ok_ts > 0 else None,
        'seconds_since_ok': seconds_since_ok,
        'sources': sources_list,
        'missing_sources': missing_sources,
        'gaps': gaps
    }

__all__ = ['update', 'status']
