"""Cross-source evidence stitcher.

Normalises evidence rows from heterogeneous telemetry schemas
(Zeek, Okta, Sysmon, CrowdStrike, CloudTrail, AWS GuardDuty, etc.)
into a canonical field set, then groups rows that describe the
same real-world event from different log sources.

The canonical fields are intentionally minimal:
    user, ip, ip_dst, host, process, file, action, ts_iso, source, severity, raw

This enables multi-hop reasoning that can say:
  "Zeek conn.log row 12, Okta log row 31, and Sysmon row 44 all describe
   the same C2 callback from 10.0.1.5 by user alice@corp.com"
instead of describing them as three disconnected data points.
"""
from __future__ import annotations

import re
from typing import Optional

# ── Schema field maps ─────────────────────────────────────────────────────────
# Each entry: canonical_field -> [source_field_names, ...]
# The extractor tries each candidate in order and takes the first non-empty value.

_CANONICAL_FIELD_CANDIDATES: dict[str, list[str]] = {
    'user': [
        # Okta
        'actor.login', 'actor_login',
        # AWS / Azure
        'userIdentity.arn', 'userIdentity_arn', 'userPrincipalName', 'UserId',
        # Windows / Sysmon
        'TargetUserName', 'SubjectUserName', 'user_name',
        # CrowdStrike
        'UserName',
        # Generic
        'user', 'username', 'user_principal_name', 'email', 'account', 'actor', 'entity',
    ],
    'ip': [
        # Zeek
        'id.orig_h', 'id_orig_h', 'orig_h',
        # Okta
        'client.ipAddress', 'client_ipAddress',
        # Windows / Sysmon
        'IpAddress', 'SourceIp', 'source_ip', 'src_ip', 'client_ip',
        # AWS
        'sourceIPAddress',
        # Generic
        'ip', 'remote_address', 'ClientIP',
    ],
    'ip_dst': [
        # Zeek
        'id.resp_h', 'id_resp_h', 'resp_h',
        # Sysmon
        'DestinationIp', 'dst_ip', 'destination_ip',
        # Generic
        'ip_dst', 'dest_ip',
    ],
    'host': [
        # Windows / Sysmon / CrowdStrike
        'ComputerName', 'hostname', 'device_name', 'Computer',
        # Zeek
        'local_orig',
        # AWS
        'requestParameters.instanceId',
        # Generic
        'host', 'machine', 'endpoint',
    ],
    'process': [
        # Sysmon
        'Image', 'ProcessName', 'ParentImage',
        # CrowdStrike
        'FileName',
        # Generic
        'process', 'process_name', 'cmd',
    ],
    'file': [
        # Sysmon
        'TargetFilename', 'ImageLoaded',
        # CrowdStrike
        'FileName', 'FilePath',
        # Generic
        'file', 'file_path', 'file_name',
    ],
    'action': [
        # Okta
        'displayMessage', 'eventType',
        # AWS
        'eventName',
        # Windows
        'EventID', 'Keywords',
        # Generic
        'action', 'event_type', 'description', 'msg',
    ],
    'ts_iso': [
        'timestamp_utc', 'timestamp', '@timestamp', 'event_ts',
        'event_time', 'start_time', 'time', 'ts',
    ],
    'severity': [
        'severity', 'Severity', 'priority', 'risk_level',
    ],
}

# Testnet ranges that should never appear in real evidence
_TESTNET_PREFIXES = ('192.0.2.', '198.51.100.', '203.0.113.')


def _nested_get(row: dict, key: str) -> Optional[str]:
    """Get a value from a flat or dot-notation nested key."""
    if '.' in key:
        parts = key.split('.', 1)
        sub = row.get(parts[0])
        if isinstance(sub, dict):
            return _nested_get(sub, parts[1])
        return None
    val = row.get(key)
    if val is None:
        return None
    s = str(val).strip()
    return s if s and s not in ('-', 'N/A', 'n/a', 'null', 'None') else None


def normalise_row(row: dict) -> dict:
    """Normalise a single evidence row into canonical fields.

    Original fields are preserved under 'raw'. Canonical fields are added
    at the top level. Testnet IPs are blanked.
    """
    canonical: dict[str, Optional[str]] = {}
    for field, candidates in _CANONICAL_FIELD_CANDIDATES.items():
        for candidate in candidates:
            val = _nested_get(row, candidate)
            if val:
                canonical[field] = val
                break
        else:
            canonical[field] = None

    # Blank testnet IPs
    for ip_field in ('ip', 'ip_dst'):
        v = canonical.get(ip_field)
        if v and any(v.startswith(p) for p in _TESTNET_PREFIXES):
            canonical[ip_field] = None

    # Source telemetry type from the row's _source or sheet field
    source = str(row.get('_source') or row.get('source') or row.get('sheet') or 'unknown')
    return {
        **canonical,
        'row_index': row.get('row_index'),
        'source': source,
        'raw': row,
    }


def detect_schema_type(row: dict) -> str:
    """Detect the telemetry schema type from a raw row."""
    keys = set(row.keys())
    source = str(row.get('_source') or row.get('source') or '').lower()

    if 'id.orig_h' in keys or 'id_orig_h' in keys or 'zeek' in source:
        return 'zeek'
    if 'actor.login' in keys or 'actor_login' in keys or 'okta' in source:
        return 'okta'
    if 'Image' in keys or 'TargetFilename' in keys or 'sysmon' in source:
        return 'sysmon'
    if 'ComputerName' in keys and 'EventID' in keys:
        return 'windows_security'
    if 'eventName' in keys and 'sourceIPAddress' in keys:
        return 'cloudtrail'
    if 'UserName' in keys and 'ComputerName' in keys:
        return 'crowdstrike'
    if 'guardduty' in source or 'finding_type' in keys:
        return 'guardduty'
    return 'generic'


class CrossSourceStitcher:
    """Group normalised evidence rows into cross-source correlated events.

    Two rows are grouped into the same 'stitch' when they share:
      - The same user AND (ip OR host), OR
      - The same ip AND host AND the same 2-minute time window, OR
      - The same user AND the same 5-minute time window with different sources

    Stitches that span >1 source are the high-value findings — they show the
    same real-world action appearing in multiple independent telemetry streams.
    """

    def __init__(self, time_window_seconds: int = 300):
        self.time_window_seconds = time_window_seconds

    def stitch(self, rows: list[dict]) -> list[dict]:
        """Normalise and stitch rows. Returns list of stitch groups."""
        normalised = [normalise_row(r) for r in rows]
        groups: list[list[dict]] = []
        assigned: set[int] = set()

        for i, row_i in enumerate(normalised):
            if i in assigned:
                continue
            group = [row_i]
            assigned.add(i)
            for j, row_j in enumerate(normalised):
                if j <= i or j in assigned:
                    continue
                if self._rows_match(row_i, row_j):
                    group.append(row_j)
                    assigned.add(j)
            groups.append(group)

        # Build stitch summary for each group
        stitches = []
        for g in groups:
            sources = list({r['source'] for r in g if r['source'] != 'unknown'})
            users = list({r['user'] for r in g if r.get('user')})
            ips = list({r['ip'] for r in g if r.get('ip')})
            hosts = list({r['host'] for r in g if r.get('host')})
            indices = [r['row_index'] for r in g if r.get('row_index') is not None]
            cross_source = len(sources) > 1

            stitches.append({
                'row_indices': indices,
                'sources': sources,
                'source_count': len(sources),
                'cross_source': cross_source,
                'users': users,
                'ips': ips,
                'hosts': hosts,
                'actions': [r.get('action', '') for r in g if r.get('action')][:5],
                'timestamps': sorted(r.get('ts_iso', '') for r in g if r.get('ts_iso'))[:2],
                'rows': g,
            })

        # Sort: cross-source groups first, then by row count descending
        stitches.sort(key=lambda s: (-int(s['cross_source']), -len(s['row_indices'])))
        return stitches

    def _rows_match(self, a: dict, b: dict) -> bool:
        """Return True if two normalised rows describe the same real-world event."""
        # Same user + same IP → strong match
        if a.get('user') and a['user'] == b.get('user'):
            if a.get('ip') and a['ip'] == b.get('ip'):
                return True
            if a.get('host') and a['host'] == b.get('host'):
                return True
            # Same user, different source, close in time
            if a.get('source') != b.get('source'):
                if self._within_window(a.get('ts_iso'), b.get('ts_iso')):
                    return True

        # Same IP + same host → likely same machine, different log
        if a.get('ip') and a['ip'] == b.get('ip'):
            if a.get('host') and a['host'] == b.get('host'):
                return True
            # Same IP, different source, within tight window
            if a.get('source') != b.get('source'):
                if self._within_window(a.get('ts_iso'), b.get('ts_iso'), 120):
                    return True

        return False

    def _within_window(
        self,
        ts_a: Optional[str],
        ts_b: Optional[str],
        window: Optional[int] = None,
    ) -> bool:
        """Return True if two ISO timestamps are within the time window."""
        if not ts_a or not ts_b:
            return False
        try:
            from datetime import datetime, timezone
            fmt = '%Y-%m-%dT%H:%M:%S'
            # Normalise: strip milliseconds + Z
            def _parse(s: str):
                s = re.sub(r'\.\d+', '', s).rstrip('Z').strip()
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            delta = abs((_parse(ts_a) - _parse(ts_b)).total_seconds())
            return delta <= (window or self.time_window_seconds)
        except Exception:
            return False


def stitch_cluster_evidence(
    cluster: dict,
    assessment: dict,
    time_window_seconds: int = 300,
) -> list[dict]:
    """Convenience: stitch all evidence rows for a single cluster."""
    row_refs = cluster.get('row_refs') or []
    all_rows = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows')
        or []
    )
    row_map = {r.get('row_index', i): r for i, r in enumerate(all_rows)}
    cluster_rows = [row_map[ref] for ref in row_refs if ref in row_map]
    return CrossSourceStitcher(time_window_seconds).stitch(cluster_rows)
