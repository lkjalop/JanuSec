"""Tier-1 prefill orchestrator — LLM orchestration and public entry points."""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

# ── NamedTuple for kill-chain phase events ────────────────────────────────────

class PhaseEvent(NamedTuple):
    """Structured kill-chain phase event extracted from a single row."""
    phase: str
    row_index: int
    timestamp: str
    country: str   # empty string when unavailable
    asn: str       # empty string when unavailable


# ── Row utility helpers ───────────────────────────────────────────────────────

def _row_time(row: dict) -> str:
    for key in (
        'timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time',
        'start_time', 'end_time', 'published', 'created', 'time', 'ts',
    ):
        value = row.get(key)
        if value not in (None, ''):
            return str(value)
    return ''


def _row_geo_asn(row: dict) -> tuple[str, str]:
    geo = row.get('_geo') if isinstance(row.get('_geo'), dict) else {}
    country = (
        row.get('geo_dst_country') or row.get('dst_country') or row.get('destination_country')
        or row.get('country') or row.get('geo_country') or row.get('geo_src_country')
        or row.get('src_country') or geo.get('dst_country') or geo.get('country') or geo.get('src_country') or ''
    )
    asn = (
        row.get('geo_dst_asn') or row.get('destination_asn') or row.get('dst_asn')
        or row.get('asn') or row.get('source_asn') or row.get('src_asn') or row.get('geo_src_asn')
        or geo.get('dst_asn') or geo.get('asn') or geo.get('src_asn') or ''
    )
    return str(country or ''), str(asn or '')


# ── Attack sequence detection ─────────────────────────────────────────────────

def _detect_attack_sequence(rows: list[dict]) -> str:
    """Map cluster rows to kill-chain phases and return a sequence summary for the LLM.

    Sorts rows by timestamp, maps each to a phase, collapses consecutive duplicates,
    and pattern-matches against known multi-stage attack signatures.
    """
    if not rows:
        return ''

    def _phase(row: dict) -> str | None:
        src = str(row.get('_source') or row.get('source') or '').lower()
        event = str(
            row.get('event_simpleName') or row.get('eventName') or
            row.get('activityDisplayName') or row.get('event_type') or
            row.get('operationName') or row.get('query_type') or
            row.get('query_text') or row.get('CommandLine') or
            row.get('command_line') or row.get('process') or ''
        ).lower()
        result = str(row.get('outcome_result') or row.get('result') or '').lower()
        disposition = str(row.get('disposition') or row.get('action') or '').lower()
        mitre = str(row.get('mitre_technique') or '').lower()

        # Exfiltration
        try:
            bytes_out = float(row.get('orig_bytes') or row.get('bytes_sent') or row.get('bytes') or 0)
        except Exception:
            bytes_out = 0.0
        if bytes_out > 10_000_000:
            return 'exfiltration'
        if any(t in event for t in ('copy into', 'external stage', 'unload', 'upload', 'exfil', 'mega.nz', 'backblaze', 'rclone')):
            return 'exfiltration'
        if 't1041' in mitre or 't1567' in mitre:
            return 'exfiltration'

        # Lateral movement
        if any(t in event for t in ('rdp', 'smb', 'psexec', 'wmiexec', 'lateral', 'remote service')):
            return 'lateral_movement'
        if 't1021' in mitre or 't1570' in mitre:
            return 'lateral_movement'

        # Credential access
        if any(t in event for t in ('lsass', 'mimikatz', 'ntds', 'credential dump', 'password spray', 'brute')):
            return 'credential_access'
        if 't1003' in mitre or 't1110' in mitre or 't1621' in mitre:
            return 'credential_access'
        if result in ('fail', 'failure', 'locked', 'invalid_credentials') and any(
            s in src for s in ('okta', 'entra', 'm365')
        ):
            return 'credential_access'

        # Execution
        if any(t in event for t in ('processrun', 'processcreate', 'processrollup', 'execute', 'powershell', 'cmd.exe', 'wscript', 'rclone')):
            return 'execution'
        if 't1059' in mitre:
            return 'execution'

        # Persistence
        if any(t in event for t in ('scheduled task', 'autorun', 'startup', 'service install', 'registry write')):
            return 'persistence'
        if 't1547' in mitre or 't1053' in mitre:
            return 'persistence'

        # Collection / discovery
        if any(t in event for t in ('fileaccessed', 'fileread', 'listitems', 'searchquery', 'enum', 'recon')):
            return 'collection'
        if 't1083' in mitre or 't1135' in mitre or 't1114' in mitre:
            return 'collection'

        # C2 / network beaconing
        if any(t in event for t in ('beacon', 'dns tunnel', 'anomalous')) or row.get('ja3') or row.get('ja4'):
            return 'c2'
        if 't1071' in mitre:
            return 'c2'

        # Initial access / delivery
        if 'email' in src or any(t in event for t in ('phish', 'url click', 'attachment open')):
            return 'blocked_delivery' if disposition in ('block', 'blocked', 'quarantine') else 'initial_access'
        if any(s in src for s in ('okta', 'entra', 'm365')) and result in ('success', 'allow', 'allowed'):
            return 'initial_access'

        return None

    def _ts_key(row: dict) -> str:
        for k in (
            'timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time',
            'start_time', 'end_time', 'published', 'created', 'time', 'ts',
        ):
            v = row.get(k)
            if v:
                return str(v)
        try:
            return f'{int(row.get("row_index") or 0):010d}'
        except Exception:
            return ''

    sorted_rows = sorted(rows, key=_ts_key)
    phases: list[str] = []
    events: list[PhaseEvent] = []
    for row in sorted_rows[:100]:
        p = _phase(row)
        if p:
            ts = _ts_key(row)
            try:
                ridx = int(row.get('row_index') or 0)
            except Exception:
                ridx = 0
            country, asn = _row_geo_asn(row)
            events.append(PhaseEvent(phase=p, row_index=ridx, timestamp=ts, country=country, asn=asn))
            if not phases or phases[-1] != p:
                phases.append(p)

    if not phases:
        return ''

    unique = list(dict.fromkeys(phases))
    phase_set = set(phases)
    pattern = ''
    if {'initial_access', 'credential_access', 'collection', 'exfiltration'}.issubset(phase_set):
        pattern = '⚠ FULL KILL CHAIN'
    elif {'credential_access', 'lateral_movement', 'exfiltration'}.issubset(phase_set):
        pattern = '⚠ CREDENTIAL → LATERAL → EXFIL'
    elif {'initial_access', 'credential_access', 'lateral_movement'}.issubset(phase_set):
        pattern = '⚠ MULTI-STAGE INTRUSION'
    elif 'exfiltration' in phase_set and len(phase_set) >= 3:
        pattern = '⚠ EXFILTRATION WITH PRECURSORS'
    elif {'credential_access', 'collection'}.issubset(phase_set):
        pattern = '⚠ CREDENTIAL ACCESS + COLLECTION'
    elif 'c2' in phase_set and 'initial_access' in phase_set:
        pattern = '⚠ ACCESS + C2 BEACONING'

    seq_str = ' → '.join(unique)
    out = f"{len(unique)} distinct phase(s): {seq_str} ({len(phases)} phase-transitions observed)"
    if pattern:
        out += f"\nPattern: {pattern}"
    return out


def _detect_attack_sequence_events(rows: list[dict]) -> list[PhaseEvent]:
    """Return the full ordered list of PhaseEvent objects for geo/ASN analysis.

    Builds a PhaseEvent per row that maps to a known kill-chain phase.
    Suitable for passing to _geo_sequence_summary().
    """
    def _phase(row: dict) -> str | None:
        src = str(row.get('_source') or row.get('source') or '').lower()
        event = str(
            row.get('event_simpleName') or row.get('eventName') or
            row.get('activityDisplayName') or row.get('event_type') or
            row.get('operationName') or row.get('query_type') or
            row.get('query_text') or row.get('CommandLine') or
            row.get('command_line') or row.get('process') or ''
        ).lower()
        result = str(row.get('outcome_result') or row.get('result') or '').lower()
        disposition = str(row.get('disposition') or row.get('action') or '').lower()
        mitre = str(row.get('mitre_technique') or '').lower()
        try:
            bytes_out = float(row.get('orig_bytes') or row.get('bytes_sent') or row.get('bytes') or 0)
        except Exception:
            bytes_out = 0.0
        if bytes_out > 10_000_000:
            return 'exfiltration'
        if any(t in event for t in ('copy into', 'external stage', 'unload', 'upload', 'exfil', 'mega.nz', 'backblaze', 'rclone')):
            return 'exfiltration'
        if 't1041' in mitre or 't1567' in mitre:
            return 'exfiltration'
        if any(t in event for t in ('rdp', 'smb', 'psexec', 'wmiexec', 'lateral', 'remote service')):
            return 'lateral_movement'
        if 't1021' in mitre or 't1570' in mitre:
            return 'lateral_movement'
        if any(t in event for t in ('lsass', 'mimikatz', 'ntds', 'credential dump', 'password spray', 'brute')):
            return 'credential_access'
        if 't1003' in mitre or 't1110' in mitre or 't1621' in mitre:
            return 'credential_access'
        if result in ('fail', 'failure', 'locked', 'invalid_credentials') and any(
            s in src for s in ('okta', 'entra', 'm365')
        ):
            return 'credential_access'
        if any(t in event for t in ('processrun', 'processcreate', 'processrollup', 'execute', 'powershell', 'cmd.exe', 'wscript', 'rclone')):
            return 'execution'
        if 't1059' in mitre:
            return 'execution'
        if any(t in event for t in ('scheduled task', 'autorun', 'startup', 'service install', 'registry write')):
            return 'persistence'
        if 't1547' in mitre or 't1053' in mitre:
            return 'persistence'
        if any(t in event for t in ('fileaccessed', 'fileread', 'listitems', 'searchquery', 'enum', 'recon')):
            return 'collection'
        if 't1083' in mitre or 't1135' in mitre or 't1114' in mitre:
            return 'collection'
        if any(t in event for t in ('beacon', 'dns tunnel', 'anomalous')) or row.get('ja3') or row.get('ja4'):
            return 'c2'
        if 't1071' in mitre:
            return 'c2'
        if 'email' in src or any(t in event for t in ('phish', 'url click', 'attachment open')):
            return 'blocked_delivery' if disposition in ('block', 'blocked', 'quarantine') else 'initial_access'
        if any(s in src for s in ('okta', 'entra', 'm365')) and result in ('success', 'allow', 'allowed'):
            return 'initial_access'
        return None

    def _ts_key(row: dict) -> str:
        for k in ('timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time',
                  'start_time', 'end_time', 'published', 'created', 'time', 'ts'):
            v = row.get(k)
            if v:
                return str(v)
        try:
            return f'{int(row.get("row_index") or 0):010d}'
        except Exception:
            return ''

    out: list[PhaseEvent] = []
    for row in sorted(rows, key=_ts_key)[:100]:
        p = _phase(row)
        if p:
            ts = _ts_key(row)
            try:
                ridx = int(row.get('row_index') or 0)
            except Exception:
                ridx = 0
            country, asn = _row_geo_asn(row)
            out.append(PhaseEvent(phase=p, row_index=ridx, timestamp=ts, country=country, asn=asn))
    return out


def _geo_sequence_summary(events: list[PhaseEvent]) -> str:
    """Derive geo/ASN sequence notes from PhaseEvent list for the render prompt.

    Flags:
    - ASN reuse across multiple kill-chain phases (adversarial infrastructure)
    - Multi-country transitions (VPN/proxy chaining or distributed actor)

    Returns an empty string when events lack geo data or nothing is notable.
    """
    if not events:
        return ''

    asn_phases: dict[str, set[str]] = {}
    countries: list[str] = []
    for ev in events:
        if ev.asn:
            asn_phases.setdefault(ev.asn, set()).add(ev.phase)
        if ev.country:
            if not countries or countries[-1] != ev.country:
                countries.append(ev.country)

    notes: list[str] = []

    # ASN reuse: same ASN seen across 2+ distinct phases → adversarial infra
    for asn, phases_set in asn_phases.items():
        if len(phases_set) >= 2:
            notes.append(
                f'ASN {asn} reused across {len(phases_set)} kill-chain phases '
                f'({", ".join(sorted(phases_set))}) — consistent adversarial infrastructure.'
            )

    # Country transitions: 2+ distinct countries in temporal order
    distinct = list(dict.fromkeys(countries))
    if len(distinct) >= 2:
        notes.append(
            f'Source country transitions: {" → ".join(distinct)} — '
            f'possible VPN/proxy chaining or multi-country actor.'
        )

    return ' '.join(notes)


# ── Privilege / sensitive data signals ───────────────────────────────────────

# Privilege-level keywords — elevate DREAD damage + affected_users scores
_PRIV_SIGNALS = (
    'admin', 'root', 'administrator', 'domain admin', 'global admin',
    'privileged', 'superuser', 'sudo', 'sysadmin', 'service account',
    'svc_', 'arn:aws:iam', 'sts:assumerole', 'assumerolewithsaml',
    'globaladministrator', 'owner', 'contributor',
)

# Sensitive data type signals — escalate DREAD damage
_SENSITIVE_DATA_SIGNALS = (
    'password', 'credential', 'secret', 'token', 'key', 'pii', 'ssn',
    'credit card', 'cardholder', 'phi', 'health', 'salary', 'financial',
    'customer', 'patient', 'manifest', 'shipping', 'invoice', 'vault',
    'restricted', 'confidential', 'classified',
)


# ── DREAD numeric score ───────────────────────────────────────────────────────

def _compute_dread_score(cluster: dict, rows: list[dict]) -> dict:
    """Compute numeric DREAD scores (0-10 per dimension).

    D — Damage: phase count × source count, boosted by privilege level and sensitive data type
    R — Reproducibility: public tooling used? higher = easier to repeat
    E — Exploitability: how easy was initial access?
    A — Affected Users: count of distinct users, boosted by privilege level
    D — Discoverability: was a detection event present (silent = low, blocked = high)?
    """
    phases = cluster.get('phases') or []
    sources = cluster.get('sources') or []
    phase_ids = {p.get('phase_id') or p.get('case_role') or '' for p in phases}
    row_text_all = ' '.join(
        ' '.join(str(v) for v in r.values() if isinstance(v, str))
        for r in rows
    ).lower()

    # Privilege level scan
    has_privilege = any(sig in row_text_all for sig in _PRIV_SIGNALS)

    # Sensitive data type scan
    has_sensitive_data = any(sig in row_text_all for sig in _SENSITIVE_DATA_SIGNALS)

    # D — Damage (0-10)
    base_damage = min(10, len(phases) * 2 + len(set(sources)))
    if has_privilege:
        base_damage = min(10, base_damage + 2)
    if has_sensitive_data:
        base_damage = min(10, base_damage + 1)
    # Exfil phase = max damage
    if any(p in phase_ids for p in ('data_exfiltration', 'data_exfiltration_snowflake', 'data_exfiltration_rclone')):
        base_damage = max(base_damage, 8)

    # Identify damage type for CEO description
    damage_types: list[str] = []
    if has_sensitive_data:
        for sig, label in [('customer', 'customer data'), ('credential', 'credentials'),
                            ('financial', 'financial records'), ('health', 'health records'),
                            ('vault', 'secrets vault'), ('manifest', 'shipping manifests')]:
            if sig in row_text_all:
                damage_types.append(label)
    if not damage_types:
        damage_types = ['corporate data']

    # R — Reproducibility (0-10): public commodity tools = high
    repro = 3  # baseline
    repro_tools: list[str] = []
    for tool, score, label in [
        ('rclone', 3, 'Rclone'), ('certutil', 2, 'certutil'), ('mimikatz', 3, 'Mimikatz'),
        ('psexec', 2, 'PsExec'), ('cobalt', 3, 'Cobalt Strike'), ('mshta', 2, 'mshta'),
        ('nuclei', 2, 'Nuclei'), ('nmap', 1, 'nmap'), ('sqlmap', 2, 'SQLMap'),
    ]:
        if tool in row_text_all:
            repro = min(10, repro + score)
            repro_tools.append(label)

    # Standard cloud API abuse (no special tooling needed)
    if any(p in phase_ids for p in ('secret_access', 'data_exfiltration_snowflake')):
        repro = min(10, repro + 2)
        repro_tools.append('standard cloud CLI')

    # E — Exploitability (0-10): how easy was initial access?
    exploit = 5  # baseline
    exploit_vector = 'unknown initial access vector'
    if 'session_theft' in phase_ids:
        exploit = 7
        exploit_vector = 'stolen session token (phishing or token replay)'
    elif 'initial_access' in phase_ids:
        exploit = 6
        exploit_vector = 'phishing or credential spray'
    if 'credential_theft' in phase_ids:
        exploit = min(10, exploit + 1)
    if 'privilege_escalation_k8s' in phase_ids:
        exploit = min(10, exploit + 2)
        exploit_vector += ' → container escape'

    # A — Affected Users (0-10): distinct user count + privilege multiplier
    distinct_users = len({
        str(r.get('user_canonical') or r.get('user') or '').strip().lower()
        for r in rows
        if r.get('user_canonical') or r.get('user')
    } - {'', '-', 'n/a', 'system', 'root'})
    affected = min(8, distinct_users + 1)
    privilege_note = ''
    if has_privilege:
        affected = min(10, affected + 3)
        privilege_note = 'privileged/admin accounts involved — blast radius significantly larger'
    elif distinct_users == 0:
        affected = 1

    # D — Discoverability (0-10): detection events present?
    discov = 3  # baseline: not trivially discoverable
    discov_note = 'no active detection event'
    if any(str(r.get('disposition') or r.get('action') or '').lower() in
           ('blocked', 'quarantined', 'prevented', 'alert') for r in rows):
        discov = 7
        discov_note = 'endpoint/network detection event present'
    if any('crowdstrike' in str(r.get('_source') or '').lower() and
           str(r.get('severity') or '').lower() in ('critical', 'high') for r in rows):
        discov = max(discov, 8)
        discov_note = 'CrowdStrike high/critical detection fired'
    # Silent for >7 days before IR = low discoverability
    ts_vals = [float(r['_ts_epoch']) for r in rows if r.get('_ts_epoch')]
    if len(ts_vals) >= 2:
        span_days = (max(ts_vals) - min(ts_vals)) / 86400
        if span_days > 7 and discov < 5:
            discov = max(2, discov - 1)
            discov_note = f'activity ran {span_days:.0f} days undetected'

    total = base_damage + repro + exploit + affected + discov
    if total >= 40:
        risk_tier = 'CRITICAL'
    elif total >= 30:
        risk_tier = 'HIGH'
    elif total >= 20:
        risk_tier = 'MEDIUM'
    else:
        risk_tier = 'LOW'

    return {
        'damage':         base_damage,
        'damage_detail':  f"Affected: {', '.join(damage_types[:3])}. {'Privileged access involved.' if has_privilege else ''}".strip(),
        'reproducibility': repro,
        'reproducibility_detail': f"Tools used: {', '.join(repro_tools) or 'standard TTPs'}. Widely available.",
        'exploitability': exploit,
        'exploitability_detail': exploit_vector.capitalize() + '.',
        'affected_users': affected,
        'affected_users_detail': privilege_note or f'{distinct_users} distinct account(s) involved.',
        'discoverability': discov,
        'discoverability_detail': discov_note.capitalize() + '.',
        'total': total,
        'max': 50,
        'risk_tier': risk_tier,
    }


# ── Geo helpers ───────────────────────────────────────────────────────────────

# Approximate great-circle distances (km) between country centroids.
_COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    'AU': (-25.3, 133.8), 'NZ': (-40.9, 174.9),
    'SG': (1.4, 103.8),   'JP': (36.2, 138.3),   'KR': (35.9, 127.8),
    'CN': (35.9, 104.2),  'IN': (20.6, 78.9),     'HK': (22.3, 114.2),
    'MY': (4.2, 101.9),   'TH': (15.9, 100.9),    'ID': (-2.5, 118.0),
    'PH': (12.9, 121.8),  'VN': (14.1, 108.3),
    'US': (38.9, -77.0),  'CA': (56.1, -106.3),   'MX': (23.6, -102.5),
    'GB': (55.4, -3.4),   'DE': (51.2, 10.5),      'FR': (46.2, 2.2),
    'NL': (52.1, 5.3),    'SE': (60.1, 18.6),      'NO': (60.5, 8.5),
    'RU': (61.5, 105.3),  'UA': (48.4, 31.2),      'PL': (51.9, 19.1),
    'BR': (-14.2, -51.9), 'AR': (-38.4, -63.6),
    'ZA': (-28.5, 24.7),  'NG': (9.1, 8.7),
    'AE': (23.4, 53.8),   'SA': (23.9, 45.1),      'IL': (31.0, 34.9),
}

_COUNTRY_NAMES: dict[str, str] = {
    'AU': 'Australia',   'NZ': 'New Zealand',
    'SG': 'Singapore',   'JP': 'Japan',         'KR': 'South Korea',
    'CN': 'China',       'IN': 'India',          'HK': 'Hong Kong',
    'MY': 'Malaysia',    'TH': 'Thailand',       'ID': 'Indonesia',
    'PH': 'Philippines', 'VN': 'Vietnam',        'TW': 'Taiwan',
    'US': 'United States', 'CA': 'Canada',       'MX': 'Mexico',
    'GB': 'United Kingdom', 'DE': 'Germany',     'FR': 'France',
    'NL': 'Netherlands', 'SE': 'Sweden',         'NO': 'Norway',
    'FI': 'Finland',     'DK': 'Denmark',        'CH': 'Switzerland',
    'AT': 'Austria',     'BE': 'Belgium',        'IT': 'Italy',
    'ES': 'Spain',       'PT': 'Portugal',       'PL': 'Poland',
    'RU': 'Russia',      'UA': 'Ukraine',        'RO': 'Romania',
    'CZ': 'Czech Republic', 'HU': 'Hungary',     'SK': 'Slovakia',
    'BR': 'Brazil',      'AR': 'Argentina',      'CO': 'Colombia',
    'CL': 'Chile',       'PE': 'Peru',
    'ZA': 'South Africa','NG': 'Nigeria',        'KE': 'Kenya',
    'EG': 'Egypt',       'MA': 'Morocco',
    'AE': 'UAE',         'SA': 'Saudi Arabia',   'IL': 'Israel',
    'TR': 'Turkey',      'IR': 'Iran',           'PK': 'Pakistan',
    'BD': 'Bangladesh',
}


def _format_geo_location(ip: str, city: str, country: str, country_code: str, asn_org: str) -> str:
    from .evidence_binder import _field_text
    cc = (country_code or '').upper()
    country_full = _COUNTRY_NAMES.get(cc) or country or cc or 'Unknown'
    city_part = city.strip() if city else ''
    location = f"{city_part}, {country_full}" if city_part else country_full

    detail_parts = [p for p in [ip, asn_org, cc] if p]
    detail = ' · '.join(detail_parts)
    return f"{location} ({detail})" if detail else location


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _extract_geo_from_row(row: dict) -> dict:
    """Pull geo context from whatever the event already carries."""
    geo: dict = {}

    # Okta: event.context.geographicalContext
    ctx = row.get('context') or row.get('event_context') or {}
    if isinstance(ctx, dict):
        geo_ctx = ctx.get('geographicalContext') or ctx.get('geo') or {}
        if isinstance(geo_ctx, dict):
            if geo_ctx.get('country'):
                geo['country'] = str(geo_ctx['country']).strip()
            if geo_ctx.get('city'):
                geo['city'] = str(geo_ctx['city']).strip()
            if geo_ctx.get('countryCode') or geo_ctx.get('country_code'):
                geo['country_code'] = str(geo_ctx.get('countryCode') or geo_ctx.get('country_code')).strip().upper()
            if geo_ctx.get('geolocation'):
                loc = geo_ctx['geolocation']
                if isinstance(loc, dict):
                    try:
                        geo['lat'] = float(loc.get('lat', 0))
                        geo['lon'] = float(loc.get('lon', 0))
                    except Exception:
                        pass

    # Okta: context.ipChain[0].geographicalContext
    ip_chain = ctx.get('ipChain') or []
    if isinstance(ip_chain, list) and ip_chain and isinstance(ip_chain[0], dict):
        chain_geo = ip_chain[0].get('geographicalContext') or {}
        if isinstance(chain_geo, dict) and not geo.get('country'):
            if chain_geo.get('country'):
                geo['country'] = str(chain_geo['country']).strip()
            if chain_geo.get('city'):
                geo['city'] = str(chain_geo['city']).strip()

    # Generic field scan
    for field in ('geo_country', 'country_name', 'country', 'geoip_country_name', 'geo_location_country'):
        val = row.get(field)
        if val and isinstance(val, str) and len(val) > 1 and not geo.get('country'):
            geo['country'] = val.strip()
            break
    for field in ('country_code', 'geo_country_code', 'geoip_country_code', 'countryCode'):
        val = row.get(field)
        if val and isinstance(val, str) and 2 <= len(val) <= 3 and not geo.get('country_code'):
            geo['country_code'] = val.strip().upper()
            break
    for field in ('geo_city', 'city', 'geoip_city_name'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('city'):
            geo['city'] = val.strip()
            break
    for field in ('asn', 'as_number', 'asn_number', 'geo_asn', 'autonomous_system_number'):
        val = row.get(field)
        if val is not None and not geo.get('asn'):
            geo['asn'] = str(val).strip()
            break
    for field in ('as_org', 'asn_org', 'asn_organization', 'isp', 'geo_isp', 'autonomous_system_organization'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('asn_org'):
            geo['asn_org'] = val.strip()
            break

    # Source IP
    for field in ('source_ip', 'src_ip', 'client_ip', 'ClientIP', 'remote_address', 'sourceIPAddress', 'ip_address'):
        val = row.get(field)
        if val and isinstance(val, str) and not geo.get('ip'):
            geo['ip'] = val.strip()
            break

    # If we have a country_code but no lat/lon, look up centroid
    if not geo.get('lat') and geo.get('country_code'):
        centroid = _COUNTRY_CENTROIDS.get(geo['country_code'].upper())
        if centroid:
            geo['lat'], geo['lon'] = centroid

    return geo


def _detect_impossible_travel(rows: list[dict]) -> list[dict]:
    """Per-user impossible travel analysis across all rows."""
    import math
    from datetime import datetime, timezone

    def _parse_ts(row: dict):
        for f in (
            'timestamp_utc', 'timestamp', '@timestamp', 'ts', 'event_ts',
            'event_time', 'start_time', 'end_time', 'time', 'published', 'created',
        ):
            v = row.get(f)
            if not v:
                continue
            try:
                s = str(v).replace('Z', '+00:00')
                return datetime.fromisoformat(s)
            except Exception:
                pass
        return None

    def _user_key(row: dict) -> str:
        for f in ('user_principal_name', 'userPrincipalName', 'username', 'user_name',
                  'actor', 'user', 'initiator', 'email'):
            v = row.get(f)
            if v and isinstance(v, str) and '@' in v or (v and isinstance(v, str) and len(v) > 2):
                return str(v).lower().strip()
            if isinstance(v, dict):
                inner = v.get('alternateId') or v.get('login') or v.get('id') or ''
                if inner:
                    return str(inner).lower().strip()
        return ''

    # Group login events by user
    user_events: dict[str, list[dict]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        user = _user_key(row)
        if not user:
            continue
        geo = row.get('_geo') or _extract_geo_from_row(row)
        if not geo.get('country') and not geo.get('country_code'):
            continue  # no geo signal — skip
        ts = _parse_ts(row)
        if not ts:
            continue
        row['_geo'] = geo
        row['_parsed_ts'] = ts
        user_events.setdefault(user, []).append(row)

    flags: list[dict] = []
    for user, events in user_events.items():
        events_sorted = sorted(events, key=lambda r: r['_parsed_ts'])
        for i in range(len(events_sorted) - 1):
            e1, e2 = events_sorted[i], events_sorted[i + 1]
            g1, g2 = e1.get('_geo', {}), e2.get('_geo', {})
            cc1 = (g1.get('country_code') or '').upper()
            cc2 = (g2.get('country_code') or '').upper()
            c1 = g1.get('country', cc1)
            c2 = g2.get('country', cc2)
            if not c1 or not c2 or c1 == c2:
                continue

            # Time delta
            dt = (e2['_parsed_ts'] - e1['_parsed_ts']).total_seconds()
            if dt <= 0:
                verdict = 'CONCURRENT_IMPOSSIBLE'
                km, km_hr = 0.0, float('inf')
            else:
                hours = dt / 3600.0
                lat1, lon1 = g1.get('lat', 0.0), g1.get('lon', 0.0)
                lat2, lon2 = g2.get('lat', 0.0), g2.get('lon', 0.0)
                if lat1 and lat2:
                    km = _haversine_km(lat1, lon1, lat2, lon2)
                    km_hr = km / hours if hours > 0 else float('inf')
                else:
                    km, km_hr = -1.0, -1.0

                if km_hr == float('inf') or km_hr > 900:
                    verdict = 'IMPOSSIBLE'
                elif km_hr > 400:
                    verdict = 'SUSPICIOUS'
                else:
                    verdict = 'PLAUSIBLE_TRAVEL'

            from_city = g1.get('city', '')
            to_city = g2.get('city', '')
            from_ip = g1.get('ip', '')
            to_ip = g2.get('ip', '')
            from_asn = g1.get('asn_org', '') or g1.get('asn', '')
            to_asn = g2.get('asn_org', '') or g2.get('asn', '')

            _APPROX_FLIGHT: dict[tuple[str, str], float] = {
                ('AU', 'SG'): 8, ('SG', 'AU'): 8,
                ('AU', 'GB'): 22, ('GB', 'AU'): 22,
                ('AU', 'US'): 17, ('US', 'AU'): 17,
                ('AU', 'JP'): 10, ('JP', 'AU'): 10,
                ('AU', 'NZ'): 3, ('NZ', 'AU'): 3,
                ('SG', 'GB'): 13, ('GB', 'SG'): 13,
                ('US', 'GB'): 8, ('GB', 'US'): 8,
                ('US', 'RO'): 11, ('RO', 'US'): 11,
                ('AU', 'RO'): 24, ('RO', 'AU'): 24,
            }
            flight_hrs = _APPROX_FLIGHT.get((cc1, cc2)) or _APPROX_FLIGHT.get((cc2, cc1))

            flags.append({
                'user': user,
                'from_country': c1,
                'from_country_code': cc1,
                'from_city': from_city,
                'from_ip': from_ip,
                'from_asn_org': from_asn,
                'from_ts': e1['_parsed_ts'].isoformat(),
                'to_country': c2,
                'to_country_code': cc2,
                'to_city': to_city,
                'to_ip': to_ip,
                'to_asn_org': to_asn,
                'to_ts': e2['_parsed_ts'].isoformat(),
                'hours_between': round(dt / 3600, 2) if dt > 0 else 0,
                'km': round(km, 0) if km >= 0 else None,
                'km_hr': round(km_hr, 0) if 0 <= km_hr < 10000 else None,
                'verdict': verdict,
                'min_flight_hours': flight_hrs,
                'row_index_from': e1.get('row_index', e1.get('row_number')),
                'row_index_to': e2.get('row_index', e2.get('row_number')),
                'from_label': _format_geo_location(from_ip, from_city, c1, cc1, from_asn),
                'to_label': _format_geo_location(to_ip, to_city, c2, cc2, to_asn),
            })

    return flags


# ── Cluster intelligence enrichment ──────────────────────────────────────────

def _build_event_chain_summary(cluster: dict, rows: list[dict]) -> str:
    """Format a temporal event chain from phase anchor rows sorted by _ts_epoch."""
    from .evidence_binder import _row_action_text
    if not rows:
        return ''

    phases = cluster.get('phases') or []
    anchor_refs: set[int] = set()
    for p in phases:
        for r in (p.get('row_refs') or [])[:5]:
            try:
                anchor_refs.add(int(r))
            except (TypeError, ValueError):
                pass

    _row_by_idx: dict[int, dict] = {}
    for _r in rows:
        _ri = _r.get('row_index')
        if _ri is not None:
            try:
                _row_by_idx[int(float(_ri))] = _r
            except (TypeError, ValueError):
                pass
    row_by_idx = _row_by_idx

    if anchor_refs:
        chain_rows = [row_by_idx[i] for i in sorted(anchor_refs) if i in row_by_idx]
    else:
        chain_rows = sorted(rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)[:12]

    def _ep(r: dict) -> float:
        ep = r.get('_ts_epoch')
        if ep:
            return float(ep)
        ts = r.get('timestamp') or ''
        if ts:
            try:
                from datetime import datetime as _dt
                return _dt.fromisoformat(str(ts).replace('Z', '+00:00')).timestamp()
            except Exception:
                pass
        return 0.0

    chain_rows = sorted(chain_rows, key=_ep)
    if not chain_rows:
        return ''

    t0 = _ep(chain_rows[0])
    users = [str(r.get('user_canonical') or r.get('user') or '').strip() for r in chain_rows if r.get('user_canonical') or r.get('user')]
    actor = users[0] if users else 'unknown'
    actor_label = actor[:24].ljust(24)

    lines: list[str] = []
    for i, r in enumerate(chain_rows[:10]):
        ep = _ep(r)
        delta_s = ep - t0 if ep and t0 else 0
        if delta_s < 0:
            delta_s = 0
        if delta_s < 60:
            rel = 'T+0'
        elif delta_s < 3600:
            rel = f'T+{int(delta_s // 60)}m'
        elif delta_s < 86400:
            rel = f'T+{int(delta_s // 3600)}h'
        else:
            rel = f'T+{int(delta_s // 86400)}d'

        event = _row_action_text(r)[:60]
        src_ip = str(r.get('src_ip') or r.get('dst_ip') or '').strip()
        ip_col = f'  {src_ip}' if src_ip else ''

        prefix = actor_label if i == 0 else ' ' * len(actor_label)
        lines.append(f'{prefix} │ {rel:<7} {event}{ip_col}')

    return '\n'.join(lines)


def _enrich_cluster_intelligence(data: dict, cluster: dict, rows: list[dict]) -> None:
    """Populate deterministic structured intelligence fields on tier1_prefill."""
    from .threat_models import (
        _build_kill_chain_summary, _detect_adversarial_sequence,
        _split_entities, _compute_diamond_model, _compute_pasta_summary,
    )
    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
    phases = cluster.get('phases') or []
    is_breach = verdict in ('VALIDATED_BREACH', 'CONFIRMED_BREACH', 'LIKELY_BREACH', 'LIKELY_COMPROMISE')

    # ── 2.1 event_chain_summary ───────────────────────────────────────────────
    if not data.get('event_chain_summary') and rows:
        try:
            data['event_chain_summary'] = _build_event_chain_summary(cluster, rows)
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: event_chain_summary failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 2.2 kill_chain_summary ────────────────────────────────────────────────
    if not data.get('kill_chain_summary'):
        try:
            data['kill_chain_summary'] = _build_kill_chain_summary(phases)
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: kill_chain_summary failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 2.3 adversarial_sequence ──────────────────────────────────────────────
    if 'adversarial_sequence' not in data:
        try:
            flag, detail = _detect_adversarial_sequence(phases, rows)
            data['adversarial_sequence'] = flag
            if detail:
                data['adversarial_sequence_detail'] = detail
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: adversarial_sequence failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 2.4 known/unknown entity split ───────────────────────────────────────
    if not data.get('known_technical') and not data.get('unknown_technical'):
        try:
            known, unknown = _split_entities(cluster, rows)
            data['known_technical'] = known
            data['unknown_technical'] = unknown
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: entity_split failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 3.1 DREAD numeric score ───────────────────────────────────────────────
    if not data.get('dread_score') and rows:
        try:
            data['dread_score'] = _compute_dread_score(cluster, rows)
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: dread_score failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 3.2 Diamond model ─────────────────────────────────────────────────────
    if not data.get('diamond_model') and is_breach:
        try:
            data['diamond_model'] = _compute_diamond_model(cluster, rows)
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: diamond_model failed for %s: %s',
                         cluster.get('cluster_id'), _e)

    # ── 3.3 PASTA summary ─────────────────────────────────────────────────────
    if not data.get('pasta_summary') and is_breach:
        try:
            data['pasta_summary'] = _compute_pasta_summary(cluster, rows, data)
        except Exception as _e:
            logger.debug('_enrich_cluster_intelligence: pasta_summary failed for %s: %s',
                         cluster.get('cluster_id'), _e)


# ── v2 fallback helpers ───────────────────────────────────────────────────────

def _fallback_incident_name(cluster: dict, rows: list[dict]) -> str:
    from .evidence_binder import _field_text, _row_action_text
    parts = [
        str(cluster.get('incident_name') or ''),
        str(cluster.get('lead_description') or ''),
        str(cluster.get('reason_summary') or ''),
        str(cluster.get('business_significance') or ''),
    ]
    for row in rows[:80]:
        for key in (
            'incident_id', 'threat_actor', 'analyst_notes', 'event_type',
            'email_subject', 'email_body_summary', 'dns_query', 'sni',
            'process_name', 'event_simpleName', 'rule_name', 'rule_destination',
            'mitre_technique', 'notes', 'objectRef', 'user', 'src_ip', 'dst_ip',
            'remote_address', 'ja3', 'ja4',
        ):
            value = row.get(key)
            if value not in (None, ''):
                parts.append(_field_text(value))
    joined = ' '.join(parts).lower()
    if any(t in joined for t in ('integration-runner', 'serviceaccount:integration-tests', 'pods/exec')):
        return 'K8s Credential Exfiltration via Integration Runner'
    if any(t in joined for t in ('k8s.audit', 'kubernetes', 'pods/exec', 'daemonsets')):
        return 'KUBERNETES PRIVILEGED ACTIVITY'
    if any(t in joined for t in ('bec', 'wire transfer', 'mailbox rule', 'finance officer')):
        return 'BUSINESS EMAIL COMPROMISE'
    if any(t in joined for t in ('npm', 'postinstall', 'supply chain', 'package')):
        return 'SUPPLY CHAIN INCIDENT'
    if any(t in joined for t in ('dns tunnel', 'dns beacon', 'fast-flux')):
        return 'DNS C2 BEACON'
    if any(t in joined for t in ('c2', 'command and control', 'command-and-control', 'beacon')):
        return 'C2 BEACON'
    if any(t in joined for t in ('mfa fatigue', 'password spray', 'legacy auth', 'imap', 'okta')):
        return 'OKTA IDENTITY COMPROMISE'
    if 'exfil' in joined:
        return 'DATA EXFILTRATION'
    return 'CORRELATED INCIDENT'


def _infer_root_cause(data: dict, cluster: dict, rows: list[dict]) -> str:
    from .evidence_binder import _row_action_text
    joined = ' '.join([
        str(data.get('incident_name') or ''),
        str(data.get('headline_subtitle') or ''),
        str(data.get('short_narrative') or ''),
        ' '.join(_row_action_text(r) for r in rows[:20]),
    ]).lower()
    if any(token in joined for token in ('bec', 'wire', 'bcc', 'mailbox', 'finance officer')):
        return 'Compromised finance mailbox or identity used for business email compromise activity.'
    if any(token in joined for token in ('integration-runner', 'serviceaccount:integration-tests', 'pods/exec')):
        return 'Kubernetes service account credentials for the integration runner were used for privileged workload activity.'
    if any(token in joined for token in ('k8s.audit', 'kubernetes', 'daemonsets')):
        return 'Kubernetes over-privilege or misconfiguration allowed privileged workload activity.'
    if any(token in joined for token in ('mfa fatigue', 'push', 'legacy imap', 'session token')):
        return 'Identity compromise via MFA fatigue or legacy authentication allowed attacker access.'
    if any(token in joined for token in ('dns', 'beacon', 'c2', 'command and control')):
        return 'Endpoint or network activity indicates command-and-control beaconing that needs containment.'
    if any(token in joined for token in ('npm', 'package', 'postinstall', 'supply chain')):
        return 'A package or build dependency introduced suspicious supply-chain execution.'
    if any(token in joined for token in ('lateral', 'rdp', 'smb', 'psexec', 'wmiexec')):
        return 'Correlated host access suggests lateral movement or administrative tooling abuse.'
    if any(token in joined for token in ('rclone', 'backblaze', 'mega.nz', 'external stage', 'copy into', 'cloud storage', 's3://', 'gsutil', 'azcopy')):
        return 'Data staged or synchronised to cloud storage via tooling, consistent with exfiltration activity.'
    if any(token in joined for token in ('lsass', 'comsvcs', 'mimikatz', 'procdump', 'ntds', 'credential dump')):
        return 'Credential theft tooling or LSASS access detected on an endpoint, indicating an active hands-on-keyboard intrusion.'
    if any(token in joined for token in ('pentest', 'nmap', 'metasploit', 'cobalt strike', 'red team', 'authorized')):
        return 'Activity matches authorized penetration test or red team tooling within the engagement scope.'
    return str(cluster.get('reason_summary') or 'Correlated evidence exceeded the investigation threshold.').strip()


def _is_generic_root_cause(value: Any) -> bool:
    text = str(value or '').strip().lower()
    if not text:
        return True
    generic_markers = (
        'correlated evidence exceeded the investigation threshold',
        'correlated evidence exceeds the investigation threshold',
        'containment scope depends on the correlated evidence rows',
        'correlated evidence requires further analyst investigation',
    )
    return any(marker in text for marker in generic_markers)


def _row_business_significance(row: dict, technique: str = '') -> str:
    """Return a plain-English sentence explaining why this row matters to the business."""
    src = str(row.get('_source') or row.get('source') or row.get('log_source') or '').lower()
    action_raw = str(row.get('event_type') or row.get('event_action') or row.get('action') or
                     row.get('operation') or row.get('query_type') or '').lower()
    joined = ' '.join(str(v) for v in row.values() if isinstance(v, str)).lower()

    # Cloud-sync / exfiltration tools
    if any(t in joined for t in ('rclone', 'backblaze', 'mega.nz', 'azcopy', 'gsutil', 'aws s3 cp')):
        dest = 'a cloud storage destination'
        for marker, label in [('backblaze', 'Backblaze B2'), ('mega.nz', 'MEGA.nz'),
                               ('aws s3', 'Amazon S3'), ('gsutil', 'Google Cloud Storage'),
                               ('azcopy', 'Azure Blob Storage')]:
            if marker in joined:
                dest = label
                break
        return (f"A file-sync tool was used to copy data to {dest}. "
                "This is a hallmark of deliberate data exfiltration — data has left the organisation.")

    # Bulk DB export
    if any(t in action_raw for t in ('unload', 'copy', 'export')) or \
       any(t in joined for t in ('copy into', 'select *', 'rows_produced')):
        rows_out = row.get('rows_produced') or row.get('rows_exported') or ''
        suffix = f" ({rows_out} records)" if rows_out else ''
        return (f"A bulk database export was executed{suffix}. "
                "Exporting large volumes of records is a data theft indicator requiring immediate review.")

    # Email / BEC
    if any(t in joined for t in ('bcc', 'forward', 'mail', 'inbox rule', 'imap')) or 'email' in src:
        return ("Mailbox activity was observed on a privileged account. "
                "Attackers frequently configure forwarding rules to silently intercept email, "
                "including financial approvals and credential resets.")

    # Network beacon / C2
    if any(t in joined for t in ('beacon', 'c2', 'cobalt', 'metasploit', 'empire')) or \
       any(t in src for t in ('network', 'firewall', 'ids', 'proxy')):
        dst = row.get('dst_ip') or row.get('destination') or ''
        suffix = f" to {dst}" if dst else ''
        return (f"A network connection{suffix} was logged that matches command-and-control communication patterns. "
                "This indicates an attacker maintaining persistent remote access inside the environment.")

    # Authentication / credential
    if any(t in joined for t in ('login', 'sign-in', 'signin', 'authentication', 'mfa', 'password')) or \
       any(t in src for t in ('okta', 'azure ad', 'entra', 'iam')):
        user = row.get('user_principal_name') or row.get('username') or row.get('user') or 'an account'
        return (f"An authentication event for {user} was recorded. "
                "Unusual login patterns — unexpected location, timing, or MFA bypass — "
                "indicate the account may have been compromised.")

    # Endpoint / EDR process
    if any(t in joined for t in ('process', 'executable', '.exe', 'powershell', 'cmd.exe', 'wscript')) or \
       any(t in src for t in ('edr', 'crowdstrike', 'defender', 'falcon', 'endpoint')):
        proc = row.get('process_name') or row.get('TargetProcessName') or ''
        suffix = f" ({proc})" if proc else ''
        return (f"An endpoint process{suffix} was recorded by the security agent. "
                "Malicious processes running on corporate devices can harvest credentials, "
                "move laterally, or stage data for exfiltration.")

    # Cloud API / IAM
    if any(t in joined for t in ('iam', 'role', 'policy', 'assume', 'cloudtrail', 'api call')) or \
       any(t in src for t in ('aws', 'azure', 'gcp', 'cloud')):
        return ("A privileged cloud API call was made. "
                "Attackers use cloud API access to escalate privileges, exfiltrate data, "
                "or establish persistence by creating new accounts or access keys.")

    # MITRE technique fallback
    if technique:
        return f"Evidence supporting {technique} — a documented attacker technique used to achieve their objective in this incident."

    return ("This event was correlated with others in the incident timeline. "
            "Together these records form the chain of evidence showing how the attacker operated.")


def _build_fallback_evidence_chain(rows: list[dict]) -> list[dict]:
    from .evidence_binder import _row_ref, _row_action_text, _row_actor

    if not rows:
        return []

    def sort_key(row: dict):
        return (_row_time(row), _row_ref(row) if _row_ref(row) is not None else 10**9)

    selected: list[dict] = []
    seen_refs: set[int] = set()
    seen_actions: set[str] = set()
    for row in sorted(rows, key=sort_key):
        ref = _row_ref(row)
        if ref in seen_refs:
            continue
        text = _row_action_text(row)
        if not text:
            continue
        action_key = text[:120].lower()
        if action_key in seen_actions:
            continue
        seen_actions.add(action_key)
        selected.append(row)
        if ref is not None:
            seen_refs.add(ref)
        if len(selected) >= 5:
            break

    chain: list[dict] = []
    for idx, row in enumerate(selected, start=1):
        ref = _row_ref(row)
        action = _row_action_text(row)
        actor = _row_actor(row)
        when = _row_time(row)
        technique = row.get('mitre_technique') or row.get('mitre') or ''
        chain.append({
            'step': idx,
            'what': f"{when + ' - ' if when else ''}{actor}: {action}",
            'why_significant': _row_business_significance(row, technique),
            'row_refs': [ref] if ref is not None else [],
        })
    return chain


def _build_fallback_observed_impact(cluster: dict, rows: list[dict]) -> dict:
    _PROC_RE = re.compile(
        r'\.(exe|dll|sys|bat|ps1|sh)$'
        r'|^(system|nt authority|network service|local service'
        r'|processrollup\d*|lsass|svchost|winlogon|services)$',
        re.I,
    )
    identities = sorted({
        str(v).strip()
        for row in rows
        for k in (
            'user_principal_name', 'username', 'user', 'account',
            'actor', 'UserName', 'subject', 'target_user',
            'email', 'user_email', 'principal_name', 'SamAccountName',
            'user_name', 'UserId',
        )
        for v in [row.get(k)]
        if v and not _PROC_RE.search(str(v).strip())
    })[:5]
    hosts = sorted({
        str(v)
        for row in rows
        for v in (row.get('hostname'), row.get('host'), row.get('device_name'))
        if v
    })[:4]
    amounts = [
        row.get('wire_transfer_amount_aud')
        for row in rows
        if row.get('wire_transfer_amount_aud') not in (None, '')
    ]
    data_impact = ''
    if amounts:
        data_impact = 'Wire-transfer exposure observed: AUD ' + ', AUD '.join(str(a) for a in amounts[:2])
    elif any(row.get('emails_accessed') or row.get('email_read') for row in rows):
        data_impact = 'Mailbox access or email-read activity observed.'
    elif any(
        str(row.get('query_type') or '').upper() in {'UNLOAD', 'COPY'}
        or 'copy into' in str(row.get('query_text') or '').lower()
        for row in rows
    ):
        produced = [
            str(row.get('rows_produced'))
            for row in rows
            if row.get('rows_produced') not in (None, '')
        ]
        data_impact = (
            'Bulk data export or staging activity observed'
            + (f": {', '.join(produced[:2])} rows produced." if produced else '.')
        )
    return {
        'identity': ', '.join(identities) if identities else 'No named identity extracted.',
        'data': data_impact or 'No confirmed data loss field was present in the supplied telemetry.',
        'operational': (
            'Affected hosts: ' + ', '.join(hosts)
            if hosts else
            (cluster.get('business_significance') or 'Containment scope depends on the correlated evidence rows.')
        ),
    }


def _build_fallback_evidence_gaps(cluster: dict, rows: list[dict]) -> list[dict]:
    from .evidence_binder import _row_action_text
    joined = ' '.join(_row_action_text(r).lower() for r in rows[:30])
    gaps: list[dict] = []
    if any(token in joined for token in ('bec', 'wire', 'mailbox', 'bcc', 'imap')):
        gaps.append({
            'gap': 'Full mailbox audit and message trace for the affected finance accounts.',
            'would_confirm': 'whether the attacker sent, forwarded, or deleted additional payment messages',
            'significance': 'high',
        })
        gaps.append({
            'gap': 'Finance-system or bank workflow confirmation for the referenced payment request.',
            'would_confirm': 'whether the BEC attempt produced actual payment impact',
            'significance': 'high',
        })
    if any(token in joined for token in ('dns', 'beacon', 'c2', 'http', 'proxy')):
        gaps.append({
            'gap': 'Proxy, DNS, and firewall egress logs around the beacon window.',
            'would_confirm': 'the external command-and-control path and transferred byte volume',
            'significance': 'high',
        })
    if any(token in joined for token in ('process', 'powershell', 'exe', 'scheduled task', 'persistence')):
        gaps.append({
            'gap': 'EDR process tree and persistence artifacts for affected endpoints.',
            'would_confirm': 'the executable, parent process, and persistence mechanism',
            'significance': 'high',
        })
    if not gaps:
        gaps.append({
            'gap': ', '.join((cluster.get('recommended_logs') or ['Additional endpoint, identity, and network logs'])[:3]),
            'would_confirm': 'whether the correlated activity forms a complete attack chain',
            'significance': 'medium',
        })
    return gaps[:4]


def _classify_subtask_autonomy(label: str, tool_command: str = '') -> str:
    """Classify subtask autonomy tier for bounded-action display."""
    combined = (label + ' ' + tool_command).lower()
    if re.search(r'block|quarantin|isolat|revoke|reset.pass|disable|delete', combined):
        return 'APPROVAL_REQUIRED'
    if re.search(r'export|collect|captur|preserv|backup|snapshot|read.only|query|search|hunt|investigat', combined):
        return 'SAFE_TO_RUN'
    if re.search(r'notif|contact|escalat|alert|page|call', combined):
        return 'MANUAL_REVIEW'
    return ''


def _build_fallback_actions(data: dict) -> list[dict]:
    actions = data.get('top_actions') or []
    if not isinstance(actions, list):
        return []
    result: list[dict] = []
    for idx, action in enumerate(actions[:5], start=1):
        title = str(action).strip()
        if not title:
            continue
        autonomy = _classify_subtask_autonomy(title)
        result.append({
            'priority': f'P{min(idx, 3)}',
            'persona': 'SOC',
            'title': title,
            'subtasks': [
                {
                    'label': 'Record the evidence rows used for this action.',
                    'tool_command': '',
                    'expected_finding': 'Action is grounded in the displayed cluster evidence.',
                    'autonomy': autonomy,
                }
            ],
        })
    return result


def _infer_mitre_techniques(cluster: dict, rows: list[dict]) -> list[str]:
    from .evidence_binder import _row_action_text
    techniques: list[str] = []
    for source in (cluster.get('top_mitre'), cluster.get('mitre_techniques')):
        if isinstance(source, list):
            techniques.extend(str(item).strip() for item in source if str(item or '').strip())
    for row in rows:
        for key in ('mitre_technique', 'technique_id', 'mitre_id'):
            value = str(row.get(key) or '').strip()
            if value:
                techniques.append(value)
        for key in ('mitre', 'mitre_techniques', 'mitre_tags'):
            value = row.get(key)
            if isinstance(value, list):
                techniques.extend(str(item).strip() for item in value if str(item or '').strip())
            elif str(value or '').strip():
                techniques.append(str(value).strip())

    joined = ' '.join(_row_action_text(row).lower() for row in rows[:80])
    keyword_map = [
        (('password spray', 'invalid_credentials', 'credential stuffing'), 'T1110.003'),
        (('mfa fatigue', 'push notification', 'mfa prompt'), 'T1621'),
        (('legacy auth', 'imap', 'imap4'), 'T1078'),
        (('mailbox', 'email read', 'emails accessed'), 'T1114'),
        (('forwarding rule', 'bcc rule', 'inbox rule'), 'T1114.003'),
        (('bec', 'wire transfer', 'payment request'), 'T1566'),
        (('dns tunnel', 'dns beacon', 'beacon'), 'T1071.004'),
        (('c2', 'command-and-control', 'command and control'), 'T1071'),
        (('powershell', 'encoded command'), 'T1059.001'),
        (('scheduled task', 'persistence'), 'T1053.005'),
        (('lateral', 'rdp', 'wmi'), 'T1021'),
        (('exfil', 'bytes sent', 'rclone', 'backblaze', 'copy into', 'unload'), 'T1041'),
    ]
    for needles, technique in keyword_map:
        if any(needle in joined for needle in needles):
            techniques.append(technique)

    return list(dict.fromkeys(t for t in techniques if t))[:8]


# ── v2 prefill fields ─────────────────────────────────────────────────────────

def _ensure_v2_prefill_fields(data: dict, cluster: dict, rows: list[dict], tenant_id: str = 'default') -> dict:
    """Populate v2 story fields when an older LLM response only returned v1 keys."""
    if not isinstance(data, dict):
        return data
    narrative = str(data.get('what_happened') or '').strip()
    if not narrative:
        narrative = str(data.get('short_narrative') or '').strip()
    if not narrative:
        title = _fallback_incident_name(cluster, rows)
        subtitle = str(data.get('headline_subtitle') or '').strip()
        narrative = f"{title}: {subtitle}" if subtitle else title
    data['what_happened'] = narrative

    current_name = str(data.get('incident_name') or '').strip()
    if (
        not current_name
        or re.match(r'^unknown(?:[-_\s]*\d{4})?(?:[-_\s]*[a-z])?\s*breach$', current_name, re.I)
        or current_name.lower() in {'correlated incident', 'no validated breach'}
        or current_name.lower().startswith(('day ', 'shared ', 'same ', 'identity compromise or '))
        or len(current_name) > 72
        or 'cluster-' in current_name.lower()
    ):
        data['incident_name'] = _fallback_incident_name(cluster, rows)

    if _is_generic_root_cause(data.get('root_cause')):
        data['root_cause'] = _infer_root_cause(data, cluster, rows)

    if not isinstance(data.get('evidence_chain'), list) or not data.get('evidence_chain'):
        data['evidence_chain'] = _build_fallback_evidence_chain(rows)

    impact = data.get('observed_impact')
    impact_is_stale = (
        isinstance(impact, dict)
        and rows
        and (
            str(impact.get('identity') or '').startswith('No named identity')
            or str(impact.get('data') or '').startswith('No confirmed data loss')
        )
    )
    if not isinstance(impact, dict) or not impact or impact_is_stale:
        data['observed_impact'] = _build_fallback_observed_impact(cluster, rows)

    if not isinstance(data.get('evidence_gaps'), list) or not data.get('evidence_gaps'):
        data['evidence_gaps'] = _build_fallback_evidence_gaps(cluster, rows)

    if not isinstance(data.get('immediate_actions'), list) or not data.get('immediate_actions'):
        data['immediate_actions'] = _build_fallback_actions(data)

    if not isinstance(data.get('mitre_techniques'), list) or not data.get('mitre_techniques'):
        data['mitre_techniques'] = _infer_mitre_techniques(cluster, rows)

    # Replace raw verdict code labels or mismatched malicious-sounding text with evidence-based narrative
    _VERDICT_CODE_RE = re.compile(r'^[A-Z][A-Z_]{3,}$')
    _MALICIOUS_IN_BENIGN_RE = re.compile(
        r'command.and.control|c2 beacon|needs containment|attacker maintain|exfiltrat|intrusion|threat actor',
        re.I,
    )
    vr = str(data.get('verdict_reasoning') or '').strip()
    verdict = str(cluster.get('final_verdict') or cluster.get('verdict') or '').strip()
    _benign_verdict = verdict in ('BENIGN_EXPECTED', 'NO_VALIDATED_BREACH')
    _vr_needs_replace = (
        not vr
        or _VERDICT_CODE_RE.match(vr)
        or (_benign_verdict and _MALICIOUS_IN_BENIGN_RE.search(vr))
    )
    if _vr_needs_replace:
        root = str(data.get('root_cause') or '').strip()
        impact = data.get('observed_impact') or {}
        actors = str(impact.get('identity') or '').strip()
        seq = _detect_attack_sequence(rows)
        parts: list[str] = []
        if root:
            parts.append(root)
        if seq:
            first_line = seq.split('\n')[0]
            parts.append(f'Kill-chain: {first_line}.')
        if actors and 'No named' not in actors:
            parts.append(f'Affected accounts: {actors}.')
        if verdict in ('VALIDATED_BREACH', 'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE'):
            data['verdict_reasoning'] = ' '.join(parts) or 'Multi-source correlated evidence exceeds the breach investigation threshold.'
        elif _benign_verdict:
            short_narrative = str(data.get('short_narrative') or '').strip()
            benign_parts: list[str] = []
            if short_narrative and not _MALICIOUS_IN_BENIGN_RE.search(short_narrative):
                benign_parts.append(short_narrative)
            if root and not _MALICIOUS_IN_BENIGN_RE.search(root):
                benign_parts.append(root)
            if actors and 'No named' not in actors:
                benign_parts.append(f'Associated accounts reviewed: {actors}.')
            benign_parts.append('No indicators of unauthorized access, data loss, or malicious intent were confirmed.')
            data['verdict_reasoning'] = ' '.join(benign_parts)
        else:
            data['verdict_reasoning'] = root or 'Correlated evidence requires further analyst investigation.'

    # Build DREAD fragments and SABSA coda (deterministic — no LLM)
    if verdict not in ('BENIGN_EXPECTED', 'NO_VALIDATED_BREACH'):
        try:
            from src.prefill.dread_fragments import build_dread_narrative, fragments_fill_rate
            from src.prefill.sabsa_coda import build_sabsa_coda, derive_breached_attributes
            from src.prefill.compliance_tags import derive_controls_breached
        except ImportError:
            try:
                from prefill.dread_fragments import build_dread_narrative, fragments_fill_rate  # type: ignore
                from prefill.sabsa_coda import build_sabsa_coda, derive_breached_attributes      # type: ignore
                from prefill.compliance_tags import derive_controls_breached                      # type: ignore
            except ImportError:
                build_dread_narrative = None  # type: ignore
                derive_controls_breached = None  # type: ignore

        _existing_dn = data.get('dread_narrative') or {}
        _existing_fill = float(_existing_dn.get('fill_rate') or 0)
        if build_dread_narrative is not None and (not _existing_dn or _existing_fill < 0.20):
            frags = build_dread_narrative(rows, cluster, data, tenant_id=tenant_id)
            fill  = fragments_fill_rate(frags)
            attrs = derive_breached_attributes(frags)
            coda  = build_sabsa_coda(frags, attrs)
            data['dread_narrative'] = {
                'fragments':          frags,
                'fill_rate':          round(fill, 2),
                'sabsa_attributes':   attrs,
                'sabsa_coda_draft':   coda,
            }
            if derive_controls_breached is not None:
                data['compliance_controls'] = derive_controls_breached(frags)

    # ── Deterministic intelligence enrichments ─────────────────────────────────
    try:
        _enrich_cluster_intelligence(data, cluster, rows)
    except Exception as _ei:
        logger.warning('tier1_prefill: cluster intelligence enrichment failed for %s: %s',
                       cluster.get('cluster_id'), _ei)

    return data


# ── JSON parsing ──────────────────────────────────────────────────────────────

def _parse_prefill_json(raw: str, cluster_id: str) -> dict | None:
    """Extract JSON from LLM response, tolerating markdown fences and thinking tags."""
    from .verdict_engine import _narrative_is_technical
    import re as _re
    text = raw.strip()
    # Strip <think>...</think> blocks (qwen3 / deepseek-r1 thinking mode)
    text = _re.sub(r'<think>.*?</think>', '', text, flags=_re.DOTALL).strip()
    # Strip markdown code fences
    if text.startswith('```'):
        lines = text.split('\n')
        text = '\n'.join(
            l for l in lines
            if not l.strip().startswith('```')
        ).strip()

    def _repair_json(s: str) -> str:
        """Best-effort repair for common LLM JSON generation errors."""
        s = _re.sub(r',(\s*[}\]])', r'\1', s)
        if s and not s.rstrip().endswith(('}', ']', '"')):
            last_complete = max(s.rfind('},'), s.rfind('],'), s.rfind('"}}'))
            if last_complete > len(s) // 2:
                s = s[:last_complete + 1]
            s = s.rstrip().rstrip(',')
            s += ']' * max(0, s.count('[') - s.count(']'))
            s += '}' * max(0, s.count('{') - s.count('}'))
        return s

    def _try_parse(s: str) -> dict | None:
        try:
            return json.loads(s)
        except Exception:
            try:
                return json.loads(_repair_json(s))
            except Exception:
                return None

    required = {'incident_name', 'headline_subtitle', 'short_narrative',
                'confidence_rationale', 'top_actions', 'mitre_techniques'}

    data = _try_parse(text)
    if data is None:
        m = _re.search(r'\{.*\}', text, _re.DOTALL)
        if m:
            data = _try_parse(m.group())

    try:
        if data is not None and required.issubset(data.keys()):
            cot = data.pop('reasoning', None)
            if cot:
                data['_cot'] = cot
            mem = data.get('mitre_evidence_map')
            if isinstance(mem, dict):
                data['mitre_evidence_map'] = {
                    str(k): [int(i) for i in (v if isinstance(v, list) else [])]
                    for k, v in mem.items()
                }
            for step in (data.get('evidence_chain') or []):
                if isinstance(step, dict) and isinstance(step.get('row_refs'), list):
                    step['row_refs'] = [
                        int(r) for r in step['row_refs']
                        if str(r).lstrip('-').isdigit()
                    ]
            for field in ('what_happened', 'short_narrative'):
                val = data.get(field)
                if _narrative_is_technical(val):
                    data.setdefault('_quality_flags', []).append(
                        f'{field}_contains_jargon'
                    )
                    logger.warning(
                        'tier1_prefill: jargon detected in %s for cluster %s',
                        field, cluster_id,
                    )
            return data
        logger.warning('tier1_prefill: missing keys for %s — got=%s need=%s raw_head=%s',
                       cluster_id, sorted(data.keys()) if data else 'None',
                       sorted(required - (data.keys() if data else set())),
                       text[:300])
        return None
    except Exception as exc:
        logger.warning('tier1_prefill: JSON parse failed for %s: %s', cluster_id, exc)
        return None


# ── DREAD narrative render ────────────────────────────────────────────────────

def _raw_fragment_fallback(fragments: dict[str, str | None]) -> str:
    """Concatenate non-null fragments in causal order. Used when LLM render fails."""
    from .threat_models import _DREAD_CAUSAL_ORDER
    parts = [
        fragments.get(dim)
        for dim in _DREAD_CAUSAL_ORDER
        if fragments.get(dim)
    ]
    return ' '.join(parts)


def _choose_narrative_framework(cluster: dict, rows: list[dict]) -> str:
    """Returns 'diamond' when named actor entities exist, 'pasta' otherwise."""
    p = cluster.get('tier1_prefill') or {}
    impact = p.get('observed_impact') or {}
    actors_str = str(impact.get('identity') or '')
    if actors_str and 'No named' not in actors_str:
        named = [a.strip() for a in actors_str.split(',') if a.strip()]
        if any(('@' in a or ('.' in a and len(a) > 4)) for a in named):
            return 'diamond'
    for row in rows[:30]:
        for k in ('user_principal_name', 'username', 'user_email', 'email'):
            v = str(row.get(k) or '')
            if '@' in v or (v and '.' in v and len(v) > 4):
                return 'diamond'
    return 'pasta'


def _render_dread_narrative(
    fragments: dict[str, str | None],
    sabsa_coda_draft: str,
    sabsa_attributes: list[str],
    cluster: dict,
    rows: list[dict],
    llm: Any,
    model: str,
) -> dict[str, Any]:
    """Call the LLM with the strict render prompt, validate the output, return result dict."""
    from .threat_models import _order_fragments_temporally
    from .verdict_engine import _validate_entity_pins
    from .evidence_binder import _extract_entity_set

    _RENDER_FAILED_SENTINEL = '{{RENDER_FAILED}}'

    _prompt_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'prompts', 'dread_narrative_render.txt',
    )
    try:
        with open(_prompt_path, encoding='utf-8') as f:
            template = f.read()
    except Exception:
        template = (
            'Render a confirmed-breach executive summary from these evidence fragments.\n'
            'Rules: cite row numbers inline, preserve entity names exactly, '
            '150-220 words, start with "Confirmed breach — <label>."\n\n'
            'Fragments:\n{fragment_block}\n\nSABSA coda draft: {sabsa_coda_draft}\n\nRender now.'
        )

    ordered = _order_fragments_temporally(fragments)
    framework = _choose_narrative_framework(cluster, rows)

    frag_lines = []
    for i, (dim_label, frag_text) in enumerate(ordered, 1):
        frag_lines.append(f'  [T{i} {dim_label}]  {frag_text}')
    fragment_block = '\n'.join(frag_lines) or '  [NO FRAGMENTS AVAILABLE]'

    filled = template
    for i, (dim_label, frag_text) in enumerate(ordered, 1):
        filled = filled.replace(f'{{t{i}_dim}}', dim_label)
        filled = filled.replace(f'{{t{i}_fragment}}', frag_text)
    for i in range(len(ordered) + 1, 7):
        filled = filled.replace(f'{{t{i}_dim}}', '[ABSENT]')
        filled = filled.replace(f'{{t{i}_fragment}}', '[ABSENT]')

    geo_notes = _geo_sequence_summary(_detect_attack_sequence_events(rows))
    filled = filled.replace('{framework}', framework)
    filled = filled.replace('{sabsa_attributes}', ', '.join(sabsa_attributes) or 'none identified')
    filled = filled.replace('{sabsa_coda_draft}', sabsa_coda_draft or '[ABSENT]')
    filled = filled.replace('{geo_asn_notes}', geo_notes)
    filled = filled.replace('{fragment_block}', fragment_block)

    rendered_text = ''
    render_timeout = int(os.getenv('PREFILL_RENDER_TIMEOUT_S') or os.getenv('PREFILL_TIMEOUT_S') or os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS') or '45')
    try:
        result = llm.generate(
            filled,
            max_tokens=512,
            overrides={'timeout': render_timeout, 'retries': 0},
            model=model,
        )
        raw_rendered = (
            result.get('text') or result.get('response')
            or result.get('content') or ''
        ).strip()
        rendered_text = re.sub(r'<think>.*?</think>', '', raw_rendered, flags=re.DOTALL).strip()
    except Exception as _e:
        logger.warning('_render_dread_narrative: LLM call failed: %s', _e)
        rendered_text = ''

    if _RENDER_FAILED_SENTINEL in rendered_text or not rendered_text:
        return {
            'rendered': _raw_fragment_fallback(fragments),
            'render_fallback': True,
            'render_quality': {'passed': False, 'reason': 'sentinel_or_empty'},
        }

    allowed = _extract_entity_set(cluster, rows)
    quality = _validate_entity_pins(
        {'short_narrative': rendered_text, 'incident_name': '', 'headline_subtitle': '', 'top_actions': []},
        allowed,
    )

    if not quality['passed']:
        logger.warning(
            '_render_dread_narrative: entity pin check flagged %s — using fallback',
            quality['flagged_tokens'],
        )
        retry_prompt = (
            'The previous render was rejected because it introduced entity names '
            'not present in the evidence. Be exact — use only the names given below.\n\n'
            + filled
        )
        try:
            retry_result = llm.generate('/no_think\n' + retry_prompt, max_tokens=320, overrides={'timeout': render_timeout, 'retries': 0}, model=model)
            retry_text = (
                retry_result.get('text') or retry_result.get('response')
                or retry_result.get('content') or ''
            ).strip()
            retry_quality = _validate_entity_pins(
                {'short_narrative': retry_text, 'incident_name': '', 'headline_subtitle': '', 'top_actions': []},
                allowed,
            )
            if retry_quality['passed'] and retry_text:
                return {'rendered': retry_text, 'render_fallback': False, 'render_quality': retry_quality}
        except Exception:
            pass
        return {
            'rendered': _raw_fragment_fallback(fragments),
            'render_fallback': True,
            'render_quality': quality,
        }

    return {'rendered': rendered_text, 'render_fallback': False, 'render_quality': quality}


# ── Public entry points ───────────────────────────────────────────────────────

def run_prefill(
    assessment: dict[str, Any],
    top_n: int = 3,
    model: str = 'qwen3:14b',
    tenant_id: str = 'default',
    force: bool = False,
) -> dict[str, Any]:
    """Run Tier-1 prefill on the top_n clusters of the given assessment.

    Mutates assessment['correlation_clusters'][i]['tier1_prefill'] in-place.
    Returns a result summary dict.
    """
    from .verdict_engine import (
        PREFILL_ENABLED, PREFILL_TOP_N, PREFILL_MAX_TOKENS, PREFILL_TIMEOUT_S,
        _rank_clusters, _gated_verdict, _validate_entity_pins,
    )
    from .evidence_binder import (
        _get_rows_for_cluster, _extract_entity_set,
        _build_entity_cluster_index, _compute_cross_cluster_links,
    )

    if not PREFILL_ENABLED:
        return {'status': 'disabled', 'prefilled_clusters': [], 'duration_seconds': 0}

    assessment_id = assessment.get('assessment_id', 'unknown')
    clusters = assessment.get('correlation_clusters') or []
    if not clusters:
        logger.info('tier1_prefill: no clusters in assessment %s', assessment_id)
        return {'status': 'no_clusters', 'prefilled_clusters': [], 'duration_seconds': 0}

    try:
        from src.prompts.tier1_cluster_prefill import build_cluster_prefill_prompt
    except ImportError:
        from prompts.tier1_cluster_prefill import build_cluster_prefill_prompt  # type: ignore

    ranked = _rank_clusters(clusters)
    selected = ranked[:top_n]

    # ── Build assessment-wide engagement allowlist and inject into every cluster ──
    _all_eng_refs: set[str] = set()
    _all_eng_ip_ranges: set[str] = set()
    _all_eng_actors: set[str] = set()
    _all_auth_ips: set[str] = set()
    for _c in clusters:
        for _ref in (_c.get('engagement_refs') or []):
            _all_eng_refs.add(str(_ref).strip())
        for _rng in (_c.get('engagement_ip_ranges') or []):
            _all_eng_ip_ranges.add(str(_rng).strip())
        for _actor in (_c.get('engagement_actors') or []):
            _all_eng_actors.add(str(_actor).strip())
        for _ip in (_c.get('authorized_ips') or []):
            _all_auth_ips.add(str(_ip).strip())
        for _row in (_c.get('rows') or []):
            _row_refs = _row.get('_engagement_refs') or _row.get('engagement_refs') or []
            if _row_refs:
                _u = str(_row.get('user_canonical') or _row.get('user') or '').strip()
                if _u and _u not in ('-', ''):
                    _all_eng_actors.add(_u)

    _eng_meta = {
        '_assessment_engagement_refs':      sorted(_all_eng_refs),
        '_assessment_engagement_ip_ranges': sorted(_all_eng_ip_ranges),
        '_assessment_engagement_actors':    sorted(_all_eng_actors),
        '_assessment_authorized_ips':       sorted(_all_auth_ips),
    }
    for _c in clusters:
        _c.update(_eng_meta)
    if _all_eng_refs:
        logger.info(
            'tier1_prefill: injected assessment-wide engagement allowlist — '
            'refs=%s ip_ranges=%s actors=%d',
            sorted(_all_eng_refs), sorted(_all_eng_ip_ranges), len(_all_eng_actors),
        )

    prompts: list[str] = []
    selected_clusters: list[dict] = []
    render_pending: list[tuple[dict, dict, list[dict]]] = []  # (cluster, prefill, rows)

    _BREACH_VERDICTS = (
        'CONFIRMED_BREACH', 'LIKELY_BREACH', 'VALIDATED_BREACH',
        'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE',
    )

    for cluster in selected:
        _cv = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
        if _cv == 'ANALYSIS_INCOMPLETE':
            logger.debug('tier1_prefill: skipping ANALYSIS_INCOMPLETE cluster %s', cluster.get('cluster_id'))
            continue
        if not cluster.get('cluster_kind') and _cv not in _BREACH_VERDICTS:
            logger.debug('tier1_prefill: skipping untyped cluster %s (no cluster_kind)', cluster.get('cluster_id'))
            continue

        existing = cluster.get('tier1_prefill')
        if not force and existing and isinstance(existing, dict) and existing.get('incident_name'):
            rows = _get_rows_for_cluster(cluster, assessment)
            _ensure_v2_prefill_fields(existing, cluster, rows, tenant_id=tenant_id)
            _dn = existing.get('dread_narrative') or {}
            _fill = float(_dn.get('fill_rate') or 0)
            _verdict = str(cluster.get('verdict') or '').upper()
            if _fill < 0.20 and _verdict not in ('BENIGN_EXPECTED', 'NO_VALIDATED_BREACH'):
                try:
                    from src.prefill.dread_fragments import (
                        build_dread_narrative as _bdn,
                        fragments_fill_rate as _ffr,
                    )
                    from src.prefill.sabsa_coda import (
                        build_sabsa_coda as _bsc,
                        derive_breached_attributes as _dba,
                    )
                    _frags = _bdn(rows, cluster, existing, tenant_id=tenant_id)
                    _new_fill = _ffr(_frags)
                    _attrs = _dba(_frags)
                    _coda = _bsc(_frags, _attrs)
                    existing['dread_narrative'] = {
                        'fragments':        _frags,
                        'fill_rate':        round(_new_fill, 2),
                        'sabsa_attributes': _attrs,
                        'sabsa_coda_draft': _coda,
                    }
                    _dn = existing['dread_narrative']
                    logger.info(
                        'tier1_prefill: rebuilt stale dread for already-prefilled cluster %s fill=%.2f',
                        cluster.get('cluster_id'), _new_fill,
                    )
                except Exception as _dread_err:
                    logger.warning(
                        'tier1_prefill: dread rebuild failed for %s: %s',
                        cluster.get('cluster_id'), _dread_err,
                    )
            _v  = cluster.get('verdict', '')
            if _dn.get('fragments') and not _dn.get('rendered') and _v in _BREACH_VERDICTS:
                render_pending.append((cluster, existing, rows))
            logger.debug('tier1_prefill: cluster %s already prefilled, skipping',
                         cluster.get('cluster_id'))
            continue
        rows = _get_rows_for_cluster(cluster, assessment)
        all_rows = assessment.get('rows') or []

        if not rows and len(cluster.get('row_refs') or []) < 10:
            logger.info(
                'tier1_prefill: skipping cluster %s — no matched rows and only %d row_refs '
                '(likely a noise fragment; re-ingest to consolidate)',
                cluster.get('cluster_id'), len(cluster.get('row_refs') or []),
            )
            continue

        attack_seq = _detect_attack_sequence(rows)

        _intel: dict[str, Any] = {}
        try:
            _enrich_cluster_intelligence(_intel, cluster, rows)
        except Exception as _ie:
            logger.debug('tier1_prefill: pre-prompt intel failed for %s: %s',
                         cluster.get('cluster_id'), _ie)

        prompt = build_cluster_prefill_prompt(
            cluster, rows,
            all_assessment_rows=all_rows,
            attack_sequence=attack_seq,
            event_chain_summary=str(_intel.get('event_chain_summary') or ''),
            kill_chain_summary=str(_intel.get('kill_chain_summary') or ''),
            adversarial_sequence=bool(_intel.get('adversarial_sequence')),
            adversarial_sequence_detail=str(_intel.get('adversarial_sequence_detail') or ''),
            dread_score=_intel.get('dread_score'),
            diamond_model=_intel.get('diamond_model'),
            pasta_summary=_intel.get('pasta_summary'),
        )
        prompts.append('/no_think\n' + prompt)
        selected_clusters.append(cluster)

    if not prompts and not render_pending:
        already = [c.get('cluster_id') for c in selected]
        return {'status': 'already_cached', 'prefilled_clusters': already, 'duration_seconds': 0}

    # Fetch LLM client
    llm = None
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT
        llm = DEFAULT_CLIENT
    except Exception:
        try:
            from integrations.llm_client import DEFAULT_CLIENT  # type: ignore
            llm = DEFAULT_CLIENT
        except Exception:
            pass

    if llm is None:
        logger.warning('tier1_prefill: no LLM client available for assessment %s', assessment_id)
        return {'status': 'no_llm', 'prefilled_clusters': [], 'duration_seconds': 0}

    t0 = time.time()
    prefilled: list[str] = []

    results: list[Any] = []
    if prompts:
        try:
            results = llm.generate_batch(
                prompts=prompts,
                max_tokens=PREFILL_MAX_TOKENS,
                tenant_id=tenant_id,
                overrides={'timeout': PREFILL_TIMEOUT_S, 'retries': 0},
                model=model,
            )
        except Exception as exc:
            logger.warning('tier1_prefill: generate_batch failed for %s: %s', assessment_id, exc)
            for p in prompts:
                try:
                    r = llm.generate(
                        prompt=p,
                        max_tokens=PREFILL_MAX_TOKENS,
                        tenant_id=tenant_id,
                        overrides={'timeout': PREFILL_TIMEOUT_S, 'retries': 0},
                        model=model,
                    )
                    results.append(r)
                except Exception as e:
                    results.append({'error': str(e)})

    # Build entity index once across ALL clusters for cross-cluster linking
    all_clusters = assessment.get('correlation_clusters') or []
    entity_index = _build_entity_cluster_index(all_clusters, assessment)

    from .threat_models import _compute_confidence_meter

    for cluster, result in zip(selected_clusters, results):
        cid = cluster.get('cluster_id', '?')
        rows = _get_rows_for_cluster(cluster, assessment)

        confidence_meter = _compute_confidence_meter(cluster, rows)
        cluster['confidence_meter'] = confidence_meter

        if cluster.get('verdict_confidence') is None and confidence_meter.get('total') is not None:
            cluster['verdict_confidence'] = round(confidence_meter['total'] / 100.0, 2)

        if not (cluster.get('row_refs') or rows):
            cluster['human_validation_required'] = False
            if cluster.get('gate_urgency') not in (None, 'LOW'):
                cluster['gate_urgency'] = 'LOW'

        if isinstance(result, dict) and result.get('error'):
            logger.warning('tier1_prefill: LLM error for cluster %s: %s', cid, result['error'])
            fallback_data: dict[str, Any] = {
                '_error': result['error'],
                '_fallback_generated': True,
                'generated_at': int(time.time()),
                'confidence_meter': confidence_meter,
            }
            _ensure_v2_prefill_fields(fallback_data, cluster, rows, tenant_id=tenant_id)
            _old_t1_fb = cluster.get('tier1_prefill') or {}
            cluster['tier1_prefill'] = {**_old_t1_fb, **fallback_data}
            continue

        raw_text = ''
        if isinstance(result, dict):
            raw_text = (result.get('text') or result.get('response') or
                        result.get('content') or result.get('choices', [{}])[0].get('text', ''))
        elif isinstance(result, str):
            raw_text = result

        _think_text = ''
        _think_match = re.search(r'(?is)<think>(.*?)</think>', raw_text)
        if _think_match:
            _think_text = _think_match.group(1).strip()

        parsed = _parse_prefill_json(raw_text, cid)
        if parsed:
            parsed['model_used'] = model
            parsed['generated_at'] = int(time.time())

            if _think_text:
                parsed['_cot'] = _think_text
                _inv_lines = [
                    ln.strip(' -•*') for ln in _think_text.splitlines()
                    if any(kw in ln.lower() for kw in ('investigate', 'check', 'look for', 'trace', 'confirm', 'verify', 'hunt', 'pivot'))
                    and 10 < len(ln.strip()) < 200
                ]
                if _inv_lines and not parsed.get('investigate_next'):
                    parsed['investigate_next'] = _inv_lines[:6]
                elif _inv_lines:
                    existing = list(parsed.get('investigate_next') or [])
                    merged = existing + [l for l in _inv_lines if l not in existing]
                    parsed['investigate_next'] = merged[:8]

            allowed_entities = _extract_entity_set(cluster, rows)
            from .verdict_engine import _validate_entity_pins as _validate_ep
            quality = _validate_ep(parsed, allowed_entities)
            parsed['_quality'] = quality
            if not quality['passed']:
                logger.warning(
                    'tier1_prefill: quality gate flagged tokens %s in cluster %s',
                    quality['flagged_tokens'], cid,
                )

            parsed['confidence_meter'] = confidence_meter

            cross_links = _compute_cross_cluster_links(cluster, entity_index, all_clusters)
            parsed['cross_cluster_links'] = cross_links
            _ensure_v2_prefill_fields(parsed, cluster, rows, tenant_id=tenant_id)

            _old_t1 = cluster.get('tier1_prefill') or {}
            _old_t1.pop('_error', None)
            _old_t1.pop('_raw', None)
            cluster['tier1_prefill'] = {**_old_t1, **parsed}
            try:
                from src.core.verdict_engine.verdict_rules import compute_cluster_verdict
                v = compute_cluster_verdict(cluster)
                cluster['verdict'] = v['verdict']
                cluster['verdict_rationale'] = v['verdict_rationale']
                cluster['verdict_confidence'] = v['verdict_confidence']
            except Exception as _ve:
                logger.debug('tier1_prefill: verdict derivation failed for %s: %s', cid, _ve)

            raw_v  = cluster.get('verdict') or ''
            if raw_v == 'ANALYSIS_INCOMPLETE':
                continue
            conf   = float(cluster.get('verdict_confidence') or 0)
            dn     = parsed.get('dread_narrative') or {}
            fill   = float(dn.get('fill_rate') or 0)
            gated  = _gated_verdict(raw_v, conf, fill)
            if gated != raw_v:
                cluster['verdict'] = gated
                logger.info(
                    'tier1_prefill: verdict gated %s → %s (conf=%.2f fill=%.2f) cluster %s',
                    raw_v, gated, conf, fill, cid,
                )
            try:
                from src.api.deep_analyze_endpoints import _apply_hvr_gating
                _apply_hvr_gating(cluster)
            except Exception as _hvr_e:
                logger.debug('tier1_prefill: hvr re-apply failed for %s: %s', cid, _hvr_e)

            _dn = parsed.get('dread_narrative') or {}
            _frags = _dn.get('fragments') or {}
            _final_verdict = cluster.get('verdict', '')
            _is_breach_class = _final_verdict in (
                'CONFIRMED_BREACH', 'LIKELY_BREACH', 'VALIDATED_BREACH', 'CONFIRMED_INTRUSION',
                'LIKELY_COMPROMISE',
            )
            if _is_breach_class and _frags and not _dn.get('rendered'):
                try:
                    _render_result = _render_dread_narrative(
                        fragments=_frags,
                        sabsa_coda_draft=_dn.get('sabsa_coda_draft', ''),
                        sabsa_attributes=_dn.get('sabsa_attributes', []),
                        cluster=cluster,
                        rows=rows,
                        llm=llm,
                        model=model,
                    )
                    _dn.update(_render_result)
                    parsed['dread_narrative'] = _dn
                    _old_t1.pop('_error', None)
                    _old_t1.pop('_raw', None)
                    cluster['tier1_prefill'] = {**_old_t1, **parsed}
                    logger.info(
                        'tier1_prefill: dread narrative rendered for cluster %s (fallback=%s)',
                        cid, _render_result.get('render_fallback'),
                    )
                except Exception as _re:
                    logger.warning('tier1_prefill: dread narrative render failed for %s: %s', cid, _re)

            prefilled.append(cid)
            logger.info('tier1_prefill: prefilled cluster %s (%s) quality=%s verdict=%s',
                        cid, assessment_id, 'ok' if quality['passed'] else 'flagged',
                        cluster.get('verdict', '?'))
        else:
            _old_t1_pf = cluster.get('tier1_prefill') or {}
            _old_t1_pf.pop('incident_name', None)
            cluster['tier1_prefill'] = {
                **_old_t1_pf,
                '_error': 'parse_failed',
                '_raw': raw_text[:200],
                'generated_at': int(time.time()),
                'confidence_meter': confidence_meter,
            }

    # Deferred render pass
    for _rcluster, _rprefill, _rrows in render_pending:
        _rcid  = _rcluster.get('cluster_id', '?')
        _rdn   = _rprefill.get('dread_narrative') or {}
        _rfrgs = _rdn.get('fragments') or {}
        if not _rfrgs or _rdn.get('rendered'):
            continue
        try:
            _rr = _render_dread_narrative(
                fragments=_rfrgs,
                sabsa_coda_draft=_rdn.get('sabsa_coda_draft', ''),
                sabsa_attributes=_rdn.get('sabsa_attributes', []),
                cluster=_rcluster,
                rows=_rrows,
                llm=llm,
                model=model,
            )
            _rdn.update(_rr)
            _rprefill['dread_narrative'] = _rdn
            _rcluster['tier1_prefill'] = _rprefill
            prefilled.append(_rcid)
            logger.info(
                'tier1_prefill: deferred dread render for cached cluster %s (fallback=%s)',
                _rcid, _rr.get('render_fallback'),
            )
        except Exception as _rre:
            logger.warning('tier1_prefill: deferred render failed for %s: %s', _rcid, _rre)

    duration = round(time.time() - t0, 2)
    status = 'ok' if prefilled else 'already_cached'
    return {
        'status': status,
        'prefilled_clusters': prefilled,
        'duration_seconds': duration,
    }


def run_single_cluster_prefill(
    assessment: dict[str, Any],
    cluster_id: str,
    model: str = 'qwen3:14b',
    tenant_id: str = 'default',
    force: bool = False,
) -> dict[str, Any]:
    """Prefill a single cluster by ID (used for on-demand clusters 4+)."""
    from .evidence_binder import _get_rows_for_cluster

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        return {'status': 'not_found', 'cluster_id': cluster_id}

    existing = cluster.get('tier1_prefill')
    if not force and existing and isinstance(existing, dict) and existing.get('incident_name'):
        rows = _get_rows_for_cluster(cluster, assessment)
        _ensure_v2_prefill_fields(existing, cluster, rows)
        _dn = existing.get('dread_narrative') or {}
        _fill = float(_dn.get('fill_rate') or 0)
        _verdict = str(cluster.get('verdict') or '').upper()
        if _fill < 0.20 and _verdict not in ('BENIGN_EXPECTED', 'NO_VALIDATED_BREACH'):
            try:
                from src.prefill.dread_fragments import (
                    build_dread_narrative as _bdn,
                    fragments_fill_rate as _ffr,
                )
                from src.prefill.sabsa_coda import (
                    build_sabsa_coda as _bsc,
                    derive_breached_attributes as _dba,
                )
                _frags = _bdn(rows, cluster, existing, tenant_id=tenant_id)
                _new_fill = _ffr(_frags)
                _attrs = _dba(_frags)
                _coda = _bsc(_frags, _attrs)
                existing['dread_narrative'] = {
                    'fragments':        _frags,
                    'fill_rate':        round(_new_fill, 2),
                    'sabsa_attributes': _attrs,
                    'sabsa_coda_draft': _coda,
                }
                logger.info(
                    'run_single_cluster_prefill: rebuilt stale dread cluster=%s fill=%.2f',
                    cluster_id, _new_fill,
                )
            except Exception as _de:
                logger.warning('run_single_cluster_prefill: dread rebuild failed %s: %s', cluster_id, _de)
        return {'status': 'already_cached', 'cluster_id': cluster_id,
                'tier1_prefill': existing,
                'verdict': cluster.get('verdict'),
                'verdict_rationale': cluster.get('verdict_rationale'),
                'verdict_confidence': cluster.get('verdict_confidence'),
                'gate_urgency': cluster.get('gate_urgency'),
                'playbook_status': cluster.get('playbook_status')}

    # Temporarily set top_n=1 by swapping cluster to front
    assessment_copy = dict(assessment)
    assessment_copy['correlation_clusters'] = [cluster] + [
        c for c in clusters if c.get('cluster_id') != cluster_id
    ]
    result = run_prefill(assessment_copy, top_n=1, model=model, tenant_id=tenant_id)
    # Sync back the mutated cluster into the original list
    for orig in clusters:
        if orig.get('cluster_id') == cluster_id:
            orig['tier1_prefill'] = cluster.get('tier1_prefill')
            for key in ('verdict', 'verdict_rationale', 'verdict_confidence',
                        'human_validation_required', 'gate_urgency', 'playbook_status'):
                if key in cluster:
                    orig[key] = cluster.get(key)
            break

    return {
        'status': result.get('status'),
        'cluster_id': cluster_id,
        'tier1_prefill': cluster.get('tier1_prefill'),
        'verdict': cluster.get('verdict'),
        'verdict_rationale': cluster.get('verdict_rationale'),
        'verdict_confidence': cluster.get('verdict_confidence'),
        'human_validation_required': cluster.get('human_validation_required'),
        'gate_urgency': cluster.get('gate_urgency'),
        'playbook_status': cluster.get('playbook_status'),
        'duration_seconds': result.get('duration_seconds', 0),
    }
