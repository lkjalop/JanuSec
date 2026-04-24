"""
DREAD evidence fragment extractors.

Five pure functions — no LLM, no side effects — each returning one sentence with
inline row refs, or None when evidence is absent.

Design rules:
- Each function reads rows + cluster/data dicts only.
- Row refs cited as (rows N, M, …).
- None means evidence absent — never fabricate downstream.
- Crown-jewels tagfile is optional; functions degrade gracefully without it.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any


# ── Crown-jewels loader ──────────────────────────────────────────────────────

_CJ_CACHE: dict | None = None
_CJ_TENANT_CACHE: dict[str, dict] = {}

_DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'data')
)


def _load_crown_jewels(path: str | None = None) -> dict:
    """Load the default crown jewels file (no tenant override)."""
    global _CJ_CACHE
    if _CJ_CACHE is not None:
        return _CJ_CACHE
    candidates = [
        path,
        os.environ.get('CROWN_JEWELS_PATH'),
        os.path.join(_DATA_DIR, 'crown_jewels.json'),
        'data/crown_jewels.json',
    ]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                with open(p, encoding='utf-8') as f:
                    _CJ_CACHE = json.load(f)
                    return _CJ_CACHE
            except Exception:
                pass
    _CJ_CACHE = {}
    return _CJ_CACHE


def _load_crown_jewels_for_tenant(tenant_id: str | None) -> dict:
    """Load the tenant-specific crown jewels file, falling back to the default.
    Caches per tenant_id; use tenant_id=None for default."""
    if not tenant_id or tenant_id == 'default':
        return _load_crown_jewels()
    if tenant_id in _CJ_TENANT_CACHE:
        return _CJ_TENANT_CACHE[tenant_id]
    safe = ''.join(c for c in tenant_id if c.isalnum() or c in ('-', '_'))[:64]
    path = os.path.join(_DATA_DIR, f'crown_jewels_{safe}.json')
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                result = json.load(f)
                _CJ_TENANT_CACHE[tenant_id] = result
                return result
        except Exception:
            pass
    # Fall back to default
    result = _load_crown_jewels()
    _CJ_TENANT_CACHE[tenant_id] = result
    return result


def _effective_tier(entry: dict) -> str:
    """Return the human-overridden tier when a review exists; else the auto-detected tier."""
    review = entry.get('_human_review') or {}
    if review.get('status') in ('confirmed', 'escalated', 'downgraded') and review.get('override_tier'):
        return review['override_tier']
    return entry.get('tier', '')


# ── Row field helpers ────────────────────────────────────────────────────────

_TS_KEYS = (
    'timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time',
    'start_time', 'published', 'created', 'time', 'ts',
)

_PROC_RE = re.compile(
    r'\.(exe|dll|sys|bat|ps1|sh)$'
    r'|^(system|nt authority|network service|local service'
    r'|processrollup\d*|lsass|svchost|winlogon|services)$',
    re.I,
)

_IDENTITY_KEYS = (
    'user_principal_name', 'username', 'user_name', 'UserId',
    'user', 'account', 'actor', 'email', 'principal_name',
)


def _ts(row: dict) -> str:
    for k in _TS_KEYS:
        v = row.get(k)
        if v:
            return str(v)[:19]
    return ''


def _ref(row: dict) -> int | None:
    for k in ('row_index', 'row_number'):
        try:
            return int(row.get(k))  # type: ignore[arg-type]
        except Exception:
            pass
    return None


def _refs(rows: list[dict]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for r in rows:
        ri = _ref(r)
        if ri is not None and ri not in seen:
            seen.add(ri)
            out.append(ri)
    return sorted(out)


def _cite(refs: list[int], max_n: int = 6) -> str:
    if not refs:
        return ''
    shown = refs[:max_n]
    s = 'rows ' + ', '.join(str(r) for r in shown)
    if len(refs) > max_n:
        s += f' +{len(refs) - max_n} more'
    return f'({s})'


def _joined_lower(rows: list[dict]) -> str:
    return ' '.join(
        str(v)
        for row in rows
        for v in row.values()
        if isinstance(v, str)
    ).lower()


# ── Fragment 1: Damage ───────────────────────────────────────────────────────

def damage_fragment(
    rows: list[dict],
    cluster: dict,
    data: dict,
    crown_jewels_path: str | None = None,
    tenant_id: str | None = None,
) -> str | None:
    """What was harmed, when, and to where? Returns None if no exfil detected."""
    cj = _load_crown_jewels_for_tenant(tenant_id) if tenant_id else _load_crown_jewels(crown_jewels_path)
    cj_assets = cj.get('assets', {})
    cj_dests = cj.get('destinations', {})

    exfil_rows: list[dict] = []
    for row in rows:
        j = _joined_lower([row])
        if any(t in j for t in ('rclone', 'backblaze', 'mega.nz', 'azcopy', 'gsutil', 'aws s3 cp')):
            exfil_rows.append(row)
        elif str(row.get('query_type') or '').upper() in {'UNLOAD', 'COPY'}:
            exfil_rows.append(row)
        elif 'copy into' in str(row.get('query_text') or '').lower():
            exfil_rows.append(row)
        else:
            try:
                if float(row.get('bytes_sent') or row.get('orig_bytes') or 0) > 1_000_000:
                    exfil_rows.append(row)
            except Exception:
                pass

    if not exfil_rows:
        return None

    timed = sorted(((r, _ts(r)) for r in exfil_rows), key=lambda x: x[1])
    first_row, first_ts = timed[0]
    actor = (
        first_row.get('user_principal_name') or first_row.get('username')
        or first_row.get('user') or first_row.get('actor') or 'an actor'
    )

    joined_all = _joined_lower(exfil_rows)
    dest_label = 'a cloud storage destination'
    for marker, label in [
        ('backblaze', 'Backblaze B2'),
        ('mega.nz', 'MEGA.nz'),
        ('mega', 'MEGA.nz'),
        ('aws s3', 'Amazon S3'),
        ('gsutil', 'Google Cloud Storage'),
        ('azcopy', 'Azure Blob Storage'),
    ]:
        if marker in joined_all:
            dest_key = marker.split('.')[0]
            dest_label = label + (' (unapproved cloud destination)' if dest_key in cj_dests else '')
            break

    # Extract source path from command line
    source_path = ''
    for row in exfil_rows:
        cmd = str(row.get('CommandLine') or row.get('command_line') or row.get('process') or '')
        m = re.search(r'(\\\\[\w\\\.\-]+|\/[\w\/\-\.]+)', cmd)
        if m:
            source_path = m.group(1)
            break

    # Crown-jewel annotation — uses effective tier (human override takes precedence)
    cj_note = ''
    for asset_key, asset_meta in cj_assets.items():
        if (asset_key.lower() in joined_all
                or (source_path and asset_key.lower() in source_path.lower())):
            eff_tier = _effective_tier(asset_meta)
            if eff_tier in ('crown_jewel', 'tier_1'):
                triggers = asset_meta.get('notification_triggers', [])
                t_str = ' + '.join(t.upper() for t in triggers) if triggers else ''
                review = asset_meta.get('_human_review') or {}
                human_note = (
                    f" [human-{review['status']}]" if review.get('status') else ''
                )
                cj_note = (
                    f" — asset tagged as {eff_tier.replace('_', ' ')}{human_note}"
                    + (f" ({t_str} notification assessment triggered)" if t_str else '')
                )
            elif eff_tier == 'not_sensitive':
                # Human downgraded — skip notification trigger
                pass
            break

    refs = _cite(_refs(exfil_rows))
    ts_display = first_ts.replace('T', ' ').replace('Z', ' UTC') if 'T' in first_ts else first_ts
    path_part = f' from {source_path}' if source_path else ''

    return (
        f"On {ts_display}, {actor} transferred data{path_part} "
        f"to {dest_label}{cj_note} {refs}."
    ).strip()


# ── Fragment 2: Reproducibility ──────────────────────────────────────────────

def reproducibility_fragment(
    rows: list[dict],
    cluster: dict,
    data: dict,
) -> str | None:
    """Did the same action recur across time? Returns None if single occurrence."""
    cmd_rows = [
        row for row in rows
        if str(
            row.get('CommandLine') or row.get('command_line')
            or row.get('process') or row.get('event_type') or ''
        ).strip()
    ]
    if not cmd_rows:
        return None

    by_stem: dict[str, list[dict]] = {}
    for row in cmd_rows:
        cmd = str(
            row.get('CommandLine') or row.get('command_line')
            or row.get('process') or row.get('event_type') or ''
        )
        stem = cmd[:60].lower().strip()
        if stem:
            by_stem.setdefault(stem, []).append(row)

    if not by_stem:
        return None

    top_stem, top_rows = max(by_stem.items(), key=lambda x: len(x[1]))
    if len(top_rows) < 2:
        return None

    dates: set[str] = {_ts(r)[:10] for r in top_rows if _ts(r)}
    distinct_days = len(dates)
    if distinct_days < 2:
        return None

    refs = _cite(_refs(top_rows))
    term = 'established persistence' if distinct_days >= 3 else 'recurring activity'
    return (
        f"The same command signature recurred across {distinct_days} distinct days {refs}, "
        f"indicating {term} rather than a single-shot operation."
    )


# ── Fragment 3: Exploitability ───────────────────────────────────────────────

_CONTROL_GAP_TABLE: list[tuple[list[str], str]] = [
    (
        ['rclone', 'backblaze', 'mega', 'azcopy', 'gsutil'],
        'no DLP inspection on cloud-sync egress and no PAM gate on the path; '
        'the account held unconstrained cloud egress rights without an activity baseline',
    ),
    (
        ['lsass', 'comsvcs', 'mimikatz', 'procdump', 'ntds'],
        'endpoint protection was not in prevention mode; '
        'LSASS read access was not restricted by Credential Guard or Protected Process Light',
    ),
    (
        ['psexec', 'wmiexec', 'rdp', 'smb', 'lateral'],
        'no micro-segmentation or jump-server policy prevented lateral SMB/RDP movement '
        'from the compromised host',
    ),
    (
        ['bec', 'inbox rule', 'imap', 'mailbox rule', 'wire'],
        'no mail-flow rule blocked external forwarding; '
        'finance wire approvals lacked dual-control verification',
    ),
    (
        ['dns', 'beacon', 'c2', 'cobalt', 'empire'],
        'no DNS monitoring or proxy inspection flagged anomalous beacon intervals; '
        'C2 traffic traversed without per-process TLS inspection',
    ),
    (
        ['password spray', 'brute', 'mfa fatigue', 'legacy auth', 'imap'],
        'legacy authentication protocols were not blocked; '
        'MFA push notifications were not number-matched to resist fatigue attacks',
    ),
]


def exploitability_fragment(
    rows: list[dict],
    cluster: dict,
    data: dict,
) -> str | None:
    """What control gap allowed this? Returns None if no pattern matches."""
    joined = _joined_lower(rows[:40])
    for keywords, gap in _CONTROL_GAP_TABLE:
        if any(kw in joined for kw in keywords):
            return f"Control gaps exploited: {gap}."
    return None


# ── Fragment 4: Affected Users ───────────────────────────────────────────────

def affected_users_fragment(
    rows: list[dict],
    cluster: dict,
    data: dict,
    crown_jewels_path: str | None = None,
    tenant_id: str | None = None,
) -> str | None:
    """Named entities in scope with privilege tier. Returns None if no identifiable actors."""
    cj = _load_crown_jewels_for_tenant(tenant_id) if tenant_id else _load_crown_jewels(crown_jewels_path)
    cj_accounts = cj.get('accounts', {})

    identities: list[str] = []
    seen: set[str] = set()

    for row in rows:
        for k in _IDENTITY_KEYS:
            v = str(row.get(k) or '').strip()
            if v and v.lower() not in seen and not _PROC_RE.search(v):
                seen.add(v.lower())
                identities.append(v)

    # Supplement from already-computed observed_impact
    impact = data.get('observed_impact') or {}
    for part in str(impact.get('identity') or '').split(','):
        v = part.strip()
        if v and 'No named' not in v and v.lower() not in seen:
            seen.add(v.lower())
            identities.append(v)

    if not identities:
        return None

    labelled: list[str] = []
    for ident in identities[:6]:
        meta = cj_accounts.get(ident)
        if meta:
            eff_tier = _effective_tier(meta)
            # Human downgraded to not_sensitive — exclude from fragment
            if eff_tier == 'not_sensitive':
                continue
            role = meta.get('role', '')
            review = meta.get('_human_review') or {}
            review_tag = f', human-{review["status"]}' if review.get('status') else ''
            tag = f'{eff_tier.replace("_", " ")}{(", " + role) if role else ""}{review_tag}'
            labelled.append(f'{ident} ({tag})')
        else:
            labelled.append(ident)

    count = len(labelled)
    return f"{count} account{'s' if count != 1 else ''} in scope: {', '.join(labelled)}."


# ── Fragment 5: Discoverability ──────────────────────────────────────────────

def discoverability_fragment(
    rows: list[dict],
    cluster: dict,
    data: dict,
) -> str | None:
    """MTTD from first event to detection. Returns None if no timestamp data."""
    timestamps = sorted(t for row in rows for t in [_ts(row)] if t)
    if not timestamps:
        return None

    first_seen = timestamps[0][:10]

    detected_at = str(
        cluster.get('created_at') or cluster.get('detection_time')
        or data.get('prefill_generated_at') or ''
    )[:10]

    sources: set[str] = {
        str(row.get('_source') or row.get('source') or row.get('source_platform') or '').lower()
        for row in rows
        if row.get('_source') or row.get('source') or row.get('source_platform')
    }
    cross_source = len(sources) >= 2

    mttd_str = ''
    if first_seen and detected_at and detected_at > first_seen:
        try:
            from datetime import date
            days = (date.fromisoformat(detected_at) - date.fromisoformat(first_seen)).days
            if days > 0:
                mttd_str = f' — {days}-day MTTD'
        except Exception:
            pass

    detection_note = (
        f'Cross-source correlation across {len(sources)} source type{"s" if len(sources) != 1 else ""} surfaced it'
        if cross_source else
        'Single-source monitoring did not trigger; cross-source correlation surfaced it'
    )

    return f"First event: {first_seen}. {detection_note}{mttd_str}."


# ── Orchestrator ─────────────────────────────────────────────────────────────

def build_dread_narrative(
    rows: list[dict],
    cluster: dict,
    data: dict,
    crown_jewels_path: str | None = None,
    tenant_id: str | None = None,
) -> dict[str, str | None]:
    """
    Run all five extractors. Returns dict keyed by DREAD dimension.
    None values = evidence absent. Caller must not fabricate missing fragments.

    tenant_id — when provided, loads the tenant-specific crown jewels file so
    human review overrides (escalate/downgrade) propagate into fragment text.
    """
    return {
        'damage':          damage_fragment(rows, cluster, data, crown_jewels_path, tenant_id),
        'reproducibility': reproducibility_fragment(rows, cluster, data),
        'exploitability':  exploitability_fragment(rows, cluster, data),
        'affected_users':  affected_users_fragment(rows, cluster, data, crown_jewels_path, tenant_id),
        'discoverability': discoverability_fragment(rows, cluster, data),
    }


def fragments_fill_rate(fragments: dict[str, str | None]) -> float:
    """What fraction of the 5 slots have evidence? Used by confidence-floor gating."""
    filled = sum(1 for v in fragments.values() if v)
    return filled / max(len(fragments), 1)
