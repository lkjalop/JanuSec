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

    # ── Helper: resolve a time-range prefix for any scenario ────────────────
    def _time_prefix(candidate_rows: list[dict]) -> str:
        """Return 'On YYYY-MM-DD, ' or 'Between X and Y, ' or '' (never 'On , ')."""
        all_ts = sorted(t for r in candidate_rows or rows for t in [_ts(r)] if t)
        if all_ts:
            fd, ld = all_ts[0][:10], all_ts[-1][:10]
            return f'Between {fd} and {ld}, ' if fd != ld else f'On {fd}, '
        # Cluster-level fallback
        clt = str(
            cluster.get('created_at') or cluster.get('first_seen')
            or data.get('prefill_generated_at') or ''
        )[:10]
        return f'Around {clt}, ' if clt else ''

    # ── 0. Credential theft / LSASS / session-token theft (checked first) ──
    _CRED_KW = (
        'lsass', 'comsvcs', 'mimikatz', 'procdump', 'ntds',
        'secretsdump', 'credential_theft', 'credential theft',
        'session_theft', 'token theft', 'pass-the-hash', 'pass the hash',
    )
    _lead_lower = (
        cluster.get('lead_description') or cluster.get('cluster_label') or ''
    ).lower()
    _phases_lower = ' '.join(
        str(ph.get('phase_role') or ph.get('type') or ph.get('name') or '')
        for ph in (cluster.get('phases') or [])
    ).lower()
    cred_rows = [r for r in rows if any(kw in _joined_lower([r]) for kw in _CRED_KW)]
    _is_cred = bool(cred_rows) or any(
        kw in (_lead_lower + ' ' + _phases_lower)
        for kw in ('lsass', 'credential', 'mfa fatigue', 'session theft', 'token theft')
    )
    if _is_cred:
        ts_prefix = _time_prefix(cred_rows)
        idents: list[str] = []
        seen_ids: set[str] = set()
        for row in rows:
            for k in _IDENTITY_KEYS:
                v = str(row.get(k) or '').strip()
                if v and v.lower() not in seen_ids and not _PROC_RE.search(v):
                    seen_ids.add(v.lower())
                    idents.append(v)
        accts = ', '.join(idents[:3]) if idents else 'affected accounts'
        jc = _joined_lower(cred_rows) if cred_rows else _joined_lower(rows[:10])
        if 'comsvcs' in jc:
            tool = 'via comsvcs.dll (native LSASS memory dump)'
        elif 'mimikatz' in jc or 'sekurlsa' in jc:
            tool = 'via Mimikatz in-memory credential extraction'
        elif 'procdump' in jc:
            tool = 'via ProcDump (LSASS dump)'
        elif 'ntds' in jc or 'secretsdump' in jc:
            tool = 'via NTDS.dit extraction (domain credential dump)'
        elif 'mfa' in _lead_lower or 'fatigue' in _lead_lower:
            tool = 'via MFA fatigue push-notification bypass'
        else:
            tool = 'via LSASS memory access'
        refs = _cite(_refs(cred_rows or rows[:5]))
        return (
            f'{ts_prefix}Credential material for {accts} was harvested {tool}. '
            f'NTLM hashes \u2014 and potentially Kerberos tickets \u2014 are at risk of '
            f'pass-the-hash relay or offline cracking {refs}.'
        ).strip()

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
        # ── Endpoint/container compromise (K8s privileged pod, Docker socket, LPE) ──
        container_rows: list[dict] = []
        for row in rows:
            j = _joined_lower([row])
            if any(t in j for t in (
                'privileged', 'hostpid', 'hostnetwork', 'hostipc',
                'docker.sock', 'nsenter', 'chroot /host',
            )):
                container_rows.append(row)
            else:
                obj = row.get('objectRef') or {}
                if isinstance(obj, dict):
                    resource = str(obj.get('resource') or '').lower()
                    if resource in ('pods', 'deployments', 'daemonsets') and any(
                        t in j for t in ('privileged', 'hostpid', 'hostnetwork')
                    ):
                        container_rows.append(row)
        if container_rows:
            timed = sorted(((r, _ts(r)) for r in container_rows), key=lambda x: x[1])
            first_row, first_ts = timed[0]
            actor = (
                first_row.get('user_principal_name') or first_row.get('username')
                or first_row.get('user') or first_row.get('actor') or 'an actor'
            )
            obj = first_row.get('objectRef') or {}
            ns_raw = (
                first_row.get('namespace') or
                (obj.get('namespace') if isinstance(obj, dict) else None)
            )
            namespace = ns_raw if (ns_raw and str(ns_raw).lower() not in ('', 'unknown', 'none')) else None
            pod_name = (
                first_row.get('pod_name') or
                (obj.get('name') if isinstance(obj, dict) else None) or
                'a pod'
            )
            refs = _cite(_refs(container_rows))
            ts_prefix = _time_prefix(container_rows)
            ns_clause = f' in namespace {namespace}' if namespace else ''
            return (
                f"{ts_prefix}{actor} launched a privileged container "
                f"({pod_name}{ns_clause}), enabling potential node-level "
                f"compromise via host process or network access {refs}."
            ).strip()
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
    ts_prefix = _time_prefix(exfil_rows)
    path_part = f' from {source_path}' if source_path else ''

    return (
        f"{ts_prefix}{actor} transferred data{path_part} "
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
    (
        ['privileged', 'hostpid', 'hostnetwork', 'hostipc', 'docker.sock', 'nsenter'],
        'no PodSecurity admission policy blocked privileged container creation; '
        'host-process and host-network access was permitted without node isolation controls',
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

    # Build authorized-actor filter so pentest / red-team accounts are excluded
    # from the DREAD affected_users fragment (mirrors Diamond victim filtering).
    _auth_actors: set[str] = set()
    _eng_refs: list[str] = []
    for _key in ('_assessment_engagement_actors', 'engagement_actors'):
        for _a in (cluster.get(_key) or []):
            _auth_actors.add(str(_a).strip().lower())
    for _key in ('_assessment_engagement_refs', 'engagement_refs'):
        for _r in (cluster.get(_key) or []):
            _eng_refs.append(str(_r).strip().lower())

    def _is_auth(actor: str) -> bool:
        a = actor.strip().lower()
        if a in _auth_actors:
            return True
        return any(ref and ref in a for ref in _eng_refs)

    identities: list[str] = []
    seen: set[str] = set()

    for row in rows:
        for k in _IDENTITY_KEYS:
            v = str(row.get(k) or '').strip()
            if v and v.lower() not in seen and not _PROC_RE.search(v) and not _is_auth(v):
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

    if timestamps:
        first_seen = timestamps[0][:10]
        last_seen = timestamps[-1][:10]
    else:
        # Fall back to cluster-level timing when rows carry no timestamps
        first_seen = str(
            cluster.get('first_seen') or cluster.get('created_at')
            or data.get('prefill_generated_at') or ''
        )[:10] or None
        last_seen = None

    if not first_seen:
        return None

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

    # Show activity window when spans multiple days (temporal context for analyst)
    if last_seen and last_seen != first_seen:
        time_clause = f'Activity window: {first_seen} \u2192 {last_seen}'
    else:
        time_clause = f'First observed: {first_seen}'

    return f"{time_clause}. {detection_note}{mttd_str}."



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
