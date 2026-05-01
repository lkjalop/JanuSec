"""Threat model computation helpers for Tier-1 prefill.

Contains confidence scoring, Diamond model, PASTA summary, kill-chain helpers,
and adversarial sequence detection.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_CHAIN_ARROW = ' → '

# Canonical causal order for DREAD dimensions in a breach narrative.
_DREAD_CAUSAL_ORDER = [
    'damage', 'reproducibility', 'affected_users', 'exploitability', 'discoverability',
]

# Phase-role → readable label
_PHASE_ROLE_LABELS: dict[str, str] = {
    'initial_access':           'Initial Access',
    'session_theft':            'Session Theft',
    'credential_theft':         'Credential Theft',
    'credential_access':        'Credential Access',
    'privilege_escalation':     'Privilege Escalation',
    'privilege_escalation_k8s': 'K8s Container Escape',
    'secret_access':            'Secret/Key Abuse',
    'lateral_movement':         'Lateral Movement',
    'c2_communication':         'C2 Beaconing',
    'c2_dns_beacon':            'DNS C2 Beaconing',
    'data_exfiltration':        'Data Exfiltration',
    'data_exfiltration_snowflake': 'Snowflake Bulk Exfil',
    'data_exfiltration_rclone': 'Rclone Cloud Exfil',
    'persistence':              'Persistence',
    'collection':               'Collection',
    'execution':                'Execution',
}

# Ordered kill-chain position (lower = earlier in chain)
_PHASE_ORDER: dict[str, int] = {
    'initial_access': 0, 'session_theft': 1, 'credential_access': 2,
    'credential_theft': 3, 'secret_access': 4, 'privilege_escalation': 5,
    'privilege_escalation_k8s': 5, 'lateral_movement': 6, 'c2_communication': 7,
    'c2_dns_beacon': 7, 'persistence': 8, 'collection': 9, 'execution': 10,
    'data_exfiltration': 11, 'data_exfiltration_snowflake': 11,
    'data_exfiltration_rclone': 12,
}

# RFC1918 private prefixes — used by known/unknown entity split
_RFC1918 = ('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
            '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
            '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.')


# ── Confidence meter ───────────────────────────────────────────────────────────

def _compute_confidence_meter(cluster: dict, rows: list[dict]) -> dict:
    """Compute a 0-100 confidence score broken into 4 named segments.

    Re-uses the same factors as _cluster_routing_snapshot in deep_analyze_endpoints
    but computed locally so prefill_engine has no circular import.

    Segments (weights sum to 100):
      source_diversity  — 25: how many distinct source types are present
      evidence_quality  — 30: severity distribution of rows
      corroboration     — 25: multi-source coverage (identity + network + endpoint)
      pattern_match     — 20: cluster confidence field or row-count heuristic
    """
    _SEV_WEIGHTS = {'critical': 1.0, 'high': 0.75, 'medium': 0.5, 'low': 0.25}

    # Source diversity (25 pts): unique source types / expected 3
    sources = {str(r.get('_source') or r.get('source') or '') for r in rows if r}
    source_score = min(1.0, len(sources) / 3.0)

    # Evidence quality (30 pts): avg severity weight
    sev_scores = [
        _SEV_WEIGHTS.get(str(r.get('severity') or r.get('risk_level') or '').lower(), 0.1)
        for r in rows
    ]
    quality_score = sum(sev_scores) / max(1, len(sev_scores))

    # Corroboration (25 pts): identity + network + endpoint presence
    source_types: set[str] = set()
    for r in rows:
        src = str(r.get('_source') or r.get('source') or '').lower()
        if any(x in src for x in ('okta', 'entra', 'azure', 'identity', 'iam', 'auth')):
            source_types.add('identity')
        if any(x in src for x in ('net', 'bgp', 'c2', 'dns', 'firewall', 'nsg', 'flow')):
            source_types.add('network')
        if any(x in src for x in ('endpoint', 'edr', 'ep', 'carbon', 'defender', 'crowdstrike')):
            source_types.add('endpoint')
        if any(x in src for x in ('email', 'mail', 'mimecast', 'proofpoint', 'o365')):
            source_types.add('email')
    corroboration_score = min(1.0, len(source_types) / 3.0)

    # Pattern match (20 pts): existing cluster confidence or row-count heuristic
    existing_conf = cluster.get('confidence') or cluster.get('routing_score') or 0.0
    try:
        existing_conf = float(existing_conf)
    except (TypeError, ValueError):
        existing_conf = 0.0
    if existing_conf <= 0:
        row_count = len(rows)
        existing_conf = min(1.0, row_count / 10.0)
    pattern_score = min(1.0, existing_conf)

    total = round(
        (source_score * 25)
        + (quality_score * 30)
        + (corroboration_score * 25)
        + (pattern_score * 20),
        1,
    )

    return {
        'total': total,
        'segments': {
            'source_diversity': round(source_score * 25, 1),
            'evidence_quality': round(quality_score * 30, 1),
            'corroboration': round(corroboration_score * 25, 1),
            'pattern_match': round(pattern_score * 20, 1),
        },
        'source_types_present': sorted(source_types),
    }


# ── Authorized-engagement gate ────────────────────────────────────────────────

def _build_authorization_gate(cluster: dict):
    """
    Returns (is_authorized_ip, is_authorized_actor) — two callables that return
    True when an IP or actor belongs to a sanctioned engagement (pentest / red team)
    and must therefore be excluded from attacker-side Diamond facts.

    Reads from cluster metadata (injected by run_prefill at assessment level):
      _assessment_engagement_ip_ranges : list[str]  e.g. ["198.51.100.0/24"]
      _assessment_authorized_ips       : list[str]  exact-match IPs
      _assessment_engagement_actors    : list[str]  e.g. ["pentest-readonly-feb2026"]
      _assessment_engagement_refs      : list[str]  e.g. ["RH-ENG-2026-041"]

    Falls back to per-cluster keys when assessment-level keys are absent.
    """
    import ipaddress as _ipaddress

    def _get(key: str) -> list:
        # Assessment-level (injected union) wins; fall back to per-cluster key
        v = cluster.get('_assessment_' + key) or cluster.get(key) or []
        return [str(x).strip() for x in v if x]

    auth_ips     = set(_get('authorized_ips'))
    auth_actors  = {a.lower() for a in _get('engagement_actors')}
    eng_refs     = [r.lower() for r in _get('engagement_refs')]

    auth_networks: list = []
    for rng in _get('engagement_ip_ranges'):
        try:
            auth_networks.append(_ipaddress.ip_network(rng, strict=False))
        except (ValueError, TypeError):
            pass

    def is_authorized_ip(ip: str) -> bool:
        if not ip or ip in ('-', '0.0.0.0', ''):
            return False
        if ip in auth_ips:
            return True
        try:
            addr = _ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in net for net in auth_networks)

    def is_authorized_actor(actor: str) -> bool:
        if not actor:
            return False
        a = actor.strip().lower()
        if a in auth_actors:
            return True
        # Catch service-account names that embed the engagement ref as a substring
        return any(ref and ref in a for ref in eng_refs)

    return is_authorized_ip, is_authorized_actor


# ── Diamond model ──────────────────────────────────────────────────────────────

def _compute_diamond_model(cluster: dict, rows: list[dict]) -> dict:
    """Build the Diamond Threat Model struct for a breach cluster.

    Four corners:
      adversary    — who (inferred from: off-hours, external IP, no engagement_ref)
      capability   — how (tools/techniques from phase detectors + row content)
      infrastructure — where (external IPs, C2 domains, cloud buckets)
      victim       — what/who was targeted (users, hosts, data assets)
    """
    phases = cluster.get('phases') or []
    phase_ids = {p.get('phase_id') or '' for p in phases}
    row_text_all = ' '.join(
        ' '.join(str(v) for v in r.values() if isinstance(v, str))
        for r in rows
    ).lower()

    # Adversary
    engagement_refs = cluster.get('engagement_refs') or []
    change_refs = cluster.get('change_refs') or []
    if engagement_refs:
        adversary_type = f'Authorized penetration tester ({", ".join(engagement_refs)})'
    elif change_refs:
        adversary_type = f'Authorized change activity ({", ".join(change_refs)})'
    else:
        # Infer from signals
        signals: list[str] = []
        ts_vals = [float(r['_ts_epoch']) for r in rows if r.get('_ts_epoch')]
        if ts_vals:
            # Check for off-hours (02:00–06:00 UTC common for attacker ops)
            from datetime import datetime as _dt2
            off_hours = sum(1 for t in ts_vals if _dt2.utcfromtimestamp(t).hour in range(0, 7))
            if off_hours > len(ts_vals) * 0.4:
                signals.append('off-hours activity pattern')
        if any('getsecretvalue' in row_text_all or 'assumerole' in row_text_all for _ in [1]):
            signals.append('cloud API abuse without MFA/bastion')
        if 'rclone' in row_text_all or 'mega.nz' in row_text_all:
            signals.append('commodity exfil tooling')
        adversary_type = 'Unknown external threat actor' + (
            f' — signals: {"; ".join(signals)}' if signals else ''
        )

    # Capability (tools + techniques from phases + row content)
    capabilities: list[str] = []
    tool_map = [
        ('rclone', 'Rclone (cloud sync exfil)'),
        ('certutil', 'certutil (LOLBin payload delivery)'),
        ('mimikatz', 'Mimikatz (credential dumping)'),
        ('lsass', 'LSASS memory access (credential harvest)'),
        ('daemonset', 'K8s privileged DaemonSet (container escape)'),
        ('copy into', 'Snowflake COPY INTO (bulk data unload)'),
        ('getsecretvalue', 'AWS GetSecretValue (secrets theft)'),
        ('assumerole', 'AWS AssumeRole (privilege escalation)'),
        ('dns beacon', 'DNS beaconing (C2 channel)'),
        ('low reputation', 'NRD domain C2 infrastructure'),
        ('scheduled task', 'Scheduled task persistence'),
        ('mshta', 'mshta.exe (HTA payload execution)'),
    ]
    for term, label in tool_map:
        if term in row_text_all:
            capabilities.append(label)

    # ── Authorized-engagement gate ────────────────────────────────────────────
    _is_auth_ip, _is_auth_actor = _build_authorization_gate(cluster)

    # Infrastructure (external IPs + domains) — exclude authorized engagement ranges
    external_ips = sorted({
        str(r.get('src_ip') or '').strip()
        for r in rows
        if r.get('src_ip')
        and not any(str(r.get('src_ip', '')).startswith(p) for p in _RFC1918)
        and str(r.get('src_ip', '')).strip() not in ('', '-', '0.0.0.0')
        and not _is_auth_ip(str(r.get('src_ip', '')).strip())
    } | {
        str(r.get('dst_ip') or '').strip()
        for r in rows
        if r.get('dst_ip')
        and not any(str(r.get('dst_ip', '')).startswith(p) for p in _RFC1918)
        and str(r.get('dst_ip', '')).strip() not in ('', '-', '0.0.0.0')
        and not _is_auth_ip(str(r.get('dst_ip', '')).strip())
    })
    # Add cloud stage destinations if present
    infra: list[str] = list(external_ips[:6])
    for term, label in [('mega.nz', 'mega.nz (exfil staging)'), ('backblaze', 'Backblaze B2'),
                         ('s3://', 'Attacker-controlled S3 bucket'), ('hetzner', 'Hetzner VPS (AS24940)')]:
        if term in row_text_all:
            infra.append(label)

    # Victim (users + hosts + data) — split into typed buckets, exclude engagement actors
    _MACHINE_ID_RE = re.compile(
        r'(botocore|assumed-role|svc[-_]|service-account|'
        r'session-\d+|runner$|^i-[0-9a-f]{8,}|sts:|^arn:|'
        r'eks-integration|snowflake.*role|federation.*role)',
        re.IGNORECASE,
    )
    _SYSTEM_ACTORS = {'', '-', 'n/a', 'system', 'root', 'system:anonymous',
                      'system:unauthenticated', 'nt authority\\system'}

    raw_users = {
        str(r.get('user_canonical') or r.get('user') or '').strip()
        for r in rows
        if (r.get('user_canonical') or r.get('user'))
    }
    filtered_users = {
        u for u in raw_users
        if u.lower() not in _SYSTEM_ACTORS
        and not _is_auth_actor(u)
    }
    victim_humans   = sorted({u for u in filtered_users if not _MACHINE_ID_RE.search(u)})
    victim_machines = sorted({u for u in filtered_users if     _MACHINE_ID_RE.search(u)})
    victim_users    = victim_humans + victim_machines  # legacy union for existing consumers
    victim_hosts = sorted({
        str(r.get('hostname') or r.get('host') or '').strip().lower()
        for r in rows if r.get('hostname') or r.get('host')
    } - {'', '-'})
    victim_data: list[str] = []
    for sig, label in [('manifest', 'port scheduling manifests'), ('customer', 'customer records'),
                        ('vault', 'secrets vault'), ('kubelet', 'kubelet token'),
                        ('lsass', 'LSASS credential material'), ('snowflake', 'Snowflake data warehouse')]:
        if sig in row_text_all:
            victim_data.append(label)

    return {
        'adversary':       adversary_type,
        'capability':      capabilities[:8] or ['Unknown TTPs'],
        'infrastructure':  infra[:8] or ['No external infrastructure identified'],
        'victim_users':    victim_users[:8],    # legacy — union of humans + machines
        'victim_humans':   victim_humans[:6],   # new — named human accounts only
        'victim_machines': victim_machines[:6], # new — service/machine identities
        'victim_hosts':    victim_hosts[:6],
        'victim_data':     victim_data[:6] or ['Unknown — insufficient data type metadata'],
    }


# ── PASTA summary ──────────────────────────────────────────────────────────────

def _compute_pasta_summary(cluster: dict, rows: list[dict], data: dict) -> dict:
    """Build PASTA stages 4-7 deterministic summary (LLM writes prose from this).

    Stage 4: Threat Analysis — who / what type of actor
    Stage 5: Vulnerability — what was exploited + what data type was at risk
    Stage 6: Attack Model — reference to event_chain_summary (already computed)
    Stage 7: Risk & Impact — what business consequence
    """
    diamond = data.get('diamond_model') or {}
    dread = data.get('dread_score') or {}
    phases = cluster.get('phases') or []
    phase_ids = {p.get('phase_id') or '' for p in phases}
    row_text_all = ' '.join(
        ' '.join(str(v) for v in r.values() if isinstance(v, str))
        for r in rows
    ).lower()

    # Stage 4: Threat profile
    adversary = diamond.get('adversary') or 'Unknown external actor'
    # Map TTPs to actor archetypes
    if any(t in row_text_all for t in ('nation', 'apt', 'state-sponsored')):
        actor_archetype = 'Nation-state / APT actor'
    elif any(t in row_text_all for t in ('ransomware', 'ransom', 'extortion')):
        actor_archetype = 'Ransomware operator / criminal group'
    elif any(t in row_text_all for t in ('insider', 'employee', 'disgruntled')):
        actor_archetype = 'Malicious insider'
    elif any(p in phase_ids for p in ('data_exfiltration_snowflake', 'secret_access')):
        actor_archetype = 'Financially motivated cybercriminal (cloud-targeting)'
    else:
        actor_archetype = 'Opportunistic external attacker'

    threat_profile = f'{actor_archetype}. {adversary}.'

    # Stage 5: Vulnerability + data type
    vuln_parts: list[str] = []
    if 'session_theft' in phase_ids:
        vuln_parts.append('stolen authentication token (no hardware MFA or session binding)')
    if 'credential_theft' in phase_ids:
        vuln_parts.append('harvested credentials from LSASS memory dump')
    if 'initial_access' in phase_ids and 'session_theft' not in phase_ids and 'credential_theft' not in phase_ids:
        vuln_parts.append('phishing / social engineering (user-delivered payload)')
    if 'privilege_escalation_k8s' in phase_ids:
        vuln_parts.append('misconfigured Kubernetes RBAC (privileged DaemonSet allowed)')
    if 'secret_access' in phase_ids:
        vuln_parts.append('AWS IAM over-permissioned role (AssumeRole + GetSecretValue without MFA)')

    # Data type at risk
    data_types: list[str] = []
    for sig, label in [('manifest', 'logistics/shipping manifests (PII)'), ('customer', 'customer PII'),
                        ('vault', 'cryptographic secrets and API keys'), ('lsass', 'Windows credential hashes'),
                        ('snowflake', 'cloud data warehouse contents'), ('health', 'health records (PHI)')]:
        if sig in row_text_all:
            data_types.append(label)
    if not data_types:
        data_types = ['corporate operational data']

    exploitation_path = ('. '.join(vuln_parts) + '. ') if vuln_parts else 'Exploitation path unclear — insufficient telemetry.'
    exploitation_path += f'Data at risk: {", ".join(data_types[:3])}.'

    # Stage 7: Business impact
    risk_tier = dread.get('risk_tier') or 'HIGH'
    sabsa_attrs = (data.get('dread_narrative') or {}).get('sabsa_attributes') or []

    impact_parts: list[str] = []
    if 'data_exfiltration_snowflake' in phase_ids or 'data_exfiltration_rclone' in phase_ids:
        impact_parts.append('confirmed data exfiltration — regulatory notification obligation likely')
    if 'Confidential' in sabsa_attrs:
        impact_parts.append('confidentiality breach — data may already be in adversary hands')
    if 'Authenticated' in sabsa_attrs:
        impact_parts.append('credential compromise — all affected accounts must be rotated')
    if 'privilege_escalation_k8s' in phase_ids:
        impact_parts.append('full cluster node compromise — container workloads must be treated as untrusted')
    if not impact_parts:
        impact_parts = [f'{risk_tier} risk rating — business impact requires analyst investigation']

    business_impact = '. '.join(impact_parts[:3]) + '.'

    return {
        'threat_profile': threat_profile,
        'exploitation_path': exploitation_path,
        'attack_model_ref': 'event_chain_summary',  # points to already-computed field
        'business_impact': business_impact,
        'risk_tier': risk_tier,
    }


# ── Adversarial sequence detection ────────────────────────────────────────────

def _detect_adversarial_sequence(phases: list[dict], rows: list[dict]) -> tuple[bool, str]:
    """Return (flag, detail) when a known-adversarial phase sequence is present.

    Adversarial sequence criteria (any one sufficient):
    - secret_access + data_exfiltration in cluster phases (key abuse → exfil)
    - session_theft + privilege_escalation (token replay → priv esc)
    - credential_theft + lateral_movement (cred dump → spread)
    """
    phase_ids = {p.get('phase_id') or p.get('case_role') or '' for p in phases}

    if ('secret_access' in phase_ids and
            any(p in phase_ids for p in ('data_exfiltration_snowflake', 'data_exfiltration_rclone', 'data_exfiltration'))):
        return True, 'Secret/key access followed by bulk data exfiltration in same campaign window'

    if 'session_theft' in phase_ids and 'privilege_escalation_k8s' in phase_ids:
        return True, 'Stolen session token used to escalate into privileged container context'

    if 'credential_theft' in phase_ids and 'lateral_movement' in phase_ids:
        return True, 'Credential dump followed by lateral movement — classic pass-the-hash pattern'

    if 'session_theft' in phase_ids and 'secret_access' in phase_ids:
        return True, 'Stolen session used to access secrets — token replay into key vault'

    return False, ''


# ── Entity split ───────────────────────────────────────────────────────────────

def _split_entities(cluster: dict, rows: list[dict]) -> tuple[list[str], list[str]]:
    """Split entity set into known (internal/expected) and unknown (external/first-seen).

    Rules (no enrichment context needed):
    - Internal IPs (RFC1918) → known
    - External IPs → unknown
    - svc_ / system / machine accounts → known
    - Human accounts with email format → known (legitimate employees)
    - External-looking IPs in cloud trail (attacker origin) → unknown
    """
    known: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()

    engagement_refs = cluster.get('engagement_refs') or []
    change_refs = cluster.get('change_refs') or []

    for r in rows:
        for fld in ('src_ip', 'dst_ip'):
            ip = str(r.get(fld) or '').strip()
            if ip and ip not in seen and ip not in ('-', '0.0.0.0', ''):
                seen.add(ip)
                if any(ip.startswith(p) for p in _RFC1918):
                    known.append(f'IP {ip} (internal)')
                else:
                    unknown.append(f'IP {ip} (external — first-seen)')

        user = str(r.get('user_canonical') or r.get('user') or '').strip().lower()
        if user and user not in seen and user not in ('-', 'n/a', 'system', 'root', ''):
            seen.add(user)
            if any(user.startswith(p) for p in ('svc_', 'sa-', 'service-', 'msol', 'aadconnect')):
                known.append(f'Account {user} (service account)')
            elif engagement_refs and any(er.lower() in user for er in engagement_refs):
                known.append(f'Account {user} (pentest operator)')
            elif change_refs:
                known.append(f'Account {user} (change-managed)')
            elif '.' in user or '@' in user:
                known.append(f'Account {user} (named employee)')
            else:
                unknown.append(f'Account {user} (unrecognised principal)')

        host = str(r.get('hostname') or r.get('host') or '').strip().lower()
        if host and host not in seen:
            seen.add(host)
            if host.startswith(('sfl-', 'corp-', 'wks-', 'srv-', 'dc-', 'ws-')):
                known.append(f'Host {host} (corporate asset)')
            else:
                unknown.append(f'Host {host} (unrecognised asset)')

    # Cap to keep prompt concise
    return known[:12], unknown[:12]


# ── Kill chain helpers ─────────────────────────────────────────────────────────

def _build_kill_chain_summary(phases: list[dict]) -> str:
    """Render phase list as 'Initial Access → Credential Theft → … → Exfil' string."""
    if not phases:
        return ''
    ordered = sorted(phases, key=lambda p: _PHASE_ORDER.get(p.get('phase_id') or p.get('case_role') or '', 99))
    labels: list[str] = []
    seen: set[str] = set()
    for p in ordered:
        role = p.get('phase_id') or p.get('case_role') or ''
        label = _PHASE_ROLE_LABELS.get(role, role.replace('_', ' ').title())
        if label and label not in seen:
            labels.append(label)
            seen.add(label)
    return ' → '.join(labels) if labels else ''


def _order_fragments_temporally(
    fragments: dict[str, str | None],
) -> list[tuple[str, str]]:
    """
    Return (dim_label, fragment_text) pairs in causal order, skipping None.
    Used to build the temporal-sequence block in the render prompt.
    """
    ordered: list[tuple[str, str]] = []
    for dim in _DREAD_CAUSAL_ORDER:
        val = fragments.get(dim)
        if val:
            ordered.append((dim.replace('_', ' ').upper(), val))
    # Any dimension not in the canonical order (future-proofing) appended last
    for dim, val in fragments.items():
        if dim not in _DREAD_CAUSAL_ORDER and val:
            ordered.append((dim.replace('_', ' ').upper(), val))
    return ordered
