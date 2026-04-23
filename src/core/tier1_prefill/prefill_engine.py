"""Tier-1 prefill engine.

Runs qwen2.5:14b on the top-N clusters by severity rank after correlation
completes. Writes results to cluster['tier1_prefill'] on the assessment
artifact and re-persists to disk.

Concurrency: uses generate_batch (ThreadPoolExecutor) — fires N HTTP calls
to Ollama simultaneously. Local Ollama serializes under the hood, so true
wall time is N × ~6s. Caller should treat the estimate honestly.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

# ── Enhancement 1: Entity pin quality gate ────────────────────────────────────

def _extract_entity_set(cluster: dict, rows: list[dict]) -> set[str]:
    """Build the bounded entity set allowed for this cluster."""
    entities: set[str] = set()
    for r in rows:
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity',
                  'src_ip', 'source_ip', 'dst_ip', 'destination_ip',
                  'hostname', 'host', 'src_host', 'device_name'):
            v = str(r.get(f) or '').strip().lower()
            if v and v not in ('-', 'n/a', ''):
                entities.add(v)
    for f in ('mitre_technique', 'mitre', 'technique_id'):
        v = r.get(f)
        if isinstance(v, list):
            entities.update(str(x).lower() for x in v if x)
        elif v:
            entities.add(str(v).lower())
    # Add cluster ID itself
    entities.add(str(cluster.get('cluster_id') or '').lower())
    return entities


def _validate_entity_pins(prefill: dict, allowed: set[str]) -> dict:
    """Check that T1 output doesn't reference entities outside the allowed set.

    Scans incident_name, headline_subtitle, short_narrative, top_actions for
    capitalised multi-word tokens that look like proper nouns but don't appear
    in the allowed set. Returns a quality report.
    """
    # Tokens that are known safe generic security words — never flag these
    _GENERIC_OK = {
        'credential', 'spray', 'mfa', 'fatigue', 'pivot', 'lateral', 'movement',
        'persistence', 'exfiltration', 'bec', 'worm', 'supply', 'chain',
        'compromise', 'phishing', 'ransomware', 'c2', 'beacon', 'attacker',
        'adversary', 'threat', 'actor', 'malicious', 'suspicious', 'anomalous',
        'identity', 'network', 'endpoint', 'cloud', 'azure', 'okta', 'aws',
        'mitre', 'att&ck', 'high', 'medium', 'low', 'critical', 'confirmed',
        'likely', 'uncertain', 'benign', 'soc', 'analyst', 'hunter', 'forensics',
        'imap4', 'smtp', 'bcc', 'dns', 'kql', 'spl', 'edr', 'siem', 'ngfw',
    }

    # Scan text fields for suspicious capitalised tokens
    text_to_scan = ' '.join([
        prefill.get('incident_name', ''),
        prefill.get('headline_subtitle', ''),
        prefill.get('short_narrative', ''),
        ' '.join(prefill.get('top_actions', [])),
    ])

    # Extract proper-noun-like tokens: CamelCase, ALL_CAPS, or email-like strings
    candidate_tokens = re.findall(
        r'\b([A-Z][a-z]{2,}\.[A-Za-z]{2,}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
        r'|[A-Z]{2,}[-_][A-Z0-9]{2,}|[A-Z][A-Z0-9]{3,})\b',
        text_to_scan,
    )

    flagged: list[str] = []
    for token in candidate_tokens:
        tl = token.lower()
        if tl in _GENERIC_OK:
            continue
        # Check if this token (or a substring) is in the allowed entity set
        matched = any(
            tl in entity or entity in tl
            for entity in allowed
            if len(entity) > 3
        )
        if not matched:
            flagged.append(token)

    passed = len(flagged) == 0
    return {
        'passed': passed,
        'flagged_tokens': list(set(flagged)),
        'checked_at': int(time.time()),
    }


# ── Enhancement 2: Heuristic confidence meter ─────────────────────────────────

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


# ── Enhancement 3: Cross-cluster entity linkage ───────────────────────────────

def _build_entity_cluster_index(clusters: list[dict], assessment: dict) -> dict[str, list[str]]:
    """Map entity_value → [cluster_ids that contain that entity]."""
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_by_index: dict[int, dict] = {
        (r['row_index'] if 'row_index' in r else r.get('row_number', -1)): r
        for r in all_rows
    }

    index: dict[str, list[str]] = {}  # entity_lower → [cluster_id, ...]
    for cluster in clusters:
        cid = cluster.get('cluster_id', '')
        for ref in (cluster.get('row_refs') or []):
            row = row_by_index.get(ref, {})
            for f in ('user', 'user_principal_name', 'username', 'account',
                      'src_ip', 'source_ip', 'hostname', 'host'):
                v = str(row.get(f) or '').strip().lower()
                if v and v not in ('-', 'n/a', '', 'none'):
                    index.setdefault(v, [])
                    if cid not in index[v]:
                        index[v].append(cid)
    return index


def _compute_cross_cluster_links(
    cluster: dict,
    entity_index: dict[str, list[str]],
    clusters: list[dict],
) -> list[dict]:
    """Return list of {entity, also_in_cluster_id, also_in_incident_name} for shared entities."""
    cid = cluster.get('cluster_id', '')
    links: list[dict] = []
    seen: set[str] = set()

    # Build incident name lookup from tier1_prefill if available
    incident_by_cid: dict[str, str] = {}
    for c in clusters:
        p = c.get('tier1_prefill') or {}
        incident_by_cid[c.get('cluster_id', '')] = p.get('incident_name') or c.get('cluster_id', '')

    for entity, cluster_ids in entity_index.items():
        if cid not in cluster_ids:
            continue
        other_ids = [c for c in cluster_ids if c != cid]
        for other_id in other_ids:
            key = f"{entity}::{other_id}"
            if key not in seen:
                seen.add(key)
                links.append({
                    'entity': entity,
                    'also_in_cluster_id': other_id,
                    'also_in_incident_name': incident_by_cid.get(other_id, other_id),
                })

    return links[:10]  # cap at 10 to avoid overwhelming the card

# Config flag — set to False in tests to skip actual LLM calls
PREFILL_ENABLED = True
PREFILL_DEFAULT_MODEL = 'qwen3:30b'
PREFILL_TOP_N = 3
PREFILL_MAX_TOKENS = 1500
PREFILL_TIMEOUT_S = 45


def _rank_clusters(clusters: list[dict]) -> list[dict]:
    """Sort clusters: confirmed > likely > uncertain > benign, then by row count."""
    verdict_rank = {
        'CONFIRMED': 5,
        'LIKELY REAL': 4,
        'LIKELY': 4,
        'UNCERTAIN': 3,
        'BENIGN': 1,
    }

    def _score(c: dict) -> tuple[int, int, int]:
        verdict = str(c.get('verdict') or c.get('final_verdict') or '').upper()
        vr = max((verdict_rank[k] for k in verdict_rank if k in verdict), default=2)
        sr = _SEV_RANK.get(str(c.get('severity') or '').lower(), 0)
        rc = len(c.get('row_refs') or [])
        return (vr, sr, rc)

    return sorted(clusters, key=_score, reverse=True)


def _get_rows_for_cluster(cluster: dict, assessment: dict) -> list[dict]:
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    if not refs:
        return list(cluster.get('evidence_preview') or [])
    matched = [r for r in all_rows
               if r.get('row_index') in refs or r.get('row_number') in refs]
    preview = [r for r in (cluster.get('evidence_preview') or []) if isinstance(r, dict)]
    if matched:
        if preview and len({
            _row_ref(r) for r in matched if _row_ref(r) is not None
        }) < min(len(refs), len(preview)):
            seen = {_row_ref(r) for r in matched if _row_ref(r) is not None}
            merged = list(matched)
            for row in preview:
                ref = _row_ref(row)
                if ref is not None and ref in seen:
                    continue
                if ref is not None:
                    seen.add(ref)
                merged.append(row)
            return merged
        return matched
    # normalized_rows/evidence_rows are a sample that may not overlap with
    # this cluster's row_refs — fall back to the pre-sampled evidence_preview
    # which is always indexed against the cluster's actual row_refs.
    return preview


_JARGON_PATTERNS = [
    re.compile(r'\bT\d{4}(\.\d{3})?\b'),           # MITRE T-codes e.g. T1110.003
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # raw IPv4
    re.compile(r'\b(sourcetype|index|host)\s*='),   # Splunk SPL
    re.compile(r'\b(SecurityEvent|SigninLogs|AuditLogs)\s*\|'),  # KQL table pipes
]

_NEW_SCHEMA_PASS_THROUGH = {
    'what_happened', 'root_cause', 'evidence_chain', 'observed_impact',
    'evidence_gaps', 'immediate_actions',
}


def _narrative_is_technical(text: str) -> bool:
    """Return True if text contains jargon that belongs in evidence fields, not narratives."""
    if not isinstance(text, str):
        return False
    return any(p.search(text) for p in _JARGON_PATTERNS)


def _parse_prefill_json(raw: str, cluster_id: str) -> dict | None:
    """Extract JSON from LLM response, tolerating markdown fences.

    Required fields are the original 6 (backward compat).
    New v2 schema fields (what_happened, root_cause, evidence_chain, observed_impact,
    evidence_gaps, immediate_actions) are optional pass-throughs.
    The 'reasoning' CoT scratchpad is stripped from display payload -> _cot.
    """
    text = raw.strip()
    # Strip markdown code fences
    if text.startswith('```'):
        lines = text.split('\n')
        text = '\n'.join(
            l for l in lines
            if not l.strip().startswith('```')
        ).strip()
    try:
        data = json.loads(text)
        required = {'incident_name', 'headline_subtitle', 'short_narrative',
                    'confidence_rationale', 'top_actions', 'mitre_techniques'}
        if required.issubset(data.keys()):
            # Move CoT scratchpad out of display payload
            cot = data.pop('reasoning', None)
            if cot:
                data['_cot'] = cot
            # Normalise mitre_evidence_map — ensure int keys are str
            mem = data.get('mitre_evidence_map')
            if isinstance(mem, dict):
                data['mitre_evidence_map'] = {
                    str(k): [int(i) for i in (v if isinstance(v, list) else [])]
                    for k, v in mem.items()
                }
            # Coerce evidence_chain[].row_refs to int — LLM may emit strings
            for step in (data.get('evidence_chain') or []):
                if isinstance(step, dict) and isinstance(step.get('row_refs'), list):
                    step['row_refs'] = [
                        int(r) for r in step['row_refs']
                        if str(r).lstrip('-').isdigit()
                    ]
            # Jargon detection on narrative fields — flag but don't drop
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
        logger.warning('tier1_prefill: missing keys in response for %s', cluster_id)
        return None
    except Exception as exc:
        logger.warning('tier1_prefill: JSON parse failed for %s: %s', cluster_id, exc)
        return None


def _row_ref(row: dict) -> int | None:
    for key in ('row_index', 'row_number'):
        value = row.get(key)
        try:
            return int(value)
        except Exception:
            continue
    return None


def _field_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, dict):
        if value.get('username'):
            return str(value.get('username'))
        if value.get('resource') or value.get('namespace') or value.get('subresource'):
            return '/'.join(
                str(value.get(k))
                for k in ('resource', 'subresource', 'namespace', 'name')
                if value.get(k)
            )
        try:
            return json.dumps(value, sort_keys=True)
        except Exception:
            return str(value)
    return str(value)


def _row_time(row: dict) -> str:
    for key in (
        'timestamp_utc', 'timestamp', '@timestamp', 'event_ts', 'event_time',
        'start_time', 'end_time', 'published', 'created', 'time', 'ts',
    ):
        value = row.get(key)
        if value not in (None, ''):
            return str(value)
    return ''


def _row_actor(row: dict) -> str:
    for key in ('user_principal_name', 'username', 'user_name', 'UserId', 'user', 'account', 'actor', 'hostname', 'host'):
        value = row.get(key)
        if value not in (None, ''):
            return _field_text(value)
    return 'affected entity'


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
    for row in sorted_rows[:100]:
        p = _phase(row)
        if p and (not phases or phases[-1] != p):
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

    seq_str = ' → '.join(phases[:12])
    out = f"{len(unique)} distinct phase(s): {seq_str}"
    if pattern:
        out += f"\nPattern: {pattern}"
    return out


def _detect_row_source(row: dict) -> str:
    """Identify the data source for a row based on characteristic fields."""
    explicit = str(row.get('_source') or row.get('source') or '').lower()
    if explicit:
        for token in ('okta', 'entra', 'azure_ad', 'aad'):
            if token in explicit:
                return 'okta'
        for token in ('m365', 'sharepoint', 'teams', 'exchange', 'o365', 'office365'):
            if token in explicit:
                return 'm365'
        for token in ('proofpoint', 'mimecast', 'email', 'mail'):
            if token in explicit:
                return 'email'
        for token in ('zeek', 'network', 'bro', 'netflow', 'pcap'):
            if token in explicit:
                return 'network'
        for token in ('crowdstrike', 'falcon', 'edr', 'endpoint'):
            if token in explicit:
                return 'edr'
        for token in ('cloudtrail', 'aws', 'guardduty'):
            if token in explicit:
                return 'aws'
        for token in ('snowflake', 'database', 'query_history'):
            if token in explicit:
                return 'data'
        for token in ('sailpoint', 'iam'):
            if token in explicit:
                return 'iam'

    # Heuristic: characteristic field presence
    if row.get('displayName') or row.get('activityDisplayName') or row.get('userPrincipalName'):
        return 'okta'
    if row.get('Workload') or row.get('Operation') or row.get('ClientIP') or row.get('SiteUrl'):
        return 'm365'
    if row.get('email_from') or row.get('sender') or row.get('email_subject') or row.get('dkim_result'):
        return 'email'
    if row.get('proto') or row.get('ja3') or row.get('ja4') or row.get('orig_bytes') or row.get('ts') and row.get('id.orig_h'):
        return 'network'
    if row.get('event_simpleName') or row.get('CommandLine') or row.get('SHA256HashData'):
        return 'edr'
    if row.get('eventName') or row.get('awsRegion') or row.get('userIdentity'):
        return 'aws'
    if row.get('query_text') or row.get('query_type') or row.get('warehouse_name') or row.get('database_name'):
        return 'data'
    return 'generic'


def _row_action_text(row: dict) -> str:
    """Produce a human-readable sentence describing what this row represents.

    Source-aware: extracts the most meaningful fields per data source so that
    the attack timeline reads as specific observations, not generic boilerplate.
    """
    src = _detect_row_source(row)

    def _s(v) -> str:
        return _field_text(v).strip() if v not in (None, '') else ''

    def _trunc(s: str, n: int = 120) -> str:
        s = re.sub(r'\s+', ' ', s).strip()
        return s[:n] + '…' if len(s) > n else s

    # ── Okta / Entra ID / Azure AD ───────────────────────────────────────────
    if src == 'okta':
        event = _s(row.get('activityDisplayName') or row.get('displayName') or row.get('event_type') or '')
        user = _s(row.get('user_principal_name') or row.get('userPrincipalName') or row.get('username') or '')
        result = _s(row.get('outcome_result') or row.get('result') or row.get('outcome') or '')
        ip = _s(row.get('source_ip') or row.get('client_ip') or row.get('ipAddress') or '')
        device = _s(row.get('device_name') or row.get('deviceDetail_displayName') or '')
        geo = row.get('_geo') or {}
        location = _s(geo.get('city') or geo.get('country') or '')
        geo_ctx = row.get('context') or {}
        if isinstance(geo_ctx, dict):
            g = geo_ctx.get('geographicalContext') or {}
            if isinstance(g, dict):
                location = location or _s(g.get('city') or g.get('country') or '')

        parts = []
        if event:
            parts.append(event)
        if user:
            parts.append(f"user: {user}")
        if result:
            parts.append(f"result: {result.upper()}")
        if ip:
            parts.append(f"from: {ip}")
        if location:
            parts.append(f"({location})")
        if device:
            parts.append(f"device: {device}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Okta authentication event.'

    # ── Microsoft 365 (SharePoint, Teams, Exchange, OneDrive) ────────────────
    if src == 'm365':
        operation = _s(row.get('Operation') or row.get('operation') or row.get('activityDisplayName') or '')
        user = _s(row.get('UserId') or row.get('user_principal_name') or '')
        workload = _s(row.get('Workload') or row.get('workload') or '')
        obj = _s(row.get('ObjectId') or row.get('object_id') or row.get('SiteUrl') or '')
        client_ip = _s(row.get('ClientIP') or row.get('client_ip') or '')
        target = _s(row.get('TargetUserOrGroupName') or '')

        parts = []
        if workload:
            parts.append(f"[{workload}]")
        if operation:
            parts.append(operation)
        if obj:
            # Show just the filename/leaf, not full URL
            leaf = obj.split('/')[-1] or obj
            parts.append(f"→ {_trunc(leaf, 60)}")
        if user:
            parts.append(f"user: {user}")
        if target:
            parts.append(f"target: {target}")
        if client_ip:
            parts.append(f"from: {client_ip}")
        if parts:
            return _trunc(' '.join(parts))
        return 'Microsoft 365 activity event.'

    # ── Email (Proofpoint, Mimecast) ─────────────────────────────────────────
    if src == 'email':
        sender = _s(row.get('email_from') or row.get('sender') or row.get('from_address') or '')
        recipient = _s(row.get('email_to') or row.get('recipient') or row.get('to_address') or '')
        subject = _s(row.get('email_subject') or row.get('subject') or '')
        disposition = _s(row.get('disposition') or row.get('action') or row.get('verdict') or '')
        domain = _s(row.get('sender_domain') or '')
        url = _s(row.get('url_clicked') or row.get('threat_url') or '')

        parts = []
        if disposition:
            parts.append(f"[{disposition.upper()}]")
        if sender:
            parts.append(f"from: {sender}")
        elif domain:
            parts.append(f"domain: {domain}")
        if recipient:
            parts.append(f"to: {recipient}")
        if subject:
            parts.append(f"subject: \"{_trunc(subject, 60)}\"")
        if url:
            parts.append(f"url: {_trunc(url, 60)}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Email event.'

    # ── Network (Zeek/Bro, Netflow, PCAP) ───────────────────────────────────
    if src == 'network':
        proto = _s(row.get('proto') or row.get('protocol') or '')
        src_ip = _s(row.get('id.orig_h') or row.get('src_ip') or row.get('source_ip') or '')
        dst_ip = _s(row.get('id.resp_h') or row.get('dst_ip') or row.get('dest_ip') or row.get('remote_address') or '')
        dst_port = str(row.get('id.resp_p') or row.get('dst_port') or row.get('dest_port') or '')
        ja3 = _s(row.get('ja3') or row.get('ja3s') or '')
        ja4 = _s(row.get('ja4') or '')
        bytes_out = row.get('orig_bytes') or row.get('bytes_sent') or row.get('bytes') or 0
        sni = _s(row.get('server_name') or row.get('sni') or '')
        conn_type = _s(row.get('conn_state') or '')

        parts = []
        if proto:
            parts.append(proto.upper())
        if src_ip:
            parts.append(f"{src_ip}")
        if dst_ip:
            dst_str = dst_ip + (f":{dst_port}" if dst_port else '')
            parts.append(f"→ {dst_str}")
        if sni:
            parts.append(f"SNI: {sni}")
        if ja3:
            parts.append(f"JA3: {ja3[:16]}…" if len(ja3) > 16 else f"JA3: {ja3}")
        elif ja4:
            parts.append(f"JA4: {ja4[:16]}…" if len(ja4) > 16 else f"JA4: {ja4}")
        try:
            b = int(bytes_out)
            if b > 1_000_000_000:
                parts.append(f"{b / 1e9:.1f}GB out")
            elif b > 1_000_000:
                parts.append(f"{b / 1e6:.1f}MB out")
            elif b > 0:
                parts.append(f"{b:,}B out")
        except Exception:
            pass
        if parts:
            return _trunc(' · '.join(parts))
        return 'Network connection event.'

    # ── EDR (CrowdStrike Falcon, SentinelOne) ────────────────────────────────
    if src == 'edr':
        event_name = _s(row.get('event_simpleName') or row.get('EventType') or '')
        process = _s(row.get('FileName') or row.get('process_name') or row.get('ImageFileName') or '')
        cmdline = _s(row.get('CommandLine') or row.get('command_line') or '')
        host = _s(row.get('ComputerName') or row.get('hostname') or row.get('host') or '')
        user = _s(row.get('UserName') or row.get('username') or '')
        sha = _s(row.get('SHA256HashData') or row.get('sha256') or '')

        parts = []
        if event_name:
            parts.append(event_name)
        if process:
            parts.append(f"process: {process}")
        if user:
            parts.append(f"user: {user}")
        if host:
            parts.append(f"host: {host}")
        if cmdline:
            parts.append(f"cmd: {_trunc(cmdline, 80)}")
        if sha:
            parts.append(f"sha256: {sha[:16]}…")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Endpoint detection event.'

    # ── AWS CloudTrail ───────────────────────────────────────────────────────
    if src == 'aws':
        event = _s(row.get('eventName') or '')
        service = _s(row.get('eventSource') or '')
        region = _s(row.get('awsRegion') or '')
        identity = row.get('userIdentity') or {}
        principal = _s(identity.get('principalId') or identity.get('arn') or '' if isinstance(identity, dict) else '')
        src_ip = _s(row.get('sourceIPAddress') or '')
        error = _s(row.get('errorCode') or '')

        parts = []
        if service:
            parts.append(f"[{service.replace('.amazonaws.com', '')}]")
        if event:
            parts.append(event)
        if error:
            parts.append(f"ERROR: {error}")
        if principal:
            parts.append(f"principal: {_trunc(principal, 50)}")
        if region:
            parts.append(f"region: {region}")
        if src_ip:
            parts.append(f"from: {src_ip}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'AWS CloudTrail event.'

    if src == 'data':
        qtype = _s(row.get('query_type') or row.get('operation') or '')
        user = _s(row.get('user_name') or row.get('user') or row.get('username') or '')
        db = _s(row.get('database_name') or row.get('schema_name') or '')
        app = _s(row.get('client_application_id') or '')
        ip = _s(row.get('client_ip') or row.get('source_ip') or '')
        query = _s(row.get('query_text') or '')
        rows_out = _s(row.get('rows_produced') or '')
        bytes_scanned = _s(row.get('bytes_scanned') or '')

        parts = []
        if qtype:
            parts.append(qtype.upper())
        if user:
            parts.append(f"user: {user}")
        if db:
            parts.append(f"db: {db}")
        if query:
            parts.append(f"query: {_trunc(query, 80)}")
        if rows_out:
            parts.append(f"rows: {rows_out}")
        if bytes_scanned:
            parts.append(f"bytes scanned: {bytes_scanned}")
        if ip:
            parts.append(f"from: {ip}")
        if app:
            parts.append(f"app: {_trunc(app, 40)}")
        if parts:
            return _trunc(' · '.join(parts))
        return 'Data platform query event.'

    # ── Generic fallback — still better than a fixed string ──────────────────
    for key in (
        'description', 'summary', 'email_body_summary',
        'event_type', 'activityDisplayName', 'eventName', 'operationName',
        'event_simpleName', 'process_name', 'query_text', 'dns_query', 'notes',
    ):
        value = row.get(key)
        if value not in (None, ''):
            text = _field_text(value).strip()
            if text:
                return _trunc(text)
    # Last resort: build something from whatever entity fields exist
    actor = _row_actor(row)
    src_ip = _s(row.get('src_ip') or row.get('source_ip') or row.get('remote_address') or '')
    event_type = _s(row.get('event_type') or row.get('type') or '')
    parts = [p for p in [event_type or 'Security event', f"actor: {actor}" if actor != 'affected entity' else '', f"from: {src_ip}" if src_ip else ''] if p]
    return _trunc(' · '.join(parts)) if parts else 'Security telemetry event.'


def _fallback_incident_name(cluster: dict, rows: list[dict]) -> str:
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


def _build_fallback_evidence_chain(rows: list[dict]) -> list[dict]:
    if not rows:
        return []

    def sort_key(row: dict):
        return (_row_time(row), _row_ref(row) if _row_ref(row) is not None else 10**9)

    selected: list[dict] = []
    seen_refs: set[int] = set()
    for row in sorted(rows, key=sort_key):
        ref = _row_ref(row)
        if ref in seen_refs:
            continue
        text = _row_action_text(row)
        if not text:
            continue
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
            'why_significant': (
                f"Corroborates {technique} in the incident sequence."
                if technique else
                'Provides a timestamped evidence point for the incident sequence.'
            ),
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


def _build_fallback_actions(data: dict) -> list[dict]:
    actions = data.get('top_actions') or []
    if not isinstance(actions, list):
        return []
    result: list[dict] = []
    for idx, action in enumerate(actions[:5], start=1):
        title = str(action).strip()
        if not title:
            continue
        result.append({
            'priority': f'P{min(idx, 3)}',
            'persona': 'SOC',
            'title': title,
            'subtasks': [
                {
                    'label': 'Record the evidence rows used for this action.',
                    'tool_command': '',
                    'expected_finding': 'Action is grounded in the displayed cluster evidence.',
                }
            ],
        })
    return result


def _infer_mitre_techniques(cluster: dict, rows: list[dict]) -> list[str]:
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


def _ensure_v2_prefill_fields(data: dict, cluster: dict, rows: list[dict]) -> dict:
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

    # Replace raw verdict code labels with an evidence-based narrative
    _VERDICT_CODE_RE = re.compile(r'^[A-Z][A-Z_]{3,}$')
    vr = str(data.get('verdict_reasoning') or '').strip()
    if not vr or _VERDICT_CODE_RE.match(vr):
        verdict = str(cluster.get('final_verdict') or cluster.get('verdict') or '').strip()
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
        elif verdict == 'BENIGN_EXPECTED':
            benign_parts = [root] if root else []
            if actors and 'No named' not in actors:
                benign_parts.append(f'Associated accounts: {actors}.')
            data['verdict_reasoning'] = ' '.join(benign_parts) or 'Activity matches expected or authorized patterns across correlated sources.'
        else:
            data['verdict_reasoning'] = root or 'Correlated evidence requires further analyst investigation.'

    return data


def run_prefill(
    assessment: dict[str, Any],
    top_n: int = PREFILL_TOP_N,
    model: str = PREFILL_DEFAULT_MODEL,
    tenant_id: str = 'default',
) -> dict[str, Any]:
    """Run Tier-1 prefill on the top_n clusters of the given assessment.

    Mutates assessment['correlation_clusters'][i]['tier1_prefill'] in-place.
    Returns a result summary dict.
    """
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

    prompts: list[str] = []
    selected_clusters: list[dict] = []

    for cluster in selected:
        # Skip if already prefilled and not stale
        existing = cluster.get('tier1_prefill')
        if existing and isinstance(existing, dict) and existing.get('incident_name'):
            rows = _get_rows_for_cluster(cluster, assessment)
            _ensure_v2_prefill_fields(existing, cluster, rows)
            logger.debug('tier1_prefill: cluster %s already prefilled, skipping',
                         cluster.get('cluster_id'))
            continue
        rows = _get_rows_for_cluster(cluster, assessment)
        all_rows = assessment.get('rows') or []
        attack_seq = _detect_attack_sequence(rows)
        prompt = build_cluster_prefill_prompt(
            cluster, rows,
            all_assessment_rows=all_rows,
            attack_sequence=attack_seq,
        )
        prompts.append(prompt)
        selected_clusters.append(cluster)

    if not prompts:
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

    try:
        results = llm.generate_batch(
            prompts=prompts,
            max_tokens=PREFILL_MAX_TOKENS,
            tenant_id=tenant_id,
            overrides={'timeout': PREFILL_TIMEOUT_S},
            model=model,
        )
    except Exception as exc:
        logger.warning('tier1_prefill: generate_batch failed for %s: %s', assessment_id, exc)
        # Fall back to serial
        results = []
        for p in prompts:
            try:
                r = llm.generate(
                    prompt=p,
                    max_tokens=PREFILL_MAX_TOKENS,
                    tenant_id=tenant_id,
                    overrides={'timeout': PREFILL_TIMEOUT_S},
                    model=model,
                )
                results.append(r)
            except Exception as e:
                results.append({'error': str(e)})

    # Build entity index once across ALL clusters for cross-cluster linking (Enhancement 3)
    all_clusters = assessment.get('correlation_clusters') or []
    entity_index = _build_entity_cluster_index(all_clusters, assessment)

    for cluster, result in zip(selected_clusters, results):
        cid = cluster.get('cluster_id', '?')
        rows = _get_rows_for_cluster(cluster, assessment)

        # Enhancement 2: confidence meter — always computed, no LLM needed
        confidence_meter = _compute_confidence_meter(cluster, rows)
        cluster['confidence_meter'] = confidence_meter

        if isinstance(result, dict) and result.get('error'):
            logger.warning('tier1_prefill: LLM error for cluster %s: %s', cid, result['error'])
            cluster['tier1_prefill'] = {
                '_error': result['error'],
                'generated_at': int(time.time()),
                'confidence_meter': confidence_meter,
            }
            continue

        raw_text = ''
        if isinstance(result, dict):
            raw_text = (result.get('text') or result.get('response') or
                        result.get('content') or result.get('choices', [{}])[0].get('text', ''))
        elif isinstance(result, str):
            raw_text = result

        parsed = _parse_prefill_json(raw_text, cid)
        if parsed:
            parsed['model_used'] = model
            parsed['generated_at'] = int(time.time())

            # Enhancement 1: entity pin quality gate
            allowed_entities = _extract_entity_set(cluster, rows)
            quality = _validate_entity_pins(parsed, allowed_entities)
            parsed['_quality'] = quality
            if not quality['passed']:
                logger.warning(
                    'tier1_prefill: quality gate flagged tokens %s in cluster %s',
                    quality['flagged_tokens'], cid,
                )

            # Enhancement 2: attach confidence meter to prefill payload
            parsed['confidence_meter'] = confidence_meter

            # Enhancement 3: cross-cluster entity links
            cross_links = _compute_cross_cluster_links(cluster, entity_index, all_clusters)
            parsed['cross_cluster_links'] = cross_links
            _ensure_v2_prefill_fields(parsed, cluster, rows)

            cluster['tier1_prefill'] = parsed
            # Derive and attach verdict immediately so the cluster object is complete
            try:
                from src.core.verdict_engine.verdict_rules import compute_cluster_verdict
                v = compute_cluster_verdict(cluster)
                cluster['verdict'] = v['verdict']
                cluster['verdict_rationale'] = v['verdict_rationale']
                cluster['verdict_confidence'] = v['verdict_confidence']
            except Exception as _ve:
                logger.debug('tier1_prefill: verdict derivation failed for %s: %s', cid, _ve)
            # Re-apply HVR gating now that verdict is known — don't wait for get_assessment
            try:
                from src.api.deep_analyze_endpoints import _apply_hvr_gating
                _apply_hvr_gating(cluster)
            except Exception as _hvr_e:
                logger.debug('tier1_prefill: hvr re-apply failed for %s: %s', cid, _hvr_e)
            prefilled.append(cid)
            logger.info('tier1_prefill: prefilled cluster %s (%s) quality=%s verdict=%s',
                        cid, assessment_id, 'ok' if quality['passed'] else 'flagged',
                        cluster.get('verdict', '?'))
        else:
            cluster['tier1_prefill'] = {
                '_error': 'parse_failed',
                '_raw': raw_text[:200],
                'generated_at': int(time.time()),
                'confidence_meter': confidence_meter,
            }

    duration = round(time.time() - t0, 2)
    return {
        'status': 'ok',
        'prefilled_clusters': prefilled,
        'duration_seconds': duration,
    }


def run_single_cluster_prefill(
    assessment: dict[str, Any],
    cluster_id: str,
    model: str = PREFILL_DEFAULT_MODEL,
    tenant_id: str = 'default',
    force: bool = False,
) -> dict[str, Any]:
    """Prefill a single cluster by ID (used for on-demand clusters 4+)."""
    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        return {'status': 'not_found', 'cluster_id': cluster_id}

    existing = cluster.get('tier1_prefill')
    if not force and existing and isinstance(existing, dict) and existing.get('incident_name'):
        _ensure_v2_prefill_fields(existing, cluster, _get_rows_for_cluster(cluster, assessment))
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
