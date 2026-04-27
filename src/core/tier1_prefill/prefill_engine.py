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
import os
import re
import time
from typing import Any, NamedTuple

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
        # Generic verdict / security classification terms
        'breach', 'intrusion', 'incident', 'attack', 'exploit', 'payload',
        'escalation', 'exfil', 'recon', 'execution', 'discovery', 'collection',
        'validated', 'breach', 'rbac', 'iam', 'mfa', 'sspr', 'sso', 'saml',
        'kubernetes', 'k8s', 'container', 'docker', 'pod', 'cluster', 'node',
        'vpc', 'sg', 'acl', 'nsg', 'waf', 'cdn', 'lb', 'nat', 'vpn',
        'api', 'sdk', 'cli', 'gui', 'ui', 'rest', 'graphql', 'grpc',
        'ad', 'ldap', 'kerberos', 'ntlm', 'spn', 'dce', 'rpc', 'smb',
        'lsa', 'sam', 'gpo', 'ou', 'dc', 'ca', 'pki', 'cert', 'acme',
        'cve', 'nvd', 'cvss', 'cwe', 'osint', 'ioc', 'ttp', 'apt',
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
PREFILL_DEFAULT_MODEL = 'qwen3:14b'
PREFILL_TOP_N = 3
PREFILL_MAX_TOKENS = 3000
PREFILL_TIMEOUT_S = 90


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
    # Cast row_refs to int — they may be stored as strings while row_index is int,
    # causing silent missed matches and evidence_preview fallback for smaller clusters.
    refs: set[int] = {int(v) for v in (cluster.get('row_refs') or []) if str(v).lstrip('-').isdigit()}
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
        logger.info(
            'tier1_prefill row_attribution: cluster=%s refs=%d matched=%d',
            cluster.get('cluster_id'), len(refs), len(matched),
        )
        return matched
    # normalized_rows/evidence_rows are a sample that may not overlap with
    # this cluster's row_refs — fall back to the pre-sampled evidence_preview
    # which is always indexed against the cluster's actual row_refs.
    logger.info(
        'tier1_prefill row_attribution: cluster=%s refs=%d matched=0 preview_fallback=True',
        cluster.get('cluster_id'), len(refs),
    )
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
    """Extract JSON from LLM response, tolerating markdown fences and thinking tags.

    Required fields are the original 6 (backward compat).
    New v2 schema fields (what_happened, root_cause, evidence_chain, observed_impact,
    evidence_gaps, immediate_actions) are optional pass-throughs.
    The 'reasoning' CoT scratchpad is stripped from display payload -> _cot.
    """
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
        # Remove trailing commas before closing braces/brackets
        s = _re.sub(r',(\s*[}\]])', r'\1', s)
        # If the JSON is truncated (no closing brace), trim to last good value and close
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
        # Last resort: find the outermost {...} block
        m = _re.search(r'\{.*\}', text, _re.DOTALL)
        if m:
            data = _try_parse(m.group())

    try:
        if data is not None and required.issubset(data.keys()):
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
        logger.warning('tier1_prefill: missing keys for %s — got=%s need=%s raw_head=%s',
                       cluster_id, sorted(data.keys()) if data else 'None',
                       sorted(required - (data.keys() if data else set())),
                       text[:300])
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


class PhaseEvent(NamedTuple):
    """Structured kill-chain phase event extracted from a single row."""
    phase: str
    row_index: int
    timestamp: str
    country: str   # empty string when unavailable
    asn: str       # empty string when unavailable


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
        # Deduplicate identical action text (e.g. same rclone command appearing twice)
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
    """Classify subtask autonomy tier for bounded-action display.

    Returns one of: 'SAFE_TO_RUN', 'APPROVAL_REQUIRED', 'MANUAL_REVIEW', or ''.
    """
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
            if actors and 'No named' not in actors:
                benign_parts.append(f'Associated accounts reviewed: {actors}.')
            benign_parts.append('No indicators of unauthorised access, data loss, or malicious intent were confirmed.')
            data['verdict_reasoning'] = ' '.join(benign_parts)
        else:
            data['verdict_reasoning'] = root or 'Correlated evidence requires further analyst investigation.'

    # Build DREAD fragments and SABSA coda (deterministic — no LLM)
    # Only run for breach-class verdicts; skip benign clusters to avoid noise.
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
        # Rebuild when absent OR when fill_rate < 0.20 — prevents empty fragments
        # written by a previous run (e.g. due to row-attribution miss) from being
        # cached forever by a presence-only check.
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
                # 'rendered' is populated by the LLM render step in run_prefill
            }
            # Bolt compliance-framework control tags alongside DREAD fragments
            if derive_controls_breached is not None:
                data['compliance_controls'] = derive_controls_breached(frags)

    # ── Deterministic intelligence enrichments (Blocks 2 + 3) ─────────────────
    # These run for ALL clusters (not just breach) so that benign clusters still
    # carry structured context. The LLM prompt uses them as pre-computed context.
    try:
        _enrich_cluster_intelligence(data, cluster, rows)
    except Exception as _ei:
        logger.warning('tier1_prefill: cluster intelligence enrichment failed for %s: %s',
                       cluster.get('cluster_id'), _ei)

    return data


# ── Phase-role → readable label ───────────────────────────────────────────────
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


def _enrich_cluster_intelligence(data: dict, cluster: dict, rows: list[dict]) -> None:
    """Populate deterministic structured intelligence fields on tier1_prefill.

    Fields added (idempotent — only set when absent or empty):
      event_chain_summary   — formatted temporal event chain string
      kill_chain_summary    — "Initial Access → … → Exfil" readable string
      adversarial_sequence  — bool flag
      adversarial_sequence_detail — what the sequence was
      known_technical       — list of internal/expected entities
      unknown_technical     — list of external/first-seen entities
      dread_score           — numeric D/R/E/A/D scores + risk_tier
      diamond_model         — adversary/capability/infrastructure/victim struct
      pasta_summary         — threat_profile/exploitation_path/business_impact
    """
    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
    phases = cluster.get('phases') or []
    is_breach = verdict in ('VALIDATED_BREACH', 'CONFIRMED_BREACH', 'LIKELY_BREACH', 'LIKELY_COMPROMISE')

    # ── 2.1 event_chain_summary ───────────────────────────────────────────────
    # Each sub-computation is independently guarded so a failure in one field
    # does NOT prevent the remaining fields from being written.
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


def _build_event_chain_summary(cluster: dict, rows: list[dict]) -> str:
    """Format a temporal event chain from phase anchor rows sorted by _ts_epoch.

    Output:
        aaron.blackwood │ T+0     Session token replay (Okta)         45.133.193.118
                        │ T+6h    GetSecretValue + AssumeRole (CT)     91.240.118.7
                        │ T+8h    Privileged DaemonSet → kubelet (K8s)
                        │ T+48h   COPY INTO external_stage 1.4M rows  (Snowflake)
    """
    if not rows:
        return ''

    # Collect phase anchor rows — prefer cluster phases, fall back to all rows
    phases = cluster.get('phases') or []
    anchor_refs: set[int] = set()
    for p in phases:
        for r in (p.get('row_refs') or [])[:5]:
            try:
                anchor_refs.add(int(r))
            except (TypeError, ValueError):
                pass

    # Use int(float(...)) to tolerate row_index stored as float or float-string (e.g. "1.0").
    _row_by_idx: dict[int, dict] = {}
    for _r in rows:
        _ri = _r.get('row_index')
        if _ri is not None:
            try:
                _row_by_idx[int(float(_ri))] = _r
            except (TypeError, ValueError):
                pass
    row_by_idx = _row_by_idx

    # Use phase anchor rows if we have them, otherwise top severity rows
    if anchor_refs:
        chain_rows = [row_by_idx[i] for i in sorted(anchor_refs) if i in row_by_idx]
    else:
        chain_rows = sorted(rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)[:12]

    # Sort by epoch
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
    # Determine primary actor for left-column label
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

    # ── Authorized-engagement gate (Fixes 1 + 2) ─────────────────────────────
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
    # All matching initial-access vectors are added — multi-vector breaches need all paths.
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


_CONFIDENCE_FLOOR_CONFIRMED = 0.75
_CONFIDENCE_FLOOR_LIKELY    = 0.55
_EVIDENCE_FILL_FLOOR        = 0.60

# Canonical causal order for DREAD dimensions in a breach narrative.
# Damage first (observed harm at T1), reproducibility (patterns over time),
# affected_users (who was present), exploitability (pre-condition context),
# discoverability (detection endpoint — always last).
_DREAD_CAUSAL_ORDER = [
    'damage', 'reproducibility', 'affected_users', 'exploitability', 'discoverability',
]


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


def _choose_narrative_framework(cluster: dict, rows: list[dict]) -> str:
    """
    Returns 'diamond' when named actor entities exist (email-format or dot-separated),
    'pasta' when only IPs or generic entities are present.

    Diamond: bind actor → capability → infrastructure → victim.
    PASTA:   bind threat → vulnerability → attack vector → impact.
    """
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
    """
    Call the LLM with the strict render prompt, validate the output against
    the allowed entity set, and return the render result dict.

    Returns:
      { 'rendered': str, 'render_fallback': bool, 'render_quality': dict }
    """
    _RENDER_FAILED_SENTINEL = '{{RENDER_FAILED}}'

    # Load render prompt template
    _prompt_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'prompts', 'dread_narrative_render.txt',
    )
    try:
        with open(_prompt_path, encoding='utf-8') as f:
            template = f.read()
    except Exception:
        # Fallback inline prompt when file path resolution fails
        template = (
            'Render a confirmed-breach executive summary from these evidence fragments.\n'
            'Rules: cite row numbers inline, preserve entity names exactly, '
            '150-220 words, start with "Confirmed breach — <label>."\n\n'
            'Fragments:\n{fragment_block}\n\nSABSA coda draft: {sabsa_coda_draft}\n\nRender now.'
        )

    ordered = _order_fragments_temporally(fragments)
    framework = _choose_narrative_framework(cluster, rows)

    # Build the temporal-sequence block
    frag_lines = []
    for i, (dim_label, frag_text) in enumerate(ordered, 1):
        frag_lines.append(f'  [T{i} {dim_label}]  {frag_text}')
    fragment_block = '\n'.join(frag_lines) or '  [NO FRAGMENTS AVAILABLE]'

    # Fill placeholders — replace each T-slot individually
    filled = template
    for i, (dim_label, frag_text) in enumerate(ordered, 1):
        filled = filled.replace(f'{{t{i}_dim}}', dim_label)
        filled = filled.replace(f'{{t{i}_fragment}}', frag_text)
    # Zero out any unused T-slots
    for i in range(len(ordered) + 1, 7):
        filled = filled.replace(f'{{t{i}_dim}}', '[ABSENT]')
        filled = filled.replace(f'{{t{i}_fragment}}', '[ABSENT]')

    geo_notes = _geo_sequence_summary(_detect_attack_sequence_events(rows))
    filled = filled.replace('{framework}', framework)
    filled = filled.replace('{sabsa_attributes}', ', '.join(sabsa_attributes) or 'none identified')
    filled = filled.replace('{sabsa_coda_draft}', sabsa_coda_draft or '[ABSENT]')
    filled = filled.replace('{geo_asn_notes}', geo_notes)
    filled = filled.replace('{fragment_block}', fragment_block)

    # Call LLM — allow generous timeout for large models (qwen3.6:27b needs ~120s)
    # Thinking mode is intentionally ENABLED here: prose narrative benefits from CoT.
    # (JSON prefill at run_prefill still uses /no_think for structured-output speed.)
    rendered_text = ''
    try:
        result = llm.generate(
            filled,
            max_tokens=512,
            overrides={'timeout': 180},
            model=model,
        )
        raw_rendered = (
            result.get('text') or result.get('response')
            or result.get('content') or ''
        ).strip()
        # Strip thinking-mode tags (qwen3 / deepseek-r1)
        rendered_text = re.sub(r'<think>.*?</think>', '', raw_rendered, flags=re.DOTALL).strip()
    except Exception as _e:
        logger.warning('_render_dread_narrative: LLM call failed: %s', _e)
        rendered_text = ''

    # Check for explicit failure sentinel
    if _RENDER_FAILED_SENTINEL in rendered_text or not rendered_text:
        return {
            'rendered': _raw_fragment_fallback(fragments),
            'render_fallback': True,
            'render_quality': {'passed': False, 'reason': 'sentinel_or_empty'},
        }

    # Entity-pin validation on the rendered output
    allowed = _extract_entity_set(cluster, rows)
    # Wrap text in a pseudo-prefill dict so _validate_entity_pins can scan it
    quality = _validate_entity_pins(
        {'short_narrative': rendered_text, 'incident_name': '', 'headline_subtitle': '', 'top_actions': []},
        allowed,
    )

    if not quality['passed']:
        logger.warning(
            '_render_dread_narrative: entity pin check flagged %s — using fallback',
            quality['flagged_tokens'],
        )
        # One retry with stricter prefix
        retry_prompt = (
            'The previous render was rejected because it introduced entity names '
            'not present in the evidence. Be exact — use only the names given below.\n\n'
            + filled
        )
        try:
            retry_result = llm.generate('/no_think\n' + retry_prompt, max_tokens=320, overrides={'timeout': 180}, model=model)
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


def _raw_fragment_fallback(fragments: dict[str, str | None]) -> str:
    """Concatenate non-null fragments in causal order. Used when LLM render fails."""
    parts = [
        fragments.get(dim)
        for dim in _DREAD_CAUSAL_ORDER
        if fragments.get(dim)
    ]
    return ' '.join(parts)


def _gated_verdict(raw_verdict: str, confidence: float, fill_rate: float) -> str:
    """
    Three-valued gating for VALIDATED_BREACH verdicts.

    CONFIRMED_BREACH   — confidence >= 0.75 AND evidence fill-rate >= 0.60
    LIKELY_BREACH      — confidence >= 0.55 (human review required)
    INVESTIGATION_REQUIRED — below both floors

    Non-breach verdicts pass through unchanged.
    """
    if raw_verdict not in ('VALIDATED_BREACH', 'CONFIRMED_INTRUSION'):
        return raw_verdict
    if confidence >= _CONFIDENCE_FLOOR_CONFIRMED and fill_rate >= _EVIDENCE_FILL_FLOOR:
        return 'CONFIRMED_BREACH'
    if confidence >= _CONFIDENCE_FLOOR_LIKELY:
        return 'LIKELY_BREACH'
    return 'INVESTIGATION_REQUIRED'


def run_prefill(
    assessment: dict[str, Any],
    top_n: int = PREFILL_TOP_N,
    model: str = PREFILL_DEFAULT_MODEL,
    tenant_id: str = 'default',
    force: bool = False,
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

    # ── Build assessment-wide engagement allowlist and inject into every cluster ──
    # engagement_refs / engagement_ip_ranges are per-cluster on the PENTEST cluster.
    # The breach cluster does NOT carry them — but it may contain pentest-range IPs
    # in its rows if the pipeline correctly promoted phase-tagged rows into the campaign.
    # We collect the union across ALL clusters so every cluster benefits from the full
    # engagement scope. This matches how a real SOC reasons: if pentest RH-ENG-2026-041
    # covers 198.51.100.0/24 this week, NOTHING in the assessment attributes to that range.
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
        # Also infer engagement actors from rows carrying engagement_refs
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
    # ─────────────────────────────────────────────────────────────────────────────

    prompts: list[str] = []
    selected_clusters: list[dict] = []
    # Cached clusters that have DREAD fragments but no rendered narrative yet
    render_pending: list[tuple[dict, dict, list[dict]]] = []  # (cluster, prefill, rows)

    _BREACH_VERDICTS = (
        'CONFIRMED_BREACH', 'LIKELY_BREACH', 'VALIDATED_BREACH',
        'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE',
    )

    for cluster in selected:
        # Skip ANALYSIS_INCOMPLETE and untyped legacy clusters — they have no
        # evidence-bound phases to prefill against and must not be upgraded to
        # confirmed breach by the verdict engine.
        _cv = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
        if _cv == 'ANALYSIS_INCOMPLETE':
            logger.debug('tier1_prefill: skipping ANALYSIS_INCOMPLETE cluster %s', cluster.get('cluster_id'))
            continue
        if not cluster.get('cluster_kind') and _cv not in _BREACH_VERDICTS:
            logger.debug('tier1_prefill: skipping untyped cluster %s (no cluster_kind)', cluster.get('cluster_id'))
            continue

        # Skip if already prefilled and not stale
        existing = cluster.get('tier1_prefill')
        if not force and existing and isinstance(existing, dict) and existing.get('incident_name'):
            rows = _get_rows_for_cluster(cluster, assessment)
            _ensure_v2_prefill_fields(existing, cluster, rows, tenant_id=tenant_id)
            # Rebuild DREAD fragments when stale (fill_rate < 0.20) — covers clusters
            # that were prefilled before the type-mismatch row-attribution fix, where
            # all fragments came back None and got cached as an empty dict.
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
            # Collect for deferred LLM render if fragments present but not yet rendered
            _v  = cluster.get('verdict', '')
            if _dn.get('fragments') and not _dn.get('rendered') and _v in _BREACH_VERDICTS:
                render_pending.append((cluster, existing, rows))
            logger.debug('tier1_prefill: cluster %s already prefilled, skipping',
                         cluster.get('cluster_id'))
            continue
        rows = _get_rows_for_cluster(cluster, assessment)
        all_rows = assessment.get('rows') or []

        # Skip clusters with no usable evidence — the LLM can't produce
        # meaningful structured output from an empty evidence block and will
        # always fail the required-keys check. These are typically noise
        # fragments from pre-fix clustering runs.
        if not rows and len(cluster.get('row_refs') or []) < 10:
            logger.info(
                'tier1_prefill: skipping cluster %s — no matched rows and only %d row_refs '
                '(likely a noise fragment; re-ingest to consolidate)',
                cluster.get('cluster_id'), len(cluster.get('row_refs') or []),
            )
            continue

        attack_seq = _detect_attack_sequence(rows)

        # Pre-compute deterministic intelligence so the LLM prompt is grounded
        # in structured facts rather than raw rows alone (Block 3.4).
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
        # Disable qwen3/deepseek-r1 thinking mode — structured JSON needs speed, not CoT
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
                overrides={'timeout': PREFILL_TIMEOUT_S},
                model=model,
            )
        except Exception as exc:
            logger.warning('tier1_prefill: generate_batch failed for %s: %s', assessment_id, exc)
            # Fall back to serial
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

        # Set verdict_confidence from confidence_meter when verdict engine hasn't set it
        if cluster.get('verdict_confidence') is None and confidence_meter.get('total') is not None:
            cluster['verdict_confidence'] = round(confidence_meter['total'] / 100.0, 2)

        # Zero-row clusters cannot require human validation — they have no evidence
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
            _ensure_v2_prefill_fields(parsed, cluster, rows, tenant_id=tenant_id)

            _old_t1 = cluster.get('tier1_prefill') or {}
            # Clear stale _error so a successful parse doesn't carry forward a
            # previous failure flag — the success fields in parsed take precedence
            # but _error is not in parsed so it would survive the merge otherwise.
            _old_t1.pop('_error', None)
            _old_t1.pop('_raw', None)
            cluster['tier1_prefill'] = {**_old_t1, **parsed}
            # Derive and attach verdict immediately so the cluster object is complete
            try:
                from src.core.verdict_engine.verdict_rules import compute_cluster_verdict
                v = compute_cluster_verdict(cluster)
                cluster['verdict'] = v['verdict']
                cluster['verdict_rationale'] = v['verdict_rationale']
                cluster['verdict_confidence'] = v['verdict_confidence']
            except Exception as _ve:
                logger.debug('tier1_prefill: verdict derivation failed for %s: %s', cid, _ve)

            # Apply three-valued confidence-floor gating to breach verdicts.
            # Never override ANALYSIS_INCOMPLETE — it must persist to signal reingest.
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
            # Re-apply HVR gating now that verdict is known — don't wait for get_assessment
            try:
                from src.api.deep_analyze_endpoints import _apply_hvr_gating
                _apply_hvr_gating(cluster)
            except Exception as _hvr_e:
                logger.debug('tier1_prefill: hvr re-apply failed for %s: %s', cid, _hvr_e)

            # Wire: LLM narrative render — only for breach-class verdicts with fragments
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
            # Merge into existing tier1_prefill so deterministic Stage-5c enrichments
            # (kill_chain_summary, dread_score, diamond_model, etc.) written before the
            # LLM call are not silently discarded when the LLM returns unparseable JSON.
            _old_t1_pf = cluster.get('tier1_prefill') or {}
            # Clear stale incident_name so the cache-skip guard fires on the next retry.
            # Without this, a previous successful prefill's incident_name survives the
            # merge and permanently masks the failure — the cluster never retries.
            _old_t1_pf.pop('incident_name', None)
            cluster['tier1_prefill'] = {
                **_old_t1_pf,
                '_error': 'parse_failed',
                '_raw': raw_text[:200],
                'generated_at': int(time.time()),
                'confidence_meter': confidence_meter,
            }

    # Deferred render pass: cached clusters that had fragments but no rendered narrative
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
        rows = _get_rows_for_cluster(cluster, assessment)
        _ensure_v2_prefill_fields(existing, cluster, rows)
        # Rebuild DREAD fragments if stale (fill_rate < 0.20) — same logic as run_prefill loop.
        # This is the primary path for top-card clusters; without this check they permanently
        # cache empty fragments and show "Legacy fallback" in the UI.
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
