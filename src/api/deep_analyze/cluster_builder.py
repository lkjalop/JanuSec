"""Correlation cluster building functions.

Extracted from src.api.deep_analyze_endpoints during Phase A-3c.
All functions operate on plain dicts and carry no FastAPI/router state.
"""
from __future__ import annotations
import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from src.api.deep_analyze.helpers import _safe_text, _collect_strings_from_row
from src.api.deep_analyze.enrichment import (
    _classify_backend_severity,
    _severity_label_for_rows,
    _is_low_value_account_pivot,
    _extract_attacker_ips,
    _build_bitemporal_trace,
    _SEV_RANK,
)
from src.api.deep_analyze.verdict_seed import _initial_cluster_verdict, _apply_hvr_gating
from src.api.deep_analyze.verdict_seed import _derive_human_validation_required

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# max rows per shared key before we stop expanding that key's pairs
_CLUSTER_BUCKET_CAP = 200  # max rows per shared key before we stop expanding that key's pairs


# ---------------------------------------------------------------------------
# Cluster helper functions
# ---------------------------------------------------------------------------


def _build_remediation_simulation(component_rows: List[dict], severity: str) -> dict:
    joined = ' '.join(_collect_strings_from_row(row).lower() for row in component_rows)
    prod_targets = sorted({
        item for row in component_rows
        for item in ((row.get('hosts') or []) + (row.get('resources') or []))
        if 'prod' in _safe_text(item).lower() or 'app' in _safe_text(item).lower()
    })[:4]
    if not prod_targets:
        return {}
    containment_ready = severity in {'critical', 'high'} and any(
        token in joined for token in ('guardduty', 'securityhub', 'c2', 'beacon', 'exfil', 'credentialaccess', 'powershell', 'curl http')
    )
    return {
        'status': 'simulated' if containment_ready else 'manual_review',
        'targets': prod_targets,
        'isolated_nodes': prod_targets[:1] if containment_ready else [],
        'alb_drain_status': 'simulated_drained' if containment_ready else 'pending_review',
        'replacement_capacity_status': 'simulated_replaced' if containment_ready else 'not_started',
        'summary': 'Simulated node isolation, ALB drain, and replacement capacity exercised for the affected production workload.'
        if containment_ready
        else 'Containment remains gated pending stronger corroboration.',
    }


def _cluster_controls_and_frameworks(cluster: dict, rows: List[dict]) -> dict:
    row_map = {int(row.get('row_index') or 0): row for row in rows}
    mitre_ids = []
    for ref in cluster.get('row_refs') or []:
        mitre_ids.extend(row_map.get(int(ref), {}).get('mitre') or [])
    mitre_ids = list(dict.fromkeys([m for m in mitre_ids if isinstance(m, str) and m.strip()]))
    factors = []
    try:
        from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP, controls_for_factors  # noqa: PLC0415
        reverse: Dict[str, List[str]] = {}
        for name, meta in _FACTOR_MAP.items():
            for mid in meta.get('mitre', []):
                reverse.setdefault(mid, []).append(name)
        for mid in mitre_ids:
            factors.extend(reverse.get(mid, []))
        factors = list(dict.fromkeys(factors))
        controls = controls_for_factors(factors) if factors else []
        frameworks = sorted({(entry.get('control') or '').split(':', 1)[0] for entry in controls if entry.get('control')})
        return {
            'factors': factors[:12],
            'frameworks': frameworks[:12],
            'controls': controls[:20],
        }
    except Exception:
        return {'factors': [], 'frameworks': [], 'controls': []}


def _build_cluster_lead_description(
    component_rows: list,
    shared_ips: list,
    shared_accounts: list,
    shared_hosts: list,
    cluster_num: int,
) -> str:
    """Build a grounded cluster title from observed entities rather than raw description fields."""
    # Descriptions that are too generic to be a useful incident title — reject these
    # and fall through to the entity-based builder instead.
    _SKIP = re.compile(
        r'^('
        r'correlated activity cluster'
        r'|n/a|unknown|none|null|-|event|log entry|log'
        r'|high.severity activity\.?'
        r'|medium.severity activity\.?'
        r'|low.severity activity\.?'
        r'|critical.severity activity\.?'
        r'|suspicious activity\.?'
        r'|security event\.?'
        r'|anomalous activity\.?'
        r'|threat detected\.?'
        r'|alert triggered\.?'
        r'|potential threat\.?'
        r'|investigation required\.?'
        r'|requires investigation\.?'
        r'|see analyst notes\.?'
        r')$',
        re.I,
    )
    # Prefer a description from the highest-triage row that looks like a named action
    sorted_rows = sorted(component_rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)
    for row in sorted_rows:
        # Prefer alert_name / event_name over free-text description — they're more structured
        for field in ('alert_name', 'event_name', 'eventName', 'activityDisplayName',
                      'operationName', 'analyst_notes', 'description'):
            desc = _safe_text(row.get(field) or '')
            if desc and not _SKIP.match(desc.strip()) and 10 <= len(desc) <= 90:
                # Skip anything that looks like a raw UUID or purely numeric event ID
                if not re.match(r'^[0-9a-f\-]{8,}$', desc, re.I):
                    return desc
    # Entity-based fallback: actor → verb → target
    actor = shared_accounts[0] if shared_accounts else None
    target_host = shared_hosts[0] if shared_hosts else None
    target_ip = shared_ips[0] if shared_ips else None

    # Collect the best MITRE technique label across all rows
    mitre_verb: str = ''
    for row in sorted_rows[:10]:
        mitre = row.get('mitre') or []
        if mitre:
            mitre_verb = str(mitre[0])
            break

    # Collect the most specific event-type label
    event_verb: str = ''
    for row in sorted_rows[:5]:
        for ef in ('event_name', 'eventName', 'activityDisplayName', 'operationName', 'category'):
            ev = _safe_text(row.get(ef) or '')
            if ev and not _SKIP.match(ev) and len(ev) > 4:
                event_verb = ev
                break
        if event_verb:
            break

    verb = event_verb or mitre_verb or 'suspicious activity'

    if actor and target_ip:
        return f"{actor} → {target_ip}: {verb}" if not event_verb else f"{actor}: {event_verb}"
    if actor and target_host:
        return f"{actor} on {target_host}: {verb}" if not event_verb else f"{actor}: {event_verb}"
    if actor:
        return f"{actor}: {verb}"
    if target_ip:
        return f"External IP {target_ip}: {verb}"
    if target_host:
        return f"Host {target_host}: {verb}"
    # Last resort: informative placeholder with cluster number and pivot count
    return f"Cluster {cluster_num} — {len(component_rows)} correlated events"


def _build_cluster_reason_summary(top_links: list) -> str:
    """Aggregate unique pivot signals rather than concatenating repeated phrases."""
    if not top_links:
        return ''
    # Collect unique (pivot_type, time_bucket) combinations
    seen: set = set()
    parts: list = []
    for lk in top_links:
        summary = lk.get('summary') or ''
        pivot = lk.get('pivot_type') or lk.get('pivot') or ''
        # Deduplicate by normalising the summary to its first clause before the time qualifier
        key = re.sub(r'within \d+ minute\(s\)', 'TIMED', summary)
        if key and key not in seen:
            seen.add(key)
            parts.append(summary)
    return '; '.join(parts[:3])


def _build_enrichment_guided_cases(rows: List[dict]) -> List[dict]:
    """Production assessment path never injects enrichment-derived cases."""
    return []


def _build_inverted_index(row_map: Dict[int, dict]) -> Dict[str, List[int]]:
    """Build key → [row_index, ...] inverted index for all pivot dimensions."""
    idx: Dict[str, List[int]] = defaultdict(list)
    for row_idx, row in row_map.items():
        # Account / identity pivots
        for acc in (row.get('accounts') or []):
            if acc and not _is_low_value_account_pivot(acc):
                idx[f'acc:{acc.lower()}'].append(row_idx)
        # External IP pivots (only non-private, non-vendor)
        for ip in (row.get('external_ips') or []):
            if ip:
                idx[f'ip:{ip}'].append(row_idx)
        # Host pivots
        for h in (row.get('hosts') or []):
            if h:
                idx[f'host:{h.lower()}'].append(row_idx)
        # Session / correlation-id pivots — strong signal
        sess = _safe_text(row.get('session_id') or '')
        if sess and sess not in ('-', 'N/A'):
            idx[f'sess:{sess}'].append(row_idx)
        # Cloud boundary (subscription / account_id)
        cb = _safe_text(row.get('cloud_boundary') or '')
        if cb and cb not in ('-', 'N/A'):
            idx[f'cloud:{cb}'].append(row_idx)
        # MITRE technique pivots
        for m in (row.get('mitre') or []):
            if m:
                idx[f'mitre:{str(m).upper()}'].append(row_idx)
        # Attacker IP pivots (separate from external_ips — uses the filtered set)
        for ip in _extract_attacker_ips(row):
            idx[f'atk:{ip}'].append(row_idx)
        # Resource pivots (S3 bucket, vault, key ARN, etc.)
        for res in (row.get('resources') or []):
            if res and len(res) > 4:
                idx[f'res:{res.lower()[:80]}'].append(row_idx)
    return idx


def _build_pair_reason(left: dict, right: dict) -> dict | None:
    left_guest = left.get('guest_onboarding_context') or {}
    right_guest = right.get('guest_onboarding_context') or {}
    left_policy = left.get('policy_change_context') or {}
    right_policy = right.get('policy_change_context') or {}

    # Attacker infrastructure pivot — must check before scoring to detect conflicts
    left_atk_ips = _extract_attacker_ips(left)
    right_atk_ips = _extract_attacker_ips(right)
    shared_atk_ips = left_atk_ips & right_atk_ips
    # Events from provably different attacker origins must never merge into one cluster
    conflicting_atk_infra = bool(left_atk_ips and right_atk_ips and not shared_atk_ips)
    if conflicting_atk_infra:
        return None

    shared = {
        'accounts': sorted(
            acc for acc in set(left.get('accounts') or []).intersection(right.get('accounts') or [])
            if not _is_low_value_account_pivot(acc)
        ),
        'hosts': sorted(set(left.get('hosts') or []).intersection(right.get('hosts') or [])),
        'ips': sorted(set(left.get('external_ips') or []).intersection(right.get('external_ips') or [])),
        'resources': sorted(set(left.get('resources') or []).intersection(right.get('resources') or [])),
        'mitre': sorted(set(left.get('mitre') or []).intersection(right.get('mitre') or [])),
        'cloud_boundaries': sorted(set(filter(None, [left.get('cloud_boundary')])).intersection(filter(None, [right.get('cloud_boundary')]))),
        'privilege_states': sorted(set(filter(None, [left.get('privilege_state'), right.get('privilege_state')]))),
        'sessions': sorted(set(filter(None, [left.get('session_id')])).intersection(filter(None, [right.get('session_id')]))),
    }
    strong_corroboration = bool(shared['sessions'] or shared['hosts'] or shared_atk_ips or shared['resources'])
    suspicious_identity_signal = bool(
        left.get('impossible_travel') or right.get('impossible_travel')
        or 'elevated' in shared['privilege_states']
        or 'suspicious' in shared['privilege_states']
        or left_guest.get('suspicious')
        or right_guest.get('suspicious')
        or left_policy.get('suspicious_drift')
        or right_policy.get('suspicious_drift')
    )
    if (
        left_guest.get('category') == 'benign_onboarding'
        or right_guest.get('category') == 'benign_onboarding'
    ) and not (strong_corroboration and suspicious_identity_signal):
        return None
    if (
        left_policy.get('approved_change')
        or right_policy.get('approved_change')
    ) and not (strong_corroboration or suspicious_identity_signal):
        return None

    # Account-only match (no technical corroboration) is insufficient on its own —
    # a victim account appearing in two unrelated attacks must not merge those incidents.
    account_only = (
        bool(shared['accounts'])
        and not shared['hosts']
        and not shared_atk_ips
        and not shared['ips']
        and not shared['resources']
        and not shared['sessions']
        and not shared['mitre']
    )
    if account_only and not suspicious_identity_signal:
        return None

    score = 0.0
    if shared_atk_ips:
        # Shared attacker infrastructure is the strongest pivot signal
        score += 0.5
    if shared['accounts']:
        score += 0.4
    if shared['hosts']:
        score += 0.35
    if shared['resources']:
        score += 0.25
    if shared['ips']:
        score += 0.2
    if shared['mitre']:
        score += 0.1
    if shared['cloud_boundaries']:
        score += 0.2
    if shared['sessions']:
        score += 0.2
    if 'elevated' in shared['privilege_states'] or 'suspicious' in shared['privilege_states']:
        score += 0.15
    time_delta = None
    if left.get('timestamp_epoch') is not None and right.get('timestamp_epoch') is not None:
        time_delta = abs(float(left['timestamp_epoch']) - float(right['timestamp_epoch']))
        if time_delta <= 900:
            score += 0.2
        elif time_delta <= 3600:
            score += 0.1
    cross_source = left.get('source_sheet') != right.get('source_sheet')
    if cross_source:
        score += 0.1
    if left.get('cloud', {}).get('provider') and left.get('cloud', {}).get('provider') == right.get('cloud', {}).get('provider'):
        score += 0.05
    if left.get('impossible_travel') and right.get('impossible_travel'):
        score += 0.1
    if score < 0.45:
        return None

    # Determine the dominant pivot type for UI display and LLM context
    if shared_atk_ips:
        pivot_type = 'attacker_ip'
    elif shared['sessions']:
        pivot_type = 'session'
    elif shared['hosts']:
        pivot_type = 'host'
    elif shared['accounts'] and suspicious_identity_signal:
        pivot_type = 'identity_anomaly'
    elif shared['accounts']:
        pivot_type = 'account'
    elif shared['ips']:
        pivot_type = 'network_ip'
    elif shared['resources']:
        pivot_type = 'resource'
    else:
        pivot_type = 'behavioral'
    evidence = []
    if shared_atk_ips:
        evidence.append({'kind': 'attacker_ips', 'values': sorted(shared_atk_ips)[:4]})
    for key in ('accounts', 'hosts', 'ips', 'resources', 'mitre', 'cloud_boundaries', 'sessions'):
        vals = shared[key]
        if vals:
            evidence.append({'kind': key, 'values': vals[:4]})
    significance_parts = []
    if shared_atk_ips:
        significance_parts.append(f'shared attacker IP {next(iter(shared_atk_ips))}')
    if shared['accounts']:
        significance_parts.append('shared identity activity')
    if shared['hosts']:
        significance_parts.append('same host sequence')
    if shared['ips']:
        significance_parts.append('same network infrastructure')
    if shared['resources']:
        significance_parts.append('same resource or artifact path')
    if shared['mitre']:
        significance_parts.append('same ATT&CK technique family')
    if shared['cloud_boundaries']:
        significance_parts.append('same cloud account or boundary')
    if shared['sessions']:
        significance_parts.append('same session or correlation context')
    if 'elevated' in shared['privilege_states']:
        significance_parts.append('privileged or escalated identity context')
    if time_delta is not None and time_delta <= 3600:
        significance_parts.append(f'within {int(time_delta // 60) or 1} minute(s)')
    return {
        'target_row_index': int(right.get('row_index') or 0),
        'source_row_index': int(left.get('row_index') or 0),
        'shared': evidence,
        'cross_source': cross_source,
        'time_delta_seconds': int(time_delta) if time_delta is not None else None,
        'confidence': round(min(0.98, score), 2),
        'pivot_type': pivot_type,
        'summary': '; '.join(significance_parts) or 'shared telemetry context',
    }


def _build_correlation_clusters(rows: List[dict]) -> Tuple[List[dict], Dict[int, List[dict]]]:
    adjacency: Dict[int, List[dict]] = defaultdict(list)
    row_map = {int(row.get('row_index') or 0): row for row in rows}

    # Build inverted index across all pivot dimensions — O(n·k)
    inv_idx = _build_inverted_index(row_map)

    # Collect candidate pairs from index buckets — each bucket is a set of rows
    # sharing one pivot key.  Dedup pairs with a seen set.
    seen_pairs: Set[Tuple[int, int]] = set()
    candidate_pairs: List[Tuple[int, int]] = []
    for key, bucket in inv_idx.items():
        if len(bucket) < 2:
            continue
        # Cap super-nodes: keep the highest-triage rows in this bucket
        if len(bucket) > _CLUSTER_BUCKET_CAP:
            bucket = sorted(bucket, key=lambda i: float(row_map[i].get('triage_score') or 0), reverse=True)[:_CLUSTER_BUCKET_CAP]
        for i, left_idx in enumerate(bucket):
            for right_idx in bucket[i + 1:]:
                pair = (min(left_idx, right_idx), max(left_idx, right_idx))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    candidate_pairs.append(pair)

    logger.debug(
        '_build_correlation_clusters: %d rows → %d index buckets → %d candidate pairs',
        len(rows), len(inv_idx), len(candidate_pairs),
    )

    # Evaluate each candidate pair with the full reason builder
    for left_idx, right_idx in candidate_pairs:
        left = row_map.get(left_idx)
        right = row_map.get(right_idx)
        if left is None or right is None:
            continue
        reason = _build_pair_reason(left, right)
        if not reason:
            continue
        adjacency[left_idx].append(reason)
        reverse = dict(reason)
        reverse['target_row_index'] = left_idx
        adjacency[right_idx].append(reverse)

    indices = sorted(row_map.keys())

    visited: Set[int] = set()
    clusters: List[dict] = []
    cluster_num = 1
    for row_index in indices:
        if row_index in visited:
            continue
        component = []
        stack = [row_index]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            for link in adjacency.get(current, []):
                target = int(link.get('target_row_index') or 0)
                if target and target not in visited:
                    stack.append(target)
        if len(component) < 2:
            continue
        component_rows = [row_map[idx] for idx in sorted(component)]
        shared_accounts = sorted({
            item for row in component_rows for item in row.get('accounts') or []
            if not _is_low_value_account_pivot(item)
        })
        shared_hosts = sorted({item for row in component_rows for item in row.get('hosts') or []})
        shared_ips = sorted({item for row in component_rows for item in row.get('external_ips') or []})
        shared_resources = sorted({item for row in component_rows for item in row.get('resources') or []})
        all_links = [link for idx in component for link in adjacency.get(idx, []) if int(link.get('target_row_index') or 0) in component]
        top_links = sorted(all_links, key=lambda l: float(l.get('confidence') or 0), reverse=True)[:6]
        time_values = [row.get('timestamp_epoch') for row in component_rows if row.get('timestamp_epoch') is not None]
        cluster_id = f'cluster-{cluster_num}'
        cluster_num += 1
        cluster = {
            'cluster_id': cluster_id,
            'row_refs': [int(row.get('row_index') or 0) for row in component_rows],
            'evidence_refs': [f"R{int(row.get('row_index') or 0)}" for row in component_rows],
            'severity': _severity_label_for_rows(component_rows),
            'confidence': round(sum(float(link.get('confidence') or 0.0) for link in all_links) / max(len(all_links), 1), 2),
        'source_sheets': sorted({_safe_text(row.get('source_sheet') or 'unknown') for row in component_rows}),
        'providers': sorted({_safe_text((row.get('cloud') or {}).get('provider') or row.get('provider_profile') or 'generic') for row in component_rows}),
        'shared_accounts': shared_accounts[:6],
        'shared_hosts': shared_hosts[:6],
        'shared_external_ips': shared_ips[:6],
        'shared_resources': shared_resources[:6],
        'affected_accounts': sorted({item for row in component_rows for item in ((row.get('accounts') or []) + ([((row.get('cloud') or {}).get('account_id'))] if (row.get('cloud') or {}).get('account_id') else []))})[:8],
        'affected_assets': sorted({item for row in component_rows for item in ((row.get('hosts') or []) + (row.get('resources') or []))})[:10],
        'affected_subnets': sorted({item for row in component_rows if (row.get('network') or {}).get('subnet') for item in [(row.get('network') or {}).get('subnet')]})[:6],
        'top_mitre': sorted({item for row in component_rows for item in row.get('mitre') or []})[:6],
        'time_window': {
            'start': min(time_values) if time_values else None,
            'end': max(time_values) if time_values else None,
            'span_seconds': int(max(time_values) - min(time_values)) if len(time_values) >= 2 else 0,
            },
            'lead_description': _build_cluster_lead_description(component_rows, shared_ips, shared_accounts, shared_hosts, cluster_num - 1),
            'reason_summary': _build_cluster_reason_summary(top_links),
            'top_links': [
                {
                    'src': int(lk.get('source_row_index') or 0),
                    'dst': int(lk.get('target_row_index') or 0),
                    'pivot': lk.get('pivot_type', 'unknown'),
                    'conf': lk.get('confidence', 0.0),
                    'summary': lk.get('summary', ''),
                }
                for lk in top_links[:5]
            ],
            'business_significance': '',
            'recommended_logs': [],
        }
        cluster.update(_initial_cluster_verdict(component_rows, cluster['severity']))
        significance = []
        if shared_accounts:
            significance.append('identity compromise or shared actor sequence')
        if shared_hosts:
            significance.append('same endpoint or workload appears across multiple stages')
        if shared_ips:
            significance.append('external infrastructure appears across correlated rows')
        if 'Cloud_AWS' in cluster['source_sheets'] or 'Cloud_Azure' in cluster['source_sheets']:
            significance.append('cloud control changes may widen blast radius')
        if any('Email' in sheet for sheet in cluster['source_sheets']):
            significance.append('mailbox or phishing telemetry suggests user-facing compromise')
        provider_set = {item for item in cluster.get('providers') or [] if item and item != 'generic'}
        if {'aws', 'azure'} <= provider_set or ('okta' in provider_set and {'aws', 'azure'} & provider_set):
            significance.append('cross-cloud identity movement links identity control changes to cloud actions across provider boundaries')
        if 'active_directory' in provider_set and ('vmware' in provider_set or 'nutanix' in provider_set):
            significance.append('on-prem identity and virtualization activity suggest hybrid infrastructure lateral-movement risk')
        if 'email' in provider_set:
            # Require specific BEC indicators before surfacing payment-risk language
            _bec_tokens = ('bcc forwarding', 'inbox rule', 'forwarding rule', 'wire transfer',
                           'beneficiary', 'payment approval', 'finance officer')
            _comp_rows = component_rows
            _joined_lower = ' '.join(_collect_strings_from_row(r).lower() for r in _comp_rows[:40])
            _bec_hits = [t for t in _bec_tokens if t in _joined_lower]
            if len(_bec_hits) >= 2:
                significance.append(
                    f'BEC indicators detected ({", ".join(_bec_hits[:3])}) — '
                    'email activity may affect payment or executive-trust workflows'
                )
            elif _bec_hits:
                significance.append('email activity with possible business-process exposure — verify mailbox audit logs')
        logs = []
        if shared_accounts:
            logs.extend(['identity sign-in logs', 'MFA / Conditional Access decisions'])
        if shared_hosts:
            logs.extend(['EDR process lineage', 'Sysmon Event ID 1/3/11/13'])
        if shared_ips:
            logs.extend(['proxy / firewall egress logs', 'DNS resolution logs'])
        if any('Cloud_AWS' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['CloudTrail', 'S3 data events'])
        if any('Cloud_Azure' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['Azure Activity Log', 'Entra audit logs'])
        if any('Email' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['mailbox audit logs', 'message trace'])
        if 'okta' in provider_set:
            logs.extend(['Okta System Log', 'Okta MFA / sign-on policy audit'])
        if 'active_directory' in provider_set:
            logs.extend(['Windows Security 4624/4625/4768/4769', 'Domain controller authentication logs'])
        if 'vmware' in provider_set:
            logs.extend(['vCenter tasks and events', 'ESXi hostd / vpxa logs'])
        if 'nutanix' in provider_set:
            logs.extend(['Prism Central audit log', 'AHV hypervisor task logs'])
        if 'email' in provider_set:
            logs.extend(['mail transport / secure email gateway logs', 'mailbox rule and delegate audit'])
        cluster['recommended_logs'] = list(dict.fromkeys(logs))[:10]
        compliance = _cluster_controls_and_frameworks(cluster, component_rows)
        provider_count = len([p for p in cluster.get('providers') or [] if p and p != 'generic'])
        cluster['blast_radius_summary'] = (
            f"{len(cluster['affected_accounts'])} account/subscription boundary markers, "
            f"{len(cluster['affected_assets'])} named assets or resources, "
            f"{provider_count or 1} provider context(s)."
        )
        cluster['crown_jewel_likelihood'] = 'medium' if any('admin' in (_safe_text(item).lower()) for item in cluster.get('affected_accounts') or []) else 'low'
        cluster['regulated_data_likelihood'] = 'medium' if any('s3' in (_safe_text(item).lower()) or 'blob' in (_safe_text(item).lower()) or 'mail' in (_safe_text(item).lower()) for item in cluster.get('affected_assets') or []) else 'low'
        cluster['operational_impact_summary'] = 'Correlated activity may affect identity trust, workloads, communications, and control changes in the same case window.'
        cluster['remediation_owner'] = 'Security Operations'
        cluster['communications_owner'] = 'Security leadership'
        cluster['legal_review_recommended'] = cluster['regulated_data_likelihood'] in {'medium', 'high'} or cluster['severity'] == 'critical'
        cluster['pr_statement_recommended'] = cluster['severity'] == 'critical' and len(cluster.get('affected_assets') or []) >= 3
        cluster['notification_obligation_likelihood'] = 'medium' if cluster['legal_review_recommended'] else 'low'
        cluster['affected_frameworks'] = compliance.get('frameworks') or []
        cluster['affected_controls'] = [entry.get('control') for entry in (compliance.get('controls') or []) if entry.get('control')][:12]
        cluster['compliance_control_impact'] = {
            'frameworks': cluster['affected_frameworks'],
            'controls': cluster['affected_controls'],
            'summary': 'Mapped controls should be validated against the exact affected account, subnet, and asset scope before reporting.',
        }
        cluster['financial_impact_min'] = None
        cluster['financial_impact_max'] = None
        cluster['financial_impact_status'] = 'pending_human_input'
        cluster['policy_change_context'] = {
            'suspicious_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('policy_change_context') or {}).get('suspicious_drift')],
            'approved_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('policy_change_context') or {}).get('approved_change')],
        }
        cluster['guest_onboarding_context'] = {
            'guest_rows': [int(row.get('row_index') or 0) for row in component_rows if row.get('guest_onboarding_context')],
            'benign_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('guest_onboarding_context') or {}).get('category') == 'benign_onboarding'],
        }
        posture_contexts = [row.get('security_posture_context') or {} for row in component_rows if row.get('security_posture_context')]
        posture_vendors = sorted({vendor for ctx in posture_contexts for vendor in (ctx.get('vendors') or [])})
        posture_modes = [ctx.get('perimeter_mode') for ctx in posture_contexts if ctx.get('perimeter_mode')]
        posture_mode = (
            'none' if 'none' in posture_modes else
            'dual_firewall' if len(posture_vendors) >= 2 else
            'single_firewall' if len(posture_vendors) == 1 else
            'edge_only' if any(ctx.get('cdn_present') for ctx in posture_contexts) else
            'unspecified'
        )
        cluster['security_posture'] = {
            'vendors': posture_vendors,
            'cdn_present': any(ctx.get('cdn_present') for ctx in posture_contexts),
            'perimeter_mode': posture_mode,
            'benign_mfa_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('security_posture_context') or {}).get('benign_mfa')],
            'compromised_mfa_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('security_posture_context') or {}).get('compromised_mfa')],
            'summary': '',
        }
        posture_summary = (
            'No perimeter firewall telemetry is available in this cluster; validate ingress and egress with ALB, VPC Flow, CDN, and cloud control logs.'
            if posture_mode == 'none'
            else 'Dual next-gen firewall telemetry and cloud-native logs provide layered confirm/deny evidence for this cluster.'
            if posture_mode == 'dual_firewall'
            else 'Partial perimeter telemetry exists; confirm or deny with firewall, CDN, and cloud-native sources together.'
        )
        if cluster['security_posture'].get('compromised_mfa_rows'):
            posture_summary += ' Compromised or fatigued MFA signals are present and should be treated as identity-control degradation.'
        elif cluster['security_posture'].get('benign_mfa_rows'):
            posture_summary += ' Approved MFA activity is present and should remain benign unless later corroborated by malicious evidence.'
        cluster['security_posture']['summary'] = posture_summary
        if posture_mode == 'none':
            significance.append('limited perimeter controls increase blind-spot risk and raise the priority of cloud-native telemetry validation')
        elif posture_mode == 'dual_firewall':
            significance.append('layered perimeter telemetry strengthens ingress and egress confirm/deny analysis')
        if cluster['security_posture'].get('cdn_present'):
            significance.append('CDN edge activity sits between internet-facing delivery and origin workloads')
        if cluster['security_posture'].get('compromised_mfa_rows'):
            significance.append('MFA compromise indicators suggest identity controls may have been bypassed or fatigued')
        if 'okta' in provider_set and 'azure' in provider_set:
            significance.append('federated identity signals span IdP and Azure administrative context in the same incident window')
        if 'active_directory' in provider_set and 'email' in provider_set:
            significance.append('directory and email evidence together raise the likelihood of account takeover or BEC-driven abuse')
        cluster['business_significance'] = '; '.join(significance) or 'multiple evidentiary rows point to one investigation track'
        if 'checkpoint' in posture_vendors:
            logs.append('Check Point traffic / threat logs')
        if 'palo_alto' in posture_vendors:
            logs.append('Palo Alto traffic / threat logs')
        if cluster['security_posture'].get('cdn_present'):
            logs.append('CDN edge access logs')
        if posture_mode == 'none':
            logs.append('ALB access logs / VPC Flow (no perimeter firewall present)')
        cluster['recommended_logs'] = list(dict.fromkeys(logs))[:12]
        # Verdict-aware gate — never hardcode True (see _apply_hvr_gating docstring)
        _apply_hvr_gating(cluster, component_rows)
        cluster['remediation_simulation'] = _build_remediation_simulation(component_rows, cluster['severity'])
        cluster['alb_drain_status'] = cluster.get('remediation_simulation', {}).get('alb_drain_status')
        cluster['replacement_capacity_status'] = cluster.get('remediation_simulation', {}).get('replacement_capacity_status')
        cluster['crisis_management'] = {
            'summary': 'Prepare containment, executive briefing, and customer-impact validation in parallel if this cluster remains confirmed.',
            'actions': [
                'Validate the blast radius with named accounts, subnets, and resources before declaring crisis status.',
                'Route critical clusters to legal and executive owners when regulated data or customer services may be affected.',
            ],
        }
        cluster['legal_considerations'] = {
            'summary': 'Keep legal guidance brief: determine whether regulated data, contractual obligations, or preservation requirements apply.',
            'actions': [
                'Check whether the affected controls map to mandatory notification or evidence-preservation obligations.',
            ],
        }
        cluster['pr_media_guidance'] = {
            'summary': 'Do not issue external statements until row-linked scope, affected services, and communication ownership are confirmed.',
            'recommended': bool(cluster['pr_statement_recommended']),
        }
        cluster['mandatory_communications'] = {
            'summary': 'Use the compliance control impact and regulated-data likelihood to decide whether customer, regulator, or board communications are required.',
            'frameworks': cluster['affected_frameworks'],
        }
        for row in component_rows:
            row['correlation_cluster_id'] = cluster_id
            row['correlation_type'] = 'correlated'
            row['correlation_reasons'] = adjacency.get(int(row.get('row_index') or 0), [])
            row['blast_radius_summary'] = cluster['blast_radius_summary']
            row['affected_frameworks'] = cluster['affected_frameworks']
            row['affected_controls'] = cluster['affected_controls']
            row['human_validation_required'] = cluster['human_validation_required']
            row['playbook_status'] = cluster['playbook_status']
            row['remediation_simulation'] = cluster['remediation_simulation']
            row['alb_drain_status'] = cluster.get('alb_drain_status')
            row['replacement_capacity_status'] = cluster.get('replacement_capacity_status')
            row['security_posture'] = cluster.get('security_posture')
        clusters.append(cluster)

    for row in rows:
        row.setdefault('correlation_type', 'isolated')
        row.setdefault('correlation_reasons', [])
        if 'human_validation_required' not in row:
            _row_hvr = _derive_human_validation_required(
                row,
                policy_ctx=row.get('policy_change_context') or {},
                guest_ctx=row.get('guest_onboarding_context') or {},
            )
            row['human_validation_required'] = _row_hvr
            row['gate_urgency'] = 'NORMAL' if _row_hvr else 'LOW'
            row['playbook_status'] = 'human_gated' if _row_hvr else 'auto_triaged'
        row.setdefault('policy_change_context', {})
        row.setdefault('guest_onboarding_context', {})
        row.setdefault('security_posture_context', {})
        row.setdefault('security_posture', {})
        row.setdefault('remediation_simulation', {})
    clusters.sort(key=lambda item: (_SEV_RANK.get(item.get('severity') or 'low', 0), len(item.get('row_refs') or []), item.get('confidence') or 0.0), reverse=True)
    return clusters, adjacency


def _build_task_entry(task: str, row_refs: List[int], logs: List[str], purpose: str) -> Dict[str, Any]:
    refs = [int(r) for r in row_refs if r is not None]
    return {
        'task': task,
        'row_refs': refs,
        'evidence_refs': [f'R{r}' for r in refs],
        'logs': list(dict.fromkeys(logs))[:8],
        'purpose': purpose,
    }
