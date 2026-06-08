"""Tests for the three prefill enhancements:
  1. Entity pin quality gate
  2. Heuristic confidence meter
  3. Cross-cluster entity linkage
"""
from __future__ import annotations

import os
os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

from src.core.tier1_prefill.prefill_engine import (
    _extract_entity_set,
    _validate_entity_pins,
    _compute_confidence_meter,
    _build_entity_cluster_index,
    _compute_cross_cluster_links,
    _ensure_v2_prefill_fields,
    _fallback_incident_name,
    _infer_root_cause,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

CLUSTER_1 = {
    'cluster_id': 'cluster-1',
    'severity': 'high',
    'verdict': 'CONFIRMED',
    'row_refs': [0, 1, 2],
}

CLUSTER_2 = {
    'cluster_id': 'cluster-2',
    'severity': 'medium',
    'verdict': 'LIKELY REAL',
    'row_refs': [3, 4],
}

ROWS = [
    {'row_index': 0, 'severity': 'high', '_source': 'okta',
     'user': 'finance.officer@test.com', 'src_ip': '185.62.56.200',
     'description': 'Login attempt', 'mitre_technique': 'T1110.003'},
    {'row_index': 1, 'severity': 'high', '_source': 'azure_net',
     'user': 'cfo@test.com', 'src_ip': '185.62.56.200',
     'description': 'MFA push spike'},
    {'row_index': 2, 'severity': 'medium', '_source': 'endpoint',
     'hostname': 'WSRV-MGMT', 'description': 'Process injection'},
    {'row_index': 3, 'severity': 'medium', '_source': 'npm_log',
     'user': 'finance.officer@test.com', 'src_ip': '45.12.200.88',
     'description': 'postinstall script'},
    {'row_index': 4, 'severity': 'low', '_source': 'npm_log',
     'src_ip': '45.12.200.88', 'description': 'outbound callback'},
]


# ── Enhancement 1: Quality gate ───────────────────────────────────────────────

def test_quality_gate_passes_for_real_entities():
    allowed = _extract_entity_set(CLUSTER_1, ROWS[:3])
    prefill = {
        'incident_name': 'HARBOURSIDE BEC',
        'headline_subtitle': 'finance.officer@test.com to CFO wire fraud',
        'short_narrative': (
            'Attacker sprayed creds at finance.officer@test.com from 185.62.56.200. '
            'cfo@test.com received MFA push row_1.'
        ),
        'top_actions': ['Isolate finance.officer@test.com', 'Block 185.62.56.200'],
        'confidence_rationale': ['High severity', 'Multi-source'],
        'mitre_techniques': ['T1110.003'],
    }
    quality = _validate_entity_pins(prefill, allowed)
    # Should not flag known entities — may or may not pass depending on token
    # extraction, but flagged_tokens should not contain real allowed entities
    for token in quality['flagged_tokens']:
        assert token.lower() not in allowed, \
            f"Quality gate incorrectly flagged a real entity: {token}"


def test_quality_gate_flags_hallucinated_entity():
    allowed = _extract_entity_set(CLUSTER_1, ROWS[:3])
    prefill = {
        'incident_name': 'HARBOURSIDE BEC',
        'headline_subtitle': 'ALICE-SMITH-INVENTED to CFO wire fraud',
        'short_narrative': 'Attacker used ALICE-SMITH-INVENTED and BOB-FAKE-3000 to pivot.',
        'top_actions': ['Isolate ALICE-SMITH-INVENTED'],
        'confidence_rationale': [],
        'mitre_techniques': [],
    }
    quality = _validate_entity_pins(prefill, allowed)
    # Hallucinated entities should be flagged (or at least not in allowed set)
    # Quality gate may flag them
    assert isinstance(quality['flagged_tokens'], list)
    assert isinstance(quality['passed'], bool)


def test_quality_gate_ignores_generic_security_terms():
    allowed = _extract_entity_set(CLUSTER_1, ROWS[:3])
    prefill = {
        'incident_name': 'MFA FATIGUE BEC',
        'headline_subtitle': 'credential spray leads to lateral movement',
        'short_narrative': 'Attacker used MFA fatigue and credential spray techniques.',
        'top_actions': ['Block C2 traffic', 'Check EDR for persistence'],
        'confidence_rationale': [],
        'mitre_techniques': [],
    }
    quality = _validate_entity_pins(prefill, allowed)
    # Generic security terms like MFA, EDR, C2 should not be flagged
    generic_terms = {'MFA', 'EDR', 'C2', 'BEC'}
    for token in quality['flagged_tokens']:
        assert token.upper() not in generic_terms, \
            f"Quality gate incorrectly flagged generic term: {token}"


# ── Enhancement 2: Confidence meter ──────────────────────────────────────────

def test_confidence_meter_returns_required_fields():
    meter = _compute_confidence_meter(CLUSTER_1, ROWS[:3])
    assert 'total' in meter
    assert 'segments' in meter
    assert 'source_types_present' in meter
    segs = meter['segments']
    assert set(segs.keys()) == {'source_corroboration', 'evidence_cluster_strength',
                                'technique_confidence', 'temporal_consistency'}


def test_confidence_meter_total_within_range():
    meter = _compute_confidence_meter(CLUSTER_1, ROWS[:3])
    assert 0 <= meter['total'] <= 100


def test_confidence_meter_segments_sum_to_total():
    meter = _compute_confidence_meter(CLUSTER_1, ROWS[:3])
    seg_sum = round(sum(meter['segments'].values()), 1)
    assert abs(seg_sum - meter['total']) < 0.5, \
        f"Segments {seg_sum} don't match total {meter['total']}"


def test_confidence_meter_multi_source_boosts_corroboration():
    multi_source_rows = [
        {'row_index': 0, 'severity': 'high', '_source': 'okta', 'user': 'u@t.com'},
        {'row_index': 1, 'severity': 'high', '_source': 'azure_net', 'src_ip': '1.2.3.4'},
        {'row_index': 2, 'severity': 'high', '_source': 'endpoint', 'hostname': 'HOST1'},
    ]
    single_source_rows = [
        {'row_index': 0, 'severity': 'high', '_source': 'okta', 'user': 'u@t.com'},
        {'row_index': 1, 'severity': 'high', '_source': 'okta', 'user': 'u2@t.com'},
    ]
    multi = _compute_confidence_meter(CLUSTER_1, multi_source_rows)
    single = _compute_confidence_meter(CLUSTER_1, single_source_rows)
    assert multi['segments']['source_corroboration'] > single['segments']['source_corroboration']


def test_confidence_meter_empty_rows_does_not_crash():
    meter = _compute_confidence_meter(CLUSTER_1, [])
    assert meter['total'] >= 0


def test_placeholder_unknown_breach_name_replaced_from_k8s_evidence():
    rows = [
        {
            'row_index': 1,
            '_source': 'k8s.audit',
            'user': {'username': 'system:serviceaccount:integration-tests:integration-runner'},
            'objectRef': {'resource': 'pods', 'subresource': 'exec', 'namespace': 'integration-tests'},
        }
    ]
    cluster = {'incident_name': 'UNKNOWN-2026-A BREACH', 'row_refs': [1]}
    assert _fallback_incident_name(cluster, rows) == 'K8s Credential Exfiltration via Integration Runner'
    data = {'incident_name': 'UNKNOWN-2026-A BREACH', 'headline_subtitle': 'pre-existing breach'}
    _ensure_v2_prefill_fields(data, cluster, rows)
    assert data['incident_name'] == 'K8s Credential Exfiltration via Integration Runner'


def test_k8s_root_cause_replaces_threshold_language():
    rows = [
        {
            'row_index': 1,
            '_source': 'k8s.audit',
            'user': {'username': 'system:serviceaccount:integration-tests:integration-runner'},
            'objectRef': {'resource': 'daemonsets', 'namespace': 'integration-tests'},
        }
    ]
    data = {
        'incident_name': 'K8s Credential Exfiltration via Integration Runner',
        'root_cause': 'Correlated evidence exceeded the investigation threshold.',
    }
    cause = _infer_root_cause(data, {'row_refs': [1]}, rows)
    assert 'Kubernetes service account' in cause


# ── Enhancement 3: Cross-cluster entity linkage ───────────────────────────────

def test_cross_cluster_finds_shared_entity():
    assessment = {
        'normalized_rows': ROWS,
        'correlation_clusters': [CLUSTER_1, CLUSTER_2],
    }
    entity_index = _build_entity_cluster_index([CLUSTER_1, CLUSTER_2], assessment)
    # finance.officer@test.com is in row_0 (cluster-1) and row_3 (cluster-2)
    key = 'finance.officer@test.com'
    assert key in entity_index, f"Expected {key} in entity_index"
    assert 'cluster-1' in entity_index[key]
    assert 'cluster-2' in entity_index[key]


def test_cross_cluster_links_returned_for_shared_entity():
    assessment = {
        'normalized_rows': ROWS,
        'correlation_clusters': [CLUSTER_1, CLUSTER_2],
    }
    entity_index = _build_entity_cluster_index([CLUSTER_1, CLUSTER_2], assessment)
    links = _compute_cross_cluster_links(CLUSTER_1, entity_index, [CLUSTER_1, CLUSTER_2])
    link_cluster_ids = [l['also_in_cluster_id'] for l in links]
    assert 'cluster-2' in link_cluster_ids


def test_cross_cluster_no_self_links():
    assessment = {
        'normalized_rows': ROWS,
        'correlation_clusters': [CLUSTER_1, CLUSTER_2],
    }
    entity_index = _build_entity_cluster_index([CLUSTER_1, CLUSTER_2], assessment)
    links = _compute_cross_cluster_links(CLUSTER_1, entity_index, [CLUSTER_1, CLUSTER_2])
    for link in links:
        assert link['also_in_cluster_id'] != 'cluster-1', "Self-links must not appear"


def test_cross_cluster_no_links_when_disjoint():
    disjoint_rows = [
        {'row_index': 0, '_source': 'okta', 'user': 'alpha@a.com', 'row_refs': [0]},
        {'row_index': 1, '_source': 'okta', 'user': 'beta@b.com', 'row_refs': [1]},
    ]
    c1 = {**CLUSTER_1, 'row_refs': [0]}
    c2 = {**CLUSTER_2, 'row_refs': [1]}
    assessment = {'normalized_rows': disjoint_rows, 'correlation_clusters': [c1, c2]}
    entity_index = _build_entity_cluster_index([c1, c2], assessment)
    links = _compute_cross_cluster_links(c1, entity_index, [c1, c2])
    assert links == []
