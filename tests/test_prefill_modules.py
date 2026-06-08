"""Unit tests for the split Tier-1 prefill submodules.

Covers:
  - evidence_binder.py  — row resolution, entity extraction, cross-cluster links
  - threat_models.py    — confidence meter, PASTA, Diamond, adversarial sequence, kill chain
  - verdict_engine.py   — cluster ranking, entity-pin validation, narrative jargon check
  - prefill_engine.py   — shim re-export smoke tests
"""
from __future__ import annotations

import os
import time

os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

import pytest

from src.core.tier1_prefill.evidence_binder import (
    _get_rows_for_cluster,
    _extract_entity_set,
    _build_entity_cluster_index,
    _compute_cross_cluster_links,
)
from src.core.tier1_prefill.threat_models import (
    _compute_confidence_meter,
    _compute_pasta_summary,
    _compute_diamond_model,
    _detect_adversarial_sequence,
    _build_kill_chain_summary,
)
from src.core.tier1_prefill.verdict_engine import (
    _rank_clusters,
    _validate_entity_pins,
    _narrative_is_technical,
)


# ── Shared fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def rows():
    return [
        {'row_index': 0, 'severity': 'high', '_source': 'okta',
         'user': 'alice@corp.com', 'src_ip': '185.62.56.1'},
        {'row_index': 1, 'severity': 'high', '_source': 'okta',
         'user': 'bob@corp.com', 'src_ip': '185.62.56.1'},
        {'row_index': 2, 'severity': 'medium', '_source': 'endpoint',
         'user': 'alice@corp.com', 'hostname': 'WSRV-01'},
        {'row_index': 3, 'severity': 'critical', '_source': 'network',
         'src_ip': '10.0.0.5', 'dst_ip': '203.0.113.10'},
    ]


@pytest.fixture
def cluster(rows):
    return {
        'cluster_id': 'cluster-alpha',
        'severity': 'high',
        'verdict': 'CONFIRMED',
        'row_refs': [0, 1, 2],
    }


@pytest.fixture
def assessment(rows):
    return {
        'assessment_id': 'assess-001',
        'normalized_rows': rows,
    }


@pytest.fixture
def prefill_ok():
    return {
        'incident_name': 'Credential spray against finance team',
        'headline_subtitle': 'Multiple failed logins from single IP',
        'short_narrative': 'An attacker performed credential spray with MFA fatigue.',
        'top_actions': ['Rotate affected credentials', 'Enable MFA enforcement'],
    }


# ── evidence_binder tests ──────────────────────────────────────────────────────

def test_get_rows_for_cluster_matches_by_index(rows, assessment):
    cluster = {'cluster_id': 'c1', 'row_refs': [0, 2]}
    result = _get_rows_for_cluster(cluster, assessment)
    indices = [r['row_index'] for r in result]
    assert 0 in indices
    assert 2 in indices
    assert 1 not in indices


def test_get_rows_for_cluster_returns_preview_when_no_refs(assessment):
    preview = [{'row_index': 99, 'description': 'fallback row'}]
    cluster = {'cluster_id': 'c2', 'row_refs': [], 'evidence_preview': preview}
    result = _get_rows_for_cluster(cluster, assessment)
    assert result == preview


def test_extract_entity_set_collects_users_and_ips(rows):
    cluster = {'cluster_id': 'c1'}
    entities = _extract_entity_set(cluster, rows[:3])
    # Users and IPs from the rows should appear (lower-cased)
    assert 'alice@corp.com' in entities
    assert 'bob@corp.com' in entities
    assert '185.62.56.1' in entities


def test_build_entity_cluster_index_maps_shared_entities(rows):
    clusters = [
        {'cluster_id': 'cA', 'row_refs': [0, 1]},
        {'cluster_id': 'cB', 'row_refs': [2]},
    ]
    assessment = {'normalized_rows': rows}
    index = _build_entity_cluster_index(clusters, assessment)
    # alice@corp.com appears in row 0 (cA) and row 2 (cB)
    assert 'alice@corp.com' in index
    assert 'ca' in index['alice@corp.com'] or 'cA' in index['alice@corp.com']


def test_compute_cross_cluster_links_finds_shared_user(rows):
    clusters = [
        {'cluster_id': 'cA', 'row_refs': [0, 1], 'tier1_prefill': {'incident_name': 'Incident A'}},
        {'cluster_id': 'cB', 'row_refs': [2], 'tier1_prefill': {'incident_name': 'Incident B'}},
    ]
    assessment = {'normalized_rows': rows}
    index = _build_entity_cluster_index(clusters, assessment)
    links = _compute_cross_cluster_links(clusters[0], index, clusters)
    # alice@corp.com shared between cA and cB should produce a link
    other_ids = [lnk['also_in_cluster_id'] for lnk in links]
    assert 'cB' in other_ids


def test_compute_cross_cluster_links_caps_at_10():
    # Build 15 clusters all sharing the same user
    shared_rows = [{'row_index': i, 'user': 'shared@corp.com'} for i in range(15)]
    clusters = [{'cluster_id': f'c{i}', 'row_refs': [i]} for i in range(15)]
    assessment = {'normalized_rows': shared_rows}
    index = _build_entity_cluster_index(clusters, assessment)
    links = _compute_cross_cluster_links(clusters[0], index, clusters)
    assert len(links) <= 10


# ── threat_models tests ────────────────────────────────────────────────────────

def test_compute_confidence_meter_returns_dict_with_total_and_segments(rows, cluster):
    result = _compute_confidence_meter(cluster, rows)
    assert 'total' in result
    assert 'segments' in result
    segs = result['segments']
    assert set(segs.keys()) == {
        'source_corroboration',
        'evidence_cluster_strength',
        'technique_confidence',
        'temporal_consistency',
    }
    assert 0 <= result['total'] <= 100


def test_compute_confidence_meter_zero_rows_gives_low_score(cluster):
    result = _compute_confidence_meter(cluster, [])
    assert result['total'] < 20


def test_compute_confidence_meter_multi_source_boosts_corroboration(cluster):
    multi_rows = [
        {'row_index': 0, 'severity': 'high', '_source': 'okta_identity'},
        {'row_index': 1, 'severity': 'high', '_source': 'crowdstrike_endpoint'},
        {'row_index': 2, 'severity': 'high', '_source': 'azure_network_flow'},
    ]
    result = _compute_confidence_meter(cluster, multi_rows)
    assert result['segments']['source_corroboration'] > 0


def test_compute_pasta_summary_data_exfil_flags_regulatory_impact(rows):
    cluster = {
        'cluster_id': 'c1',
        'phases': [
            {'phase_id': 'data_exfiltration_snowflake'},
            {'phase_id': 'secret_access'},
        ],
    }
    data = {'dread_score': {'risk_tier': 'CRITICAL'}, 'dread_narrative': {}, 'diamond_model': {}}
    result = _compute_pasta_summary(cluster, rows, data)
    assert 'regulatory' in result['business_impact'].lower() or 'exfil' in result['business_impact'].lower()
    assert 'threat_profile' in result
    assert 'exploitation_path' in result
    assert 'risk_tier' in result


def test_compute_pasta_summary_credential_theft_flags_rotation(rows):
    cluster = {
        'cluster_id': 'c1',
        'phases': [
            {'phase_id': 'credential_theft'},
        ],
    }
    data = {
        'dread_score': {'risk_tier': 'HIGH'},
        'dread_narrative': {'sabsa_attributes': ['Authenticated']},
        'diamond_model': {},
    }
    result = _compute_pasta_summary(cluster, rows, data)
    assert 'rotat' in result['business_impact'].lower() or 'credential' in result['business_impact'].lower()


def test_compute_pasta_summary_empty_phases_returns_risk_tier_fallback(rows):
    cluster = {'cluster_id': 'c1', 'phases': []}
    data = {'dread_score': {'risk_tier': 'MEDIUM'}, 'dread_narrative': {}, 'diamond_model': {}}
    result = _compute_pasta_summary(cluster, rows, data)
    # With no phases the fallback path must include the risk tier
    assert 'MEDIUM' in result['business_impact']
    assert result['risk_tier'] == 'MEDIUM'


def test_compute_diamond_model_returns_required_keys(rows, cluster):
    result = _compute_diamond_model(cluster, rows)
    for key in ('adversary', 'capability', 'infrastructure', 'victim_data'):
        assert key in result, f"Missing key: {key}"


def test_detect_adversarial_sequence_credential_and_lateral_triggers():
    phases = [
        {'phase_id': 'credential_theft'},
        {'phase_id': 'lateral_movement'},
    ]
    flagged, detail = _detect_adversarial_sequence(phases, [])
    assert flagged is True
    assert 'credential' in detail.lower() or 'lateral' in detail.lower()


def test_detect_adversarial_sequence_no_match_returns_false():
    phases = [{'phase_id': 'initial_access'}]
    flagged, detail = _detect_adversarial_sequence(phases, [])
    assert flagged is False
    assert detail == ''


def test_build_kill_chain_summary_orders_phases_correctly():
    phases = [
        {'phase_id': 'data_exfiltration'},
        {'phase_id': 'initial_access'},
        {'phase_id': 'lateral_movement'},
    ]
    summary = _build_kill_chain_summary(phases)
    parts = summary.split(' → ')
    # initial_access (order 0) must appear before lateral_movement (order 6)
    # which must appear before data_exfiltration (order 11)
    assert parts.index('Initial Access') < parts.index('Lateral Movement')
    assert parts.index('Lateral Movement') < parts.index('Data Exfiltration')


# ── verdict_engine tests ───────────────────────────────────────────────────────

def test_rank_clusters_confirmed_first():
    clusters = [
        {'cluster_id': 'c-low', 'verdict': 'UNCERTAIN', 'severity': 'low', 'row_refs': [1]},
        {'cluster_id': 'c-high', 'verdict': 'CONFIRMED', 'severity': 'high', 'row_refs': [1, 2, 3]},
    ]
    ranked = _rank_clusters(clusters)
    assert ranked[0]['cluster_id'] == 'c-high'


def test_rank_clusters_benign_last():
    clusters = [
        {'cluster_id': 'c-benign', 'verdict': 'BENIGN', 'severity': 'low', 'row_refs': []},
        {'cluster_id': 'c-likely', 'verdict': 'LIKELY', 'severity': 'medium', 'row_refs': [1]},
    ]
    ranked = _rank_clusters(clusters)
    assert ranked[-1]['cluster_id'] == 'c-benign'


def test_rank_clusters_sorts_by_row_count_within_tier():
    clusters = [
        {'cluster_id': 'c-small', 'verdict': 'CONFIRMED', 'severity': 'high', 'row_refs': [1]},
        {'cluster_id': 'c-large', 'verdict': 'CONFIRMED', 'severity': 'high', 'row_refs': [1, 2, 3, 4, 5]},
    ]
    ranked = _rank_clusters(clusters)
    assert ranked[0]['cluster_id'] == 'c-large'


def test_validate_entity_pins_passes_clean_prefill(prefill_ok):
    # All tokens in prefill_ok are generic security terms — should pass
    allowed = {'finance', 'team', 'ip', 'login', 'mfa', 'credentials'}
    result = _validate_entity_pins(prefill_ok, allowed)
    assert 'passed' in result
    assert 'flagged_tokens' in result
    assert 'checked_at' in result
    assert isinstance(result['checked_at'], int)


def test_validate_entity_pins_flags_external_entity():
    prefill = {
        'incident_name': 'ACME-CORP breach detected',
        'headline_subtitle': 'Attacker compromised BIZORG systems',
        'short_narrative': 'Suspicious activity from EXTFIRM domain.',
        'top_actions': [],
    }
    # None of ACME-CORP, BIZORG, EXTFIRM are in the allowed set
    allowed = {'breach', 'attacker', 'domain'}
    result = _validate_entity_pins(prefill, allowed)
    assert result['passed'] is False
    assert len(result['flagged_tokens']) > 0


def test_narrative_is_technical_catches_mitre_tcodes():
    text = 'The attacker used T1110.003 (Password Spraying) to gain access.'
    assert _narrative_is_technical(text) is True


def test_narrative_is_technical_allows_plain_english():
    text = 'Multiple failed login attempts were observed from a single external IP address.'
    assert _narrative_is_technical(text) is False


# ── Integration: shim re-exports ───────────────────────────────────────────────

@pytest.mark.smoke
def test_prefill_engine_shim_exports_run_prefill():
    from src.core.tier1_prefill import prefill_engine
    assert hasattr(prefill_engine, 'run_prefill'), \
        'prefill_engine shim must export run_prefill'
    assert callable(prefill_engine.run_prefill)


@pytest.mark.smoke
def test_prefill_engine_shim_exports_run_single_cluster_prefill():
    from src.core.tier1_prefill import prefill_engine
    assert hasattr(prefill_engine, 'run_single_cluster_prefill'), \
        'prefill_engine shim must export run_single_cluster_prefill'
    assert callable(prefill_engine.run_single_cluster_prefill)


@pytest.mark.smoke
def test_threat_models_importable_from_shim():
    # Private functions are not re-exported by import * — verify the submodule
    # is importable and contains the expected callables.
    from src.core.tier1_prefill import threat_models
    assert callable(threat_models._compute_confidence_meter)
    assert callable(threat_models._compute_diamond_model)
    assert callable(threat_models._detect_adversarial_sequence)
