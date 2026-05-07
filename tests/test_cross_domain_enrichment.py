"""Tests for cross-domain enrichment modules.

Covers:
  - Crown jewels tagging
  - Infrastructure role classification
  - Account privilege tiering
  - Kill chain completeness scoring
  - Cluster separation (non-related event annotation)
  - Identity reconciliation bridge in cluster_builder
"""
from __future__ import annotations

import pytest


# ─── Crown Jewels ─────────────────────────────────────────────────────────────

def test_crown_jewel_dc_hostname():
    from src.core.enrichment.crown_jewels import tag_cluster_crown_jewels
    cluster = {'cluster_id': 'c1', 'shared_hosts': ['dc01.corp.com', 'ws100'],
               'severity': 'medium', 'confidence_meter': {'total': 30.0}}
    tag_cluster_crown_jewels(cluster, [])
    assert cluster['crown_jewel'] is True
    assert 'domain_controller' in cluster['crown_jewel_roles']
    # Severity should be uplifted to high
    assert cluster['severity'] == 'high'
    # Confidence boosted
    assert cluster['confidence_meter']['total'] > 30.0


def test_crown_jewel_no_match():
    from src.core.enrichment.crown_jewels import tag_cluster_crown_jewels
    cluster = {'cluster_id': 'c2', 'shared_hosts': ['ws100', 'laptop-alice']}
    tag_cluster_crown_jewels(cluster, [])
    assert cluster['crown_jewel'] is False
    assert cluster['crown_jewel_assets'] == []


def test_crown_jewel_database_port_row():
    from src.core.enrichment.crown_jewels import tag_cluster_crown_jewels
    cluster = {'cluster_id': 'c3', 'shared_hosts': []}
    rows = [{'host': 'sql-prod.corp.com', 'dst_port': 1433}]
    tag_cluster_crown_jewels(cluster, rows)
    assert cluster['crown_jewel'] is True
    assert 'database_server' in cluster['crown_jewel_roles']


def test_crown_jewel_operator_defined(monkeypatch):
    from src.core.enrichment import crown_jewels
    monkeypatch.setenv('CROWN_JEWELS_ASSETS', '["billing.corp.com","payments.corp.com"]')
    cluster = {'cluster_id': 'c4', 'shared_hosts': ['billing.corp.com']}
    crown_jewels.tag_cluster_crown_jewels(cluster, [])
    assert cluster['crown_jewel'] is True
    assert any(m['role'] == 'operator_defined' for m in cluster['crown_jewel_assets'])


# ─── Infrastructure Roles ─────────────────────────────────────────────────────

def test_infra_roles_domain_controller():
    from src.core.enrichment.infra_roles import classify_cluster_infra
    cluster = {'cluster_id': 'c1', 'shared_hosts': ['dc01.corp.com'],
               'top_mitre': ['T1558'], 'severity': 'medium',
               'confidence_meter': {'total': 40.0}}
    classify_cluster_infra(cluster, [])
    assert 'domain_controller' in cluster['infra_roles']
    assert 'domain_controller' in cluster['high_value_targets']
    assert cluster['infra_tier'] == 0
    # Tier-0 infra → severity uplifted
    assert cluster['severity'] == 'high'


def test_infra_roles_lateral_to_hv():
    from src.core.enrichment.infra_roles import classify_cluster_infra
    cluster = {
        'cluster_id': 'c2',
        'shared_hosts': ['sqlsrv01.corp.com'],
        'top_mitre': ['T1021.002'],  # SMB lateral movement
    }
    classify_cluster_infra(cluster, [])
    assert 'database_server' in cluster['infra_roles']
    assert cluster['lateral_to_hv_target'] is True


def test_infra_roles_no_match():
    from src.core.enrichment.infra_roles import classify_cluster_infra
    cluster = {'cluster_id': 'c3', 'shared_hosts': ['laptop-bob']}
    classify_cluster_infra(cluster, [])
    assert cluster['infra_roles'] == {}
    assert cluster['high_value_targets'] == []


# ─── Account Tiers ────────────────────────────────────────────────────────────

def _tier(account):
    from src.core.enrichment.account_tiers import _tier_for_account
    return _tier_for_account(account)


def test_tier0_domain_admin():
    assert _tier('Domain Admins') == 0
    assert _tier('CORP\\Administrator') == 0
    assert _tier('GlobalAdmin@tenant.onmicrosoft.com') == 0
    assert _tier('krbtgt') == 0


def test_tier1_service_account():
    assert _tier('svc_backup') == 1
    assert _tier('svc.deploy@corp.com') == 1
    assert _tier('helpdesk@corp.com') == 1


def test_tier2_standard_user():
    assert _tier('alice@corp.com') == 2
    assert _tier('bob.smith') == 2


def test_classify_cluster_accounts_tier0_uplift():
    from src.core.enrichment.account_tiers import classify_cluster_accounts
    cluster = {
        'cluster_id': 'c1',
        'shared_accounts': ['domain admin', 'alice@corp.com'],
        'severity': 'medium',
        'confidence_meter': {'total': 40.0},
    }
    classify_cluster_accounts(cluster, [])
    assert cluster['min_account_tier'] == 0
    assert 'domain admin' in cluster['tier0_accounts']
    assert cluster['severity'] == 'critical'
    assert cluster['confidence_meter']['total'] > 40.0


# ─── Kill Chain Scoring ───────────────────────────────────────────────────────

def test_kill_chain_full_cycle():
    from src.core.enrichment.kill_chain_score import score_cluster_kill_chain, PHASES
    # Provide techniques from all 9 phases
    full_mitre = [
        'T1595',  # recon
        'T1190',  # initial_access
        'T1059',  # execution
        'T1547',  # persistence
        'T1548',  # privilege_escalation
        'T1021',  # lateral_movement
        'T1005',  # collection
        'T1041',  # exfiltration
        'T1486',  # impact
    ]
    cluster = {'cluster_id': 'c1', 'top_mitre': full_mitre, 'confidence_meter': {'total': 50.0}}
    score_cluster_kill_chain(cluster, [])
    assert cluster['kill_chain_completeness'] == 1.0
    assert cluster['kill_chain_stage_label'] == 'Full-Cycle'
    assert cluster['kill_chain_phase_count'] == 9
    assert cluster['kill_chain_gaps'] == []
    # Confidence boosted
    assert cluster['confidence_meter']['total'] > 50.0


def test_kill_chain_early_stage():
    from src.core.enrichment.kill_chain_score import score_cluster_kill_chain
    cluster = {'cluster_id': 'c2', 'top_mitre': ['T1566']}  # just phishing
    score_cluster_kill_chain(cluster, [])
    assert cluster['kill_chain_stage_label'] == 'Early-Stage'
    assert cluster['kill_chain_phase_count'] == 1


def test_kill_chain_no_mitre():
    from src.core.enrichment.kill_chain_score import score_cluster_kill_chain
    cluster = {'cluster_id': 'c3', 'top_mitre': []}
    score_cluster_kill_chain(cluster, [])
    assert cluster['kill_chain_completeness'] == 0.0
    assert cluster['kill_chain_stage_label'] == 'No Kill-Chain Signal'


# ─── Cluster Separation ───────────────────────────────────────────────────────

def test_separation_only_infra_shared():
    from src.core.enrichment.cluster_separation import annotate_cluster_separation
    c1 = {
        'cluster_id': 'cl-1',
        'shared_accounts': [],
        'shared_hosts': [],
        'shared_external_ips': ['5.5.5.5'],
        'top_mitre': ['T1190'],
    }
    c2 = {
        'cluster_id': 'cl-2',
        'shared_accounts': [],
        'shared_hosts': [],
        'shared_external_ips': ['5.5.5.5'],
        'top_mitre': ['T1486'],
    }
    annotate_cluster_separation([c1, c2])
    # Should flag as only infra shared and likely unrelated (no account/host/MITRE overlap)
    sep = c1['separation']['cl-2']
    assert sep['only_infra_shared'] is True
    assert sep['likely_unrelated'] is True


def test_separation_shared_account_related():
    from src.core.enrichment.cluster_separation import annotate_cluster_separation
    c1 = {
        'cluster_id': 'cl-1',
        'shared_accounts': ['alice@corp.com'],
        'shared_hosts': [],
        'shared_external_ips': [],
        'top_mitre': [],
    }
    c2 = {
        'cluster_id': 'cl-2',
        'shared_accounts': ['alice@corp.com'],
        'shared_hosts': [],
        'shared_external_ips': [],
        'top_mitre': [],
    }
    annotate_cluster_separation([c1, c2])
    sep = c1['separation']['cl-2']
    assert sep['likely_unrelated'] is False
    assert 'alice@corp.com' in sep['shared_accounts']
    assert c1['likely_isolated'] is False


def test_separation_single_cluster_isolated():
    from src.core.enrichment.cluster_separation import annotate_cluster_separation
    c1 = {
        'cluster_id': 'cl-1',
        'shared_accounts': ['alice@corp.com'],
        'shared_hosts': [],
        'shared_external_ips': [],
        'top_mitre': [],
    }
    annotate_cluster_separation([c1])
    assert c1['likely_isolated'] is True


# ─── Identity reconciliation bridge ──────────────────────────────────────────

def test_identity_ip_bridge_links_rows():
    """Okta login row from IP 5.6.7.8 should bridge to a Zeek row seeing the same IP."""
    from src.api.deep_analyze.cluster_builder import _build_identity_ip_bridge

    identity_row = {
        'row_index': 0,
        'source_sheet': 'Okta',
        'accounts': ['alice@corp.com'],
        'client_ip': '5.6.7.8',
        'external_ips': ['5.6.7.8'],
    }
    network_row = {
        'row_index': 1,
        'source_sheet': 'Network_Zeek',
        'accounts': [],
        'external_ips': ['5.6.7.8'],
    }
    row_map = {0: identity_row, 1: network_row}
    bridge = _build_identity_ip_bridge(row_map)
    assert '5.6.7.8' in bridge
    assert 'alice@corp.com' in bridge['5.6.7.8']


def test_identity_bridge_not_built_for_non_identity():
    """A pure network row should not contribute to the identity bridge."""
    from src.api.deep_analyze.cluster_builder import _build_identity_ip_bridge
    network_row = {
        'row_index': 0,
        'source_sheet': 'Firewall',
        'accounts': [],
        'external_ips': ['9.9.9.9'],
    }
    bridge = _build_identity_ip_bridge({0: network_row})
    assert bridge == {}


def test_xdomain_pivot_connects_network_to_identity():
    """After bridge injection, the inverted index should have xid: keys linking
    the network row to the identity row's account bucket."""
    from src.api.deep_analyze.cluster_builder import (
        _build_identity_ip_bridge, _build_inverted_index,
    )
    identity_row = {
        'row_index': 0,
        'source_sheet': 'Okta',
        'accounts': ['alice@corp.com'],
        'client_ip': '5.6.7.8',
        'external_ips': ['5.6.7.8'],
        'hosts': [], 'resources': [], 'mitre': [], 'external_ips': ['5.6.7.8'],
    }
    network_row = {
        'row_index': 1,
        'source_sheet': 'Network_Zeek',
        'accounts': [],
        'external_ips': ['5.6.7.8'],
        'dst_ip': '5.6.7.8',
        'hosts': [], 'resources': [], 'mitre': [],
    }
    row_map = {0: identity_row, 1: network_row}
    bridge = _build_identity_ip_bridge(row_map)
    idx = _build_inverted_index(row_map, _identity_bridge=bridge)

    # The xid:<account> bucket should contain BOTH the identity row AND the network row
    xid_key = 'xid:alice@corp.com'
    assert xid_key in idx, f'Expected {xid_key} in index; got {sorted(idx.keys())}'
    assert 1 in idx[xid_key], 'Network row should be in xid bucket'
