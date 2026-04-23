from __future__ import annotations

import os

os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

from src.api.breach_endpoints import _cluster_rows as breach_cluster_rows
from src.core.tier1_prefill.prefill_engine import (
    _ensure_v2_prefill_fields,
    _get_rows_for_cluster,
    _row_action_text,
)


def test_disjoint_normalized_rows_fall_back_to_evidence_preview_for_breach_case():
    real_row = {
        'row_index': 5709,
        '_source': 'snowflake.query_history',
        'start_time': '2026-02-20T14:39:00.000Z',
        'user_name': 'SVC_SFL_ANALYTICS_FED',
        'query_type': 'UNLOAD',
        'query_text': 'COPY INTO @tmp_unload_stg/manifests_batch_01.csv.gz FROM SFL_DATA.PUBLIC.CUSTOMER_SHIPPING_MANIFESTS',
        'rows_produced': 1410000,
        'client_ip': '91.240.118.7',
    }
    assessment = {
        'normalized_rows': [{'row_index': 28590, '_source': 'irrelevant'}],
        'correlation_clusters': [],
    }
    cluster = {
        'cluster_id': 'case-primary-breach',
        'verdict': 'VALIDATED_BREACH',
        'row_refs': [5709],
        'evidence_preview': [real_row],
    }

    rows = _get_rows_for_cluster(cluster, assessment)
    assert rows == [real_row]

    cached_prefill = {
        'incident_name': 'PRIMARY BREACH',
        'root_cause': 'Correlated evidence exceeded the investigation threshold.',
        'observed_impact': {
            'identity': 'No named identity extracted.',
            'data': 'No confirmed data loss field was present in the supplied telemetry.',
            'operational': 'Containment scope depends on the correlated evidence rows.',
        },
        'verdict_reasoning': 'VALIDATED_BREACH',
    }
    _ensure_v2_prefill_fields(cached_prefill, cluster, rows)

    assert 'cloud storage' in cached_prefill['root_cause']
    assert 'SVC_SFL_ANALYTICS_FED' in cached_prefill['observed_impact']['identity']
    assert 'Bulk data export' in cached_prefill['observed_impact']['data']
    assert 'VALIDATED_BREACH' != cached_prefill['verdict_reasoning']


def test_partial_normalized_overlap_still_merges_evidence_preview():
    matched_row = {
        'row_index': 29141,
        '_source': 'crowdstrike',
        'event_simpleName': 'ProcessRollup2',
        'CommandLine': 'rclone sync \\\\fs01\\it-scripts backblaze:sfl-it-backups --transfers 4',
        'UserName': 'marcus.delacroix',
    }
    preview_row = {
        'row_index': 5709,
        '_source': 'snowflake.query_history',
        'user_name': 'SVC_SFL_ANALYTICS_FED',
        'query_type': 'UNLOAD',
        'query_text': 'COPY INTO @tmp_unload_stg/manifests_batch_01.csv.gz FROM CUSTOMER_SHIPPING_MANIFESTS',
        'rows_produced': 1410000,
    }
    assessment = {'normalized_rows': [matched_row]}
    cluster = {
        'cluster_id': 'case-primary-breach',
        'verdict': 'VALIDATED_BREACH',
        'row_refs': [29141, 5709],
        'evidence_preview': [matched_row, preview_row],
    }

    rows = _get_rows_for_cluster(cluster, assessment)
    assert {row['row_index'] for row in rows} == {29141, 5709}

    prefill = {
        'incident_name': 'PRIMARY BREACH',
        'root_cause': 'Correlated evidence exceeded the investigation threshold.',
        'observed_impact': {
            'identity': 'No named identity extracted.',
            'data': 'No confirmed data loss field was present in the supplied telemetry.',
        },
    }
    _ensure_v2_prefill_fields(prefill, cluster, rows)

    assert 'marcus.delacroix' in prefill['observed_impact']['identity']
    assert 'SVC_SFL_ANALYTICS_FED' in prefill['observed_impact']['identity']
    assert 'Bulk data export' in prefill['observed_impact']['data']


def test_benign_pentest_mutation_stays_authorized_from_preview_evidence():
    row = {
        'row_index': 120,
        '_source': 'janusec_network_v1.csv',
        'timestamp': '2026-02-03T01:05:00.000Z',
        'src_ip': '10.11.10.25',
        'dst_ip': '10.11.44.10',
        'notes': 'authorized red team pentest nmap scan within approved window',
    }
    assessment = {'normalized_rows': [{'row_index': 999, 'notes': 'unrelated'}]}
    cluster = {
        'cluster_id': 'case-benign-pentest',
        'verdict': 'BENIGN_EXPECTED',
        'row_refs': [120],
        'evidence_preview': [row],
    }
    prefill = {
        'incident_name': 'AUTHORIZED SECURITY TEST',
        'root_cause': 'Correlated evidence exceeded the investigation threshold.',
        'verdict_reasoning': 'BENIGN_EXPECTED',
    }

    rows = _get_rows_for_cluster(cluster, assessment)
    _ensure_v2_prefill_fields(prefill, cluster, rows)

    assert rows == [row]
    assert 'authorized penetration test' in prefill['root_cause']
    assert 'authorized' in prefill['verdict_reasoning'].lower()


def test_source_aware_row_text_uses_specific_edr_and_data_fields():
    edr = {
        'row_index': 29141,
        '_source': 'crowdstrike',
        'event_simpleName': 'ProcessRollup2',
        'FileName': 'rclone.exe',
        'CommandLine': 'rclone sync \\\\fs01\\it-scripts backblaze:sfl-it-backups --transfers 4',
        'ComputerName': 'FS01',
        'UserName': 'AARON.BLACKWOOD',
    }
    data = {
        'row_index': 5713,
        '_source': 'snowflake.query_history',
        'query_type': 'UNLOAD',
        'query_text': 'COPY INTO @tmp_unload_stg/manifests_batch_03.csv.gz FROM CUSTOMER_SHIPPING_MANIFESTS',
        'user_name': 'SVC_SFL_ANALYTICS_FED',
    }

    assert 'rclone sync' in _row_action_text(edr)
    assert 'AARON.BLACKWOOD' in _row_action_text(edr)
    assert 'UNLOAD' in _row_action_text(data)
    assert 'COPY INTO' in _row_action_text(data)


def test_breach_endpoint_cluster_rows_falls_back_to_preview_rows():
    row = {'row_index': 2485, '_source': 'janusec_network_v1.csv', 'dns_query': 'santosfreight.com.au'}
    assessment = {'normalized_rows': [{'row_index': 30313, 'dns_query': 'wrong.example'}]}
    cluster = {'row_refs': [2485], 'evidence_preview': [row]}

    assert breach_cluster_rows(cluster, assessment) == [row]
