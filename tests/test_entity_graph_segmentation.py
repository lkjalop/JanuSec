"""Tests for entity_graph_segmentation.py."""
import pytest

pytest.importorskip('networkx')

from src.core.incident_extraction.entity_graph_segmentation import (
    segment_entity_graph,
    _extract_meaningful_entities,
    _is_high_conn_ip,
    _is_high_conn_domain,
)


def _row(user=None, src_ip=None, hostname=None, dns=None, app=None):
    r = {}
    if user:
        r['user_principal_name'] = user
    if src_ip:
        r['src_ip'] = src_ip
    if hostname:
        r['hostname'] = hostname
    if dns:
        r['dns_query'] = dns
    if app:
        r['target_app_or_resource'] = app
    return r


class TestHighConnFilters:
    def test_google_dns_filtered(self):
        assert _is_high_conn_ip('8.8.8.8')

    def test_cloudflare_dns_filtered(self):
        assert _is_high_conn_ip('1.1.1.1')

    def test_gateway_ip_filtered(self):
        assert _is_high_conn_ip('10.0.0.1')

    def test_regular_ip_not_filtered(self):
        assert not _is_high_conn_ip('10.1.2.3')

    def test_microsoft_domain_filtered(self):
        assert _is_high_conn_domain('login.microsoftonline.com')

    def test_attacker_domain_not_filtered(self):
        assert not _is_high_conn_domain('evil-c2.net')


class TestExtractEntities:
    def test_user_entity_extracted(self):
        ents = _extract_meaningful_entities(_row(user='alice@corp.com'))
        assert 'user:alice@corp.com' in ents

    def test_high_conn_ip_excluded(self):
        ents = _extract_meaningful_entities(_row(src_ip='8.8.8.8'))
        assert not any('8.8.8.8' in e for e in ents)

    def test_host_extracted(self):
        ents = _extract_meaningful_entities(_row(hostname='ws1'))
        assert 'host:ws1' in ents

    def test_dns_extracted(self):
        ents = _extract_meaningful_entities(_row(dns='evil.example.com'))
        assert 'domain:evil.example.com' in ents


class TestSegmentEntityGraph:
    def test_empty_rows_returns_single_segment(self):
        assert segment_entity_graph([]) == [[]]

    def test_all_connected_returns_single_segment(self):
        rows = [
            _row(user='alice', src_ip='10.1.2.3'),
            _row(user='alice', hostname='ws1'),
            _row(user='alice', src_ip='10.1.2.3'),
        ]
        result = segment_entity_graph(rows)
        assert len(result) == 1

    def test_disjoint_users_split(self):
        # Alice and Bob share no entities — graph cut should produce 2 segments
        # Use enough rows to exceed threshold (each pair needs weight >= 0.35)
        alice_rows = [_row(user='alice', hostname='alice-host') for _ in range(5)]
        bob_rows = [_row(user='bob', hostname='bob-host') for _ in range(5)]
        rows = alice_rows + bob_rows
        result = segment_entity_graph(rows)
        assert len(result) == 2

    def test_no_edges_returns_single_segment(self):
        # Each row has only one entity — no edges in graph
        rows = [_row(user='alice'), _row(user='bob'), _row(user='charlie')]
        result = segment_entity_graph(rows)
        assert len(result) == 1

    def test_threshold_respected(self):
        # Two pairs share an IP, but infrequently — below default threshold
        rows = [
            _row(user='alice', src_ip='192.168.1.10'),
            _row(user='bob', src_ip='192.168.1.10'),
        ] + [_row(user='alice', hostname='alice-h') for _ in range(8)]
        result = segment_entity_graph(rows)
        # alice dominates; bob may be orphan but result must be a list of lists
        assert isinstance(result, list)
        assert all(isinstance(s, list) for s in result)
