import pytest

from src.core.scoring.dread_engine import compute_dread
from src.core.cmdb.client import get_cmdb_client
from src.ai.llm_integration import build_tier1_payload


def test_compute_dread_basic():
    artifact = {'destination_ports': [22, 80], 'destination_ips': ['10.0.0.1'], 'business_tier': 'high'}
    factors = [{'name': 'vulnerability_matches', 'value': [{'cve': 'CVE-2021-1234', 'cvss': 9.1, 'exploit_available': True}]}]
    cm = get_cmdb_client()
    res = compute_dread(artifact, factors, cmdb_client=cm)
    assert 'composite' in res
    assert res['composite'] > 0


def test_build_tier1_payload_injects_dread():
    artifact = {'destination_ports': [445], 'destination_ips': ['10.0.0.2'], 'business_tier': 'internal'}
    factors = []
    payload = build_tier1_payload(artifact, factors, None, [], {}, {}, {})
    assert 'prompt' in payload
    assert 'metadata' in payload
    assert 'dread' in payload['metadata']
