"""Integration tests for Option C feature set."""
from __future__ import annotations

import pytest

from src.analysis.auto_llm import build_tier2_prompt, detect_domain_with_confidence
from src.core.graph.hopgraph_integration import query_attack_graph
from src.repositories.historical_incidents_repo import HistoricalIncidentsRepo


def test_domain_detection_network() -> None:
    row = {
        'factors': ['port_scan', 'beaconing'],
        'src_ip': '10.0.0.5',
        'dst_ip': '8.8.8.8',
    }
    domain, confidence = detect_domain_with_confidence(row)
    assert domain == 'network'
    assert confidence >= 0.5


def test_domain_detection_endpoint() -> None:
    row = {
        'factors': ['process_injection', 'dll_hijack'],
        'process_name': 'malware.exe',
        'sha256': 'abc123',
    }
    domain, confidence = detect_domain_with_confidence(row)
    assert domain == 'endpoint'
    assert confidence >= 0.5


def test_tier2_prompt_generation() -> None:
    row = {
        'process_name': 'powershell.exe',
        'host': 'TEST-HOST',
        'factors': ['process_injection'],
    }
    context = {
        'pipeline_context': {
            'dread_score': 8.0,
            'mitre_tags': ['T1055'],
        }
    }
    prompt = build_tier2_prompt(row, context)
    lines = prompt.splitlines()
    assert len(lines) >= 60, f'Prompt too short: {len(lines)} lines'
    assert 'THREAT HUNTER' in prompt
    assert any(keyword in prompt for keyword in ('ENDPOINT', 'NETWORK', 'GENERIC'))


def test_historical_incidents_query() -> None:
    repo = HistoricalIncidentsRepo()
    row = {
        'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a',
        'process_name': 'powershell.exe',
        'host': 'WORKSTATION-042',
    }
    results = repo.query_similar_incidents(row, lookback_days=365, limit=5)
    assert results, 'Should find at least one historical match'
    assert results[0]['outcome'] == 'confirmed_malicious'


def test_hopgraph_integration_returns_nodes() -> None:
    row = {
        'process_name': 'malware.exe',
        'host': 'TEST-HOST',
        'sha256': 'deadbeef',
    }
    result = query_attack_graph(row, max_hops=3)
    assert 'nodes' in result
    assert 'edges' in result
    assert 'correlation_explanation' in result
    assert result['nodes'], 'Expected at least one node in graph output'


def test_tier2_prompt_includes_history() -> None:
    row = {
        'process_name': 'powershell.exe',
        'sha256': '9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a',
        'host': 'WORKSTATION-042',
        'factors': ['process_injection'],
    }
    context = {
        'pipeline_context': {
            'dread_score': 8.5,
            'mitre_tags': ['T1055'],
        }
    }
    prompt = build_tier2_prompt(row, context)
    assert 'HISTORICAL CONTEXT' in prompt
    assert 'days ago' in prompt or 'Similar incidents' in prompt


if __name__ == '__main__':  # pragma: no cover
    pytest.main([__file__, '-v'])
