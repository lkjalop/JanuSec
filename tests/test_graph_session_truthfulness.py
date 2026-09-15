import time

from fastapi.testclient import TestClient

from src.api.app import app
from src.api import graph_sessions
from src.api.runtime_state import get_file_batch_analysis, get_server_runtime_state


def _factor_name(factor):
    if isinstance(factor, dict):
        return factor.get('factor') or factor.get('name')
    return factor


def test_missing_batches_report_gaps_without_fabricating_evidence(monkeypatch):
    monkeypatch.delenv('TEST_HELPERS_ENABLED', raising=False)
    monkeypatch.delenv('SYNTHETIC_EVIDENCE_ENABLED', raising=False)
    runtime = get_server_runtime_state(app)
    batches = get_file_batch_analysis(runtime)
    batch_ids = ['truth-missing-a', 'truth-missing-b']
    for batch_id in batch_ids:
        batches.pop(batch_id, None)

    client = TestClient(app)
    response = client.post(
        '/api/v1/graph/session/build',
        json={'session_ids': batch_ids, 'correlate': True, 'ewma': False},
        headers={'x-api-key': 'devkey123'},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    summary = body['summary']

    assert summary['synthetic_evidence_enabled'] is False
    assert summary['verdict'] == 'insufficient_evidence'
    assert summary['confidence'] == 0.0
    assert {gap['batch_id'] for gap in summary['coverage_gaps'] if gap['type'] == 'missing_batch'} == set(batch_ids)
    assert all(not gap['synthetic_evidence_generated'] for gap in summary['coverage_gaps'])
    assert not any(_factor_name(factor) == 'batch_missing' for factor in summary['factors'])
    assert summary['graph_summary']['nodes'] == []
    assert not any(edge.get('type') == 'synthetic' for edge in summary['graph_summary']['edges'])
    assert len(body['graph']['nodes']) == 1  # the assessment session, not invented entities
    assert body['graph']['edges'] == []

    explained = client.get(
        f"/api/v1/graph/session/{body['session_id']}/explain",
        headers={'x-api-key': 'devkey123'},
    )
    assert explained.status_code == 200, explained.text
    explanation = explained.json()
    assert explanation['overlap_hotspots'] == []
    assert any(gap['type'] == 'no_observed_overlap' for gap in explanation['coverage_gaps'])
    assert 'no fallback hotspot was generated' in explanation['narrative'].lower()


def test_synthetic_missing_batch_evidence_requires_explicit_gate(monkeypatch):
    monkeypatch.delenv('TEST_HELPERS_ENABLED', raising=False)
    monkeypatch.setenv('SYNTHETIC_EVIDENCE_ENABLED', '1')
    client = TestClient(app)
    response = client.post(
        '/api/v1/graph/session/build',
        json={'session_ids': ['truth-demo-a', 'truth-demo-b'], 'correlate': True, 'ewma': False},
        headers={'x-api-key': 'devkey123'},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    summary = body['summary']

    assert summary['synthetic_evidence_enabled'] is True
    assert any(gap['synthetic_evidence_generated'] for gap in summary['coverage_gaps'])
    assert len(body['graph']['nodes']) > 1


def test_ewma_uses_runtime_history_and_preserves_explicit_alpha(monkeypatch):
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    runtime = get_server_runtime_state(app)
    monkeypatch.setattr(runtime, 'ewma_persist_path', None)
    batches = get_file_batch_analysis(runtime)
    batch_a = 'truth-ewma-a'
    batch_b = 'truth-ewma-b'
    batches[batch_a] = {'files': [{'user': 'shared-user', 'host': 'shared-host'}]}
    batches[batch_b] = {'files': [{'user': 'shared-user', 'host': 'shared-host'}]}
    runtime.ewma_history[f'{batch_a}::{batch_b}'] = (10.0, time.time() - 1)
    runtime.ewma_history[f'{batch_b}::{batch_a}'] = (10.0, time.time() - 1)

    client = TestClient(app)
    response = client.post(
        '/api/v1/graph/session/build',
        json={
            'session_ids': [batch_a, batch_b],
            'correlate': True,
            'ewma': True,
            'ewma_alpha': 0.25,
        },
        headers={'x-api-key': 'devkey123'},
    )
    assert response.status_code == 200, response.text
    summary = response.json()['summary']

    assert summary['ewma_alpha'] == 0.25
    assert summary['correlation'][batch_a][batch_b] == 2.0
    assert summary['correlation_smoothed'][batch_a][batch_b] == 8
    assert summary['ewma_history_entries_used'] >= 2
    assert runtime.ewma_history[f'{batch_a}::{batch_b}'][0] == 8.0


def test_ewma_alpha_boundaries_use_prior_value_or_current_value():
    prior = {'a::b': (9.0, 1.0)}
    assert graph_sessions._ewma_smooth({'a': {'b': 3.0}}, 0.0, prior, now=2.0)['a']['b'] == 9.0

    prior = {'a::b': (9.0, 1.0)}
    assert graph_sessions._ewma_smooth({'a': {'b': 3.0}}, 1.0, prior, now=2.0)['a']['b'] == 3.0
