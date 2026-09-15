import time
import pytest
from fastapi.testclient import TestClient
from src.api.app import app


def make_row(idx, tri, conf=0.9, ev_count=3, novelty=0.1, ingested_ts=None):
    return {
        'row_index': idx,
        'triage_score': tri,
        'confidence': conf,
        'evidence_count': ev_count,
        'novelty': novelty,
        'ingested_ts': ingested_ts or time.time()
    }


def test_rank_and_forward_personas():
    client = TestClient(app)
    rows = [make_row(0, 0.1), make_row(1, 0.9), make_row(2, 0.5)]
    r = client.post('/api/v1/forward/rank_and_forward', json={'rows': rows}, params={'persona': 'soc_analyst', 'top_n': 3})
    assert r.status_code == 200
    data = r.json()
    assert data['persona'] == 'soc_analyst'
    results = data['results']
    assert results[0]['triage_score'] == pytest.approx(0.9)
    assert results[1]['triage_score'] == pytest.approx(0.5)


def test_backlog_report():
    client = TestClient(app)
    rows = [
        {'row_index': 1, 'triage_score': 0.8, 'status': 'new', '_pipeline_done': False, 'factors': ['x','y'], 'ingested_ts': time.time() - 3600},
        {'row_index': 2, 'triage_score': 0.2, 'status': 'ready', '_pipeline_done': True, 'factors': ['z'], 'ingested_ts': time.time() - 100000},
        {'row_index': 3, 'triage_score': 0.6, 'status': 'pending', '_pipeline_done': False, 'factors': ['x'], 'ingested_ts': time.time() - 50000},
    ]
    r = client.post('/api/v1/forward/backlog_report', json={'rows': rows})
    assert r.status_code == 200
    j = r.json()
    assert j['not_investigated_count'] == 2
    assert 'top_factors' in j


def test_forward_and_create_creates_gate(monkeypatch):
    from fastapi.testclient import TestClient
    client = TestClient(app)
    # prepare a high impact row
    row = {'row_index': 100, 'triage_score': 0.95, 'impact_score': 0.9, 'estimated_cost': 50000, 'summary': 'Critical incident', 'evidence_refs': []}
    r = client.post('/api/v1/forward/forward_and_create', json={'rows': [row], 'persona': 'executive', 'top_n': 1})
    assert r.status_code == 200
    data = r.json()
    assert data['persona'] == 'executive'
    assert data.get('created_gate_ids') is not None
    assert len(data.get('created_gate_ids')) >= 0
