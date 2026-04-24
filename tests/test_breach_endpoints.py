"""Tests for breach_endpoints — prefill, exec summary, sign-off, further-tasks."""
from __future__ import annotations

import json
import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

# ── Minimal app fixture ────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def client():
    from fastapi import FastAPI
    from src.api.breach_endpoints import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ── Fake assessment ────────────────────────────────────────────────────────────

FAKE_AID = 'test-breach-001'

FAKE_ASSESSMENT = {
    'assessment_id': FAKE_AID,
    'correlation_clusters': [
        {
            'cluster_id': 'cluster-1',
            'severity': 'high',
            'verdict': 'CONFIRMED',
            'row_refs': [0, 1, 2],
        },
        {
            'cluster_id': 'cluster-2',
            'severity': 'medium',
            'verdict': 'LIKELY REAL',
            'row_refs': [3, 4],
        },
        {
            'cluster_id': 'cluster-3',
            'severity': 'low',
            'verdict': 'UNCERTAIN',
            'row_refs': [5],
        },
    ],
    'normalized_rows': [
        {'row_index': i, 'severity': 'high', 'description': f'Event {i}',
         '_source': 'okta', 'user': f'user{i}@test.com'}
        for i in range(6)
    ],
}


def _patch_assessment(monkeypatch, assessment=None):
    a = assessment or FAKE_ASSESSMENT
    monkeypatch.setattr(
        'src.api.breach_endpoints._get_assessment',
        lambda aid: dict(a) if aid == FAKE_AID else None,
    )
    monkeypatch.setattr('src.api.breach_endpoints._persist', lambda *_: None)


# ── Tier-1 prefill route ───────────────────────────────────────────────────────

def test_prefill_calls_engine(client, monkeypatch):
    _patch_assessment(monkeypatch)

    mock_result = {
        'status': 'ok',
        'prefilled_clusters': ['cluster-1', 'cluster-2', 'cluster-3'],
        'duration_seconds': 1.2,
    }
    monkeypatch.setattr(
        'src.api.breach_endpoints.run_prefill',
        lambda **_: mock_result,
        raising=False,
    )

    with patch('src.api.breach_endpoints._get_assessment',
               return_value=dict(FAKE_ASSESSMENT)), \
         patch('src.api.breach_endpoints._persist'), \
         patch('src.core.tier1_prefill.prefill_engine.run_prefill',
               return_value=mock_result):
        resp = client.post(f'/api/v1/assessments/{FAKE_AID}/tier1-prefill',
                           json={'model': 'qwen2.5:14b', 'top_n': 3})

    assert resp.status_code == 200
    data = resp.json()
    assert data['assessment_id'] == FAKE_AID


def test_prefill_404_unknown_assessment(client, monkeypatch):
    monkeypatch.setattr('src.api.breach_endpoints._get_assessment', lambda _: None)
    resp = client.post('/api/v1/assessments/nonexistent/tier1-prefill',
                       json={'model': 'qwen2.5:14b', 'top_n': 3})
    assert resp.status_code == 404


# ── Single cluster summary ─────────────────────────────────────────────────────

def test_single_summary_404_cluster(client, monkeypatch):
    with patch('src.api.breach_endpoints._get_assessment',
               return_value=dict(FAKE_ASSESSMENT)), \
         patch('src.api.breach_endpoints._persist'):
        from src.core.tier1_prefill.prefill_engine import run_single_cluster_prefill
        with patch('src.core.tier1_prefill.prefill_engine.run_single_cluster_prefill',
                   return_value={'status': 'not_found', 'cluster_id': 'cluster-99'}):
            resp = client.post(
                f'/api/v1/assessments/{FAKE_AID}/clusters/cluster-99/tier1-summary',
                json={},
            )
    assert resp.status_code == 404


# ── Executive summary ─────────────────────────────────────────────────────────

def test_exec_summary_deterministic_no_llm(client, monkeypatch):
    assessment = dict(FAKE_ASSESSMENT)
    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist'), \
         patch('src.api.breach_endpoints._get_llm', return_value=None):
        resp = client.post(f'/api/v1/assessments/{FAKE_AID}/executive-summary',
                           json={'regenerate': False})

    assert resp.status_code == 200
    data = resp.json()
    assert 'deterministic' in data
    assert '3 threat cases' in data['deterministic']
    assert data['llm_color'] is None


def test_exec_summary_returns_cached(client, monkeypatch):
    cached_summary = {
        'deterministic': 'Cached det.',
        'llm_color': 'Cached colour.',
        'model_used': 'qwen2.5:14b',
        'generated_at': 1000,
        'from_cache': False,
    }
    assessment = {**FAKE_ASSESSMENT, 'exec_summary_llm': cached_summary}
    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist'):
        resp = client.post(f'/api/v1/assessments/{FAKE_AID}/executive-summary',
                           json={'regenerate': False})

    assert resp.status_code == 200
    assert resp.json()['from_cache'] is True
    assert resp.json()['llm_color'] == 'Cached colour.'


# ── Sign-off ──────────────────────────────────────────────────────────────────

def test_sign_off_writes_state(client, monkeypatch):
    assessment = {
        **FAKE_ASSESSMENT,
        'correlation_clusters': [
            {'cluster_id': 'cluster-1', 'severity': 'high',
             'verdict': 'CONFIRMED', 'row_refs': [0, 1]},
        ],
    }
    persisted = {}

    def fake_persist(aid, a):
        persisted.update(a)

    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist', side_effect=fake_persist):
        resp = client.post(
            f'/api/v1/assessments/{FAKE_AID}/clusters/cluster-1/sign-off',
            json={
                'analyst_id': 'analyst@test.com',
                'notes': 'Confirmed BEC. Containment done.',
                'timeline_confirmed': True,
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data['status'] == 'ok'
    assert data['cluster_id'] == 'cluster-1'
    assert 'signed_off_at' in data
    cluster = assessment['correlation_clusters'][0]
    assert cluster['sign_off']['timeline_confirmed'] is True
    assert cluster['sign_off']['analyst_id'] == 'analyst@test.com'


def test_sign_off_404_unknown_cluster(client):
    assessment = {**FAKE_ASSESSMENT}
    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist'):
        resp = client.post(
            f'/api/v1/assessments/{FAKE_AID}/clusters/cluster-99/sign-off',
            json={'timeline_confirmed': True},
        )
    assert resp.status_code == 404


# ── Further tasks ─────────────────────────────────────────────────────────────

def test_further_tasks_drops_hallucinated_refs(client):
    """LLM returns a task citing row_999 which is not in uncovered evidence — must be dropped."""
    assessment = {
        'assessment_id': FAKE_AID,
        'correlation_clusters': [{
            'cluster_id': 'cluster-1',
            'severity': 'high',
            'verdict': 'CONFIRMED',
            'row_refs': [0, 1, 2],
            'missing_sources': ['Email gateway'],
        }],
        'normalized_rows': [
            {'row_index': i, 'severity': 'high', 'description': f'Event {i}',
             '_source': 'okta', 'user': f'user{i}@test.com'}
            for i in range(3)
        ],
    }

    llm_response = json.dumps({
        'further_tasks': [
            {
                'title': 'Real task citing row_1',
                'rationale': 'Based on row_1',
                'evidence_refs': [1],           # valid — in uncovered
                'missing_source': None,
                'priority': 'P2',
                'subtasks': ['Do thing A'],
            },
            {
                'title': 'Hallucinated task citing row_999',
                'rationale': 'Made up',
                'evidence_refs': [999],          # INVALID — not in cluster rows
                'missing_source': None,
                'priority': 'P2',
                'subtasks': ['Do invented thing'],
            },
        ]
    })

    mock_llm = MagicMock()
    mock_llm.generate.return_value = {'text': llm_response}

    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist'), \
         patch('src.api.breach_endpoints._get_llm', return_value=mock_llm):
        resp = client.post(
            f'/api/v1/assessments/{FAKE_AID}/clusters/cluster-1/further-tasks',
            json={
                'completed_evidence_refs': [],
                'completed_task_titles': [],
                'model': 'qwen2.5:14b',
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data['grounded_count'] == 1
    assert len(data['further_tasks']) == 1
    assert data['further_tasks'][0]['title'] == 'Real task citing row_1'


def test_further_tasks_missing_source_grounding(client):
    """Task citing a known missing source is kept even with no evidence_refs."""
    assessment = {
        'assessment_id': FAKE_AID,
        'correlation_clusters': [{
            'cluster_id': 'cluster-1',
            'severity': 'high',
            'verdict': 'CONFIRMED',
            'row_refs': [0],
            'missing_sources': ['EDR process tree'],
        }],
        'normalized_rows': [
            {'row_index': 0, 'severity': 'high', 'description': 'Event 0',
             '_source': 'okta', 'user': 'user0@test.com'},
        ],
    }

    llm_response = json.dumps({
        'further_tasks': [{
            'title': 'Pull EDR logs',
            'rationale': 'EDR not present',
            'evidence_refs': [],
            'missing_source': 'EDR process tree',
            'priority': 'P1',
            'subtasks': ['Request EDR feed'],
        }]
    })

    mock_llm = MagicMock()
    mock_llm.generate.return_value = {'text': llm_response}

    with patch('src.api.breach_endpoints._get_assessment', return_value=assessment), \
         patch('src.api.breach_endpoints._persist'), \
         patch('src.api.breach_endpoints._get_llm', return_value=mock_llm):
        resp = client.post(
            f'/api/v1/assessments/{FAKE_AID}/clusters/cluster-1/further-tasks',
            json={'completed_evidence_refs': [], 'completed_task_titles': []},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data['grounded_count'] == 1
    assert data['further_tasks'][0]['missing_source'] == 'EDR process tree'
