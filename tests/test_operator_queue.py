"""Regression tests for the assessment-local operator queue.

Covers:
  1. Queue item creation from clusters and isolated rows
  2. State machine transitions (confirm, deny, defer, escalate, reopen)
  3. Corroboration delta (Approach A) — entity overlap promotes Deferred → Remainder
  4. TTL re-evaluation (Approach C) — expired Deferred items reopen
  5. Denial/contradiction evidence (Approach B) — benign rows annotate without changing state
  6. Priority score ordering in queue view
  7. Active item = highest-priority Remainder item
  8. Human-Escalated items cannot be auto-cleared
  9. API endpoint smoke: /api/v1/queue/{assessment_id}/build, /action, /evidence
"""
from __future__ import annotations

import time
from typing import Any

import pytest

from src.core.operator_queue.queue_model import (
    CORROBORATION_THRESHOLD,
    QueueAction,
    QueueState,
    apply_action,
    apply_new_evidence,
    build_queue_from_assessment,
    get_active_item,
    get_queue_view,
    make_queue_item,
    reopen_expired_deferred,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _cluster(
    cluster_id: str = 'cluster-1',
    severity: str = 'high',
    confidence: float = 0.8,
    shared_accounts: list | None = None,
    shared_ips: list | None = None,
    row_refs: list | None = None,
    source_sheets: list | None = None,
) -> dict:
    return {
        'cluster_id': cluster_id,
        'severity': severity,
        'confidence': confidence,
        'row_refs': row_refs or [0, 1, 2],
        'evidence_refs': [f'R{i}' for i in (row_refs or [0, 1, 2])],
        'shared_accounts': shared_accounts or [],
        'shared_hosts': [],
        'shared_external_ips': shared_ips or [],
        'top_mitre': ['T1059'],
        'source_sheets': source_sheets or ['Network'],
        'reason_summary': 'Test cluster reason',
        'lead_description': 'Test cluster',
        'time_window': {},
    }


def _row(
    row_index: int = 10,
    severity: str = 'high',
    triage_score: float = 80.0,
    dst_ip: str = '1.2.3.4',
    user: str = 'alice',
    event_type: str = 'connection',
    disposition: str = '',
) -> dict:
    return {
        'row_index': row_index,
        'severity': severity,
        'triage_score': triage_score,
        'dst_ip': dst_ip,
        'user': user,
        'event_type': event_type,
        'disposition': disposition,
        '_sheet': 'Network',
    }


def _make_item(severity: str = 'high', confidence: float = 0.8) -> dict:
    cl = _cluster(severity=severity, confidence=confidence)
    return make_queue_item(cluster=cl, assessment_id='test-123')


# ── 1. Queue item creation ────────────────────────────────────────────────────

def test_make_cluster_item_fields():
    item = _make_item()
    assert item['source'] == 'cluster'
    assert item['state'] == QueueState.REMAINDER
    assert item['severity'] == 'high'
    assert item['base_risk'] == 0.75
    assert 0 < item['priority_score'] <= 1.0
    assert item['corroboration_count'] == 0
    assert item['requires_human_validation'] is False or 'requires_human_validation' not in item
    assert item['actions'] == []
    assert 'item_id' in item
    assert item['assessment_id'] == 'test-123'


def test_make_row_item_fields():
    row = _row(triage_score=75.0)
    item = make_queue_item(row=row, assessment_id='test-456')
    assert item['source'] == 'isolated_row'
    assert item['state'] == QueueState.REMAINDER
    assert item['row_refs'] == [10]
    assert 0 < item['priority_score'] <= 1.0


def test_make_item_neither_raises():
    with pytest.raises(ValueError):
        make_queue_item(assessment_id='test-789')


def test_cluster_severity_tiers():
    for sev, expected_base in [
        ('critical', 1.0), ('high', 0.75), ('medium', 0.5), ('low', 0.2), ('unknown', 0.1),
    ]:
        item = make_queue_item(cluster=_cluster(severity=sev), assessment_id='x')
        assert item['base_risk'] == expected_base, f'Failed for severity={sev}'


# ── 2. State machine transitions ─────────────────────────────────────────────

def test_deny_transitions_to_cleared():
    item = _make_item()
    apply_action(item, QueueAction.DENY, rationale='false positive')
    assert item['state'] == QueueState.CLEARED
    assert len(item['actions']) == 1
    assert item['actions'][0]['action'] == QueueAction.DENY
    assert item['actions'][0]['prior_state'] == QueueState.REMAINDER


def test_confirm_stays_remainder():
    item = _make_item()
    apply_action(item, QueueAction.CONFIRM, evidence_refs=['R5', 'R6'])
    assert item['state'] == QueueState.REMAINDER
    assert 'R5' in item['evidence_refs']
    assert 'R6' in item['evidence_refs']


def test_escalate_transitions_to_escalated():
    item = _make_item()
    apply_action(item, QueueAction.ESCALATE, actor='analyst-1', rationale='IR needed')
    assert item['state'] == QueueState.ESCALATED
    assert item['actions'][0]['actor'] == 'analyst-1'


def test_defer_transitions_to_deferred():
    item = _make_item()
    future = time.time() + 3600
    apply_action(item, QueueAction.DEFER, reopen_at=future, reopen_conditions=['connector_fresh'])
    assert item['state'] == QueueState.DEFERRED
    assert item['reopen_at'] == future
    assert 'connector_fresh' in item['reopen_conditions']


def test_reopen_transitions_to_remainder():
    item = _make_item()
    apply_action(item, QueueAction.DEFER, reopen_at=time.time() + 3600)
    apply_action(item, QueueAction.REOPEN, actor='analyst')
    assert item['state'] == QueueState.REMAINDER
    assert item['reopen_at'] is None


def test_actions_are_immutable_ledger():
    """Each action must append to the ledger, not replace."""
    item = _make_item()
    apply_action(item, QueueAction.CONFIRM, rationale='checked ticket')
    apply_action(item, QueueAction.ESCALATE, rationale='IR team alerted')
    assert len(item['actions']) == 2
    assert item['actions'][0]['action'] == QueueAction.CONFIRM
    assert item['actions'][1]['action'] == QueueAction.ESCALATE


# ── 3. Corroboration delta (Approach A) ──────────────────────────────────────

def test_corroboration_increments_count():
    item = make_queue_item(
        cluster=_cluster(shared_ips=['10.0.0.1', '91.219.236.12']),
        assessment_id='test',
    )
    initial_score = item['priority_score']
    apply_action(item, QueueAction.CORROBORATE, actor='system:corroboration')
    assert item['corroboration_count'] == 1
    assert item['priority_score'] > initial_score


def test_corroboration_promotes_deferred_to_remainder():
    item = make_queue_item(
        cluster=_cluster(shared_ips=['10.0.0.1', '91.219.236.12']),
        assessment_id='test',
    )
    apply_action(item, QueueAction.DEFER, reopen_at=time.time() + 86400)
    assert item['state'] == QueueState.DEFERRED

    # Apply enough corroboration to hit threshold
    for _ in range(CORROBORATION_THRESHOLD):
        apply_action(item, QueueAction.CORROBORATE, actor='system')

    assert item['state'] == QueueState.REMAINDER, (
        f'Expected Remainder after {CORROBORATION_THRESHOLD} corroborations, got {item["state"]}'
    )


def test_apply_new_evidence_corroborates_on_entity_overlap():
    """Rows sharing ≥ CORROBORATION_THRESHOLD entities with a queue item
    should trigger a CORROBORATE action."""
    C2_IP = '91.219.236.12'
    item = make_queue_item(
        cluster=_cluster(shared_ips=[C2_IP, '10.0.0.1']),
        assessment_id='test',
    )
    # Two new rows both contain the C2 IP (= CORROBORATION_THRESHOLD = 2 rows)
    new_rows = [
        {'row_index': 100, 'dst_ip': C2_IP, 'event_type': 'beacon'},
        {'row_index': 101, 'src_ip': C2_IP, 'event_type': 'c2_upload'},
    ]
    items = [item]
    apply_new_evidence(items, new_rows)
    corroborate_actions = [a for a in item['actions'] if a['action'] == QueueAction.CORROBORATE]
    assert len(corroborate_actions) >= 1, 'Expected corroboration action on entity overlap'
    assert item['new_evidence_available'] is True


def test_apply_new_evidence_does_not_corroborate_unrelated_rows():
    """Rows with no entity overlap must not affect the queue item."""
    item = make_queue_item(
        cluster=_cluster(shared_ips=['10.5.5.5']),
        assessment_id='test',
    )
    new_rows = [
        {'row_index': 200, 'dst_ip': '8.8.8.8', 'event_type': 'dns'},
        {'row_index': 201, 'dst_ip': '1.1.1.1', 'event_type': 'http'},
    ]
    apply_new_evidence([item], new_rows)
    assert item['corroboration_count'] == 0
    assert item['new_evidence_available'] is False


# ── 4. TTL re-evaluation (Approach C) ────────────────────────────────────────

def test_reopen_expired_deferred_promotes_past_due():
    item = _make_item()
    past_time = time.time() - 1  # already expired
    apply_action(item, QueueAction.DEFER, reopen_at=past_time)
    assert item['state'] == QueueState.DEFERRED

    reopen_expired_deferred([item])
    assert item['state'] == QueueState.REMAINDER


def test_reopen_expired_deferred_leaves_future_items_alone():
    item = _make_item()
    future_time = time.time() + 86_400
    apply_action(item, QueueAction.DEFER, reopen_at=future_time)
    reopen_expired_deferred([item])
    assert item['state'] == QueueState.DEFERRED


# ── 5. Denial / contradiction evidence (Approach B) ──────────────────────────

def test_denial_evidence_annotates_but_does_not_clear():
    """Benign-disposition rows that overlap a Remainder item should add
    ADD_EVIDENCE annotation but must not auto-clear the item."""
    IP = '10.5.5.5'
    item = make_queue_item(cluster=_cluster(shared_ips=[IP]), assessment_id='test')
    deny_row = {
        'row_index': 300,
        'dst_ip': IP,
        'event_type': 'connection',
        'disposition': 'benign',
    }
    apply_new_evidence([item], [deny_row] * CORROBORATION_THRESHOLD)
    assert item['state'] == QueueState.REMAINDER, (
        'Denial evidence should not auto-clear item — analyst must confirm'
    )
    add_ev_actions = [a for a in item['actions'] if a['action'] == QueueAction.ADD_EVIDENCE]
    assert add_ev_actions, 'Expected ADD_EVIDENCE annotation for contradicting benign row'
    assert any('contradict' in (a.get('rationale') or '').lower() or 'benign' in (a.get('rationale') or '').lower()
               for a in add_ev_actions)


def test_escalated_item_not_auto_cleared_by_denial_evidence():
    """An Escalated item can never be auto-cleared by code.
    Denial evidence only adds an annotation."""
    IP = '10.6.6.6'
    item = make_queue_item(cluster=_cluster(shared_ips=[IP]), assessment_id='test')
    apply_action(item, QueueAction.ESCALATE)
    deny_row = {'row_index': 400, 'dst_ip': IP, 'disposition': 'false_positive'}
    apply_new_evidence([item], [deny_row, dict(deny_row, row_index=401)])
    assert item['state'] == QueueState.ESCALATED, \
        'Escalated items must not be auto-cleared by corroboration/denial logic'


# ── 6 & 7. Priority ordering and Active derivation ───────────────────────────

def test_queue_view_active_is_highest_priority():
    items = [
        make_queue_item(cluster=_cluster('c1', 'low', 0.3), assessment_id='test'),
        make_queue_item(cluster=_cluster('c2', 'critical', 0.95), assessment_id='test'),
        make_queue_item(cluster=_cluster('c3', 'medium', 0.6), assessment_id='test'),
    ]
    active = get_active_item(items)
    assert active is not None
    assert active['severity'] == 'critical'
    # Its priority_score must be ≥ all other Remainder items
    max_remainder = max(it['priority_score'] for it in items)
    assert active['priority_score'] == max_remainder


def test_queue_view_structure():
    items = [
        make_queue_item(cluster=_cluster('c1', 'critical', 0.9), assessment_id='test'),
        make_queue_item(cluster=_cluster('c2', 'high', 0.7), assessment_id='test'),
    ]
    # Clear the second item
    apply_action(items[1], QueueAction.DENY)

    view = get_queue_view(items)
    assert 'active' in view
    assert 'remainder' in view
    assert 'cleared' in view
    assert 'escalated' in view
    assert 'deferred' in view
    assert 'counts' in view
    assert view['counts']['cleared'] == 1
    assert view['counts']['active'] == 1
    # Active is the critical item
    assert view['active']['severity'] == 'critical'


def test_no_active_when_all_items_handled():
    items = [make_queue_item(cluster=_cluster(), assessment_id='test')]
    apply_action(items[0], QueueAction.DENY)
    active = get_active_item(items)
    view = get_queue_view(items)
    assert active is None
    assert view['active'] is None
    assert view['counts']['active'] == 0


# ── 8. build_queue_from_assessment ───────────────────────────────────────────

def test_build_queue_from_assessment():
    assessment = {
        'assessment_id': 'asmnt-001',
        'clusters': [
            _cluster('cluster-1', 'critical', 0.9),
            _cluster('cluster-2', 'medium', 0.5),
        ],
        'llm_rows': [
            # isolated row above threshold
            _row(row_index=99, triage_score=80.0),
            # isolated row below threshold — should NOT appear
            _row(row_index=98, triage_score=20.0),
        ],
    }
    items = build_queue_from_assessment(assessment)
    assert len(items) == 3  # 2 clusters + 1 isolated row above threshold
    sources = {it['source'] for it in items}
    assert 'cluster' in sources
    assert 'isolated_row' in sources
    # Cluster items before isolated (higher base priority)
    cluster_indices = [i for i, it in enumerate(items) if it['source'] == 'cluster']
    row_indices = [i for i, it in enumerate(items) if it['source'] == 'isolated_row']
    assert max(cluster_indices) < min(row_indices) or items[0]['priority_score'] >= items[-1]['priority_score']


# ── 9. API endpoint smoke tests ───────────────────────────────────────────────

def _api_client():
    import os
    os.environ.setdefault('LLM_MOCK', '1')
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from src.api.queue_endpoints import router, _QUEUE_STORE

    # Seed the QUEUE_STORE with a pre-built queue for the test assessment
    test_id = 'test-api-001'
    items = [
        make_queue_item(cluster=_cluster('c1', 'critical', 0.9), assessment_id=test_id),
        make_queue_item(cluster=_cluster('c2', 'high', 0.7), assessment_id=test_id),
    ]
    _QUEUE_STORE[test_id] = items

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), test_id, items


def test_api_get_queue():
    client, test_id, items = _api_client()
    resp = client.get(f'/api/v1/queue/{test_id}', headers={'x-api-key': 'devkey123'})
    assert resp.status_code == 200
    body = resp.json()
    assert body['status'] == 'ok'
    q = body['queue']
    assert q['active'] is not None
    assert q['counts']['total'] == 2


def test_api_get_queue_404_unknown_assessment():
    client, _, _ = _api_client()
    resp = client.get('/api/v1/queue/does-not-exist', headers={'x-api-key': 'devkey123'})
    assert resp.status_code == 404


def test_api_action_deny():
    client, test_id, items = _api_client()
    item_id = items[0]['item_id']
    resp = client.post(
        f'/api/v1/queue/{test_id}/action',
        json={'item_id': item_id, 'action': 'deny', 'rationale': 'false positive'},
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body['new_state'] == 'cleared'
    assert body['queue_counts']['cleared'] == 1


def test_api_action_escalate():
    client, test_id, items = _api_client()
    item_id = items[1]['item_id']
    resp = client.post(
        f'/api/v1/queue/{test_id}/action',
        json={'item_id': item_id, 'action': 'escalate', 'actor': 'analyst-2'},
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 200
    assert resp.json()['new_state'] == 'escalated'


def test_api_action_unknown_action_400():
    client, test_id, items = _api_client()
    resp = client.post(
        f'/api/v1/queue/{test_id}/action',
        json={'item_id': items[0]['item_id'], 'action': 'blorp'},
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 400


def test_api_evidence_corroborates():
    client, test_id, items = _api_client()
    C2 = '91.219.236.12'
    # Put a C2 IP in the item's shared_ips
    items[0]['shared_ips'] = [C2]

    new_rows = [
        {'row_index': 500, 'dst_ip': C2, 'event_type': 'beacon'},
        {'row_index': 501, 'src_ip': C2, 'event_type': 'c2_upload'},
    ]
    resp = client.post(
        f'/api/v1/queue/{test_id}/evidence',
        json={'rows': new_rows},
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body['rows_processed'] == 2
    assert body['items_corroborated'] >= 1


def test_api_get_item():
    client, test_id, items = _api_client()
    resp = client.get(
        f'/api/v1/queue/{test_id}/item/{items[0]["item_id"]}',
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 200
    assert resp.json()['item']['item_id'] == items[0]['item_id']
