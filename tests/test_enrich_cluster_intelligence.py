"""Tests for Stage-5c cluster intelligence enrichment.

Covers:
  1. Normal path — all 7 deterministic fields are written to tier1_prefill.
  2. Float-string row_index tolerance in _build_event_chain_summary.
  3. Per-field isolation — a bad row that would have crashed the old monolithic
     function still allows the remaining fields to be written.
  4. run_prefill parse_failed branch — deterministic enrichments survive an LLM
     that returns unparseable JSON (parse_failed case no longer wipes tier1_prefill).
"""
from __future__ import annotations

import os
os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

import pytest
from unittest.mock import patch
from src.core.tier1_prefill.prefill_engine import (
    _enrich_cluster_intelligence,
    _build_event_chain_summary,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _breach_cluster(phases=None):
    return {
        'cluster_id': 'test-cl-001',
        'verdict': 'CONFIRMED_BREACH',
        'row_refs': [0, 1, 2],
        'phases': phases or [
            {'phase_id': 'session_theft', 'row_refs': [0]},
            {'phase_id': 'secret_access', 'row_refs': [1]},
            {'phase_id': 'data_exfiltration_snowflake', 'row_refs': [2]},
        ],
        'shared_accounts': ['alice@corp.com'],
        'shared_ips': ['185.62.56.200'],
    }


def _rows(row_index_type='int'):
    """Return test rows with the given row_index type."""
    def _ri(n):
        if row_index_type == 'int':
            return n
        elif row_index_type == 'float':
            return float(n)
        elif row_index_type == 'float_str':
            return str(float(n))   # "0.0", "1.0", "2.0" — breaks bare int()
        return n

    return [
        {
            'row_index': _ri(0), '_ts_epoch': 1_700_000_000,
            'user_canonical': 'alice', 'src_ip': '185.62.56.200',
            'triage_score': 9.0, 'severity': 'CRITICAL',
            'event_name': 'OktaSessionTokenReplay',
        },
        {
            'row_index': _ri(1), '_ts_epoch': 1_700_003_600,
            'user_canonical': 'alice', 'src_ip': '91.240.118.7',
            'triage_score': 8.5, 'severity': 'HIGH',
            'event_name': 'GetSecretValue',
        },
        {
            'row_index': _ri(2), '_ts_epoch': 1_700_010_000,
            'user_canonical': 'alice', 'src_ip': '91.240.118.7',
            'triage_score': 10.0, 'severity': 'CRITICAL',
            'event_name': 'COPY INTO external_stage',
        },
    ]


# ── 1. Normal path — all fields written ───────────────────────────────────────

def test_enrich_cluster_intelligence_normal_fields():
    data: dict = {}
    _enrich_cluster_intelligence(data, _breach_cluster(), _rows())

    assert data.get('kill_chain_summary'), "kill_chain_summary should be set"
    assert 'adversarial_sequence' in data, "adversarial_sequence must be present (even if False)"
    assert data.get('known_technical') is not None or data.get('unknown_technical') is not None, \
        "entity split should produce at least one list"
    assert data.get('dread_score'), "dread_score should be a non-empty dict"
    assert data.get('diamond_model'), "diamond_model should be set for CONFIRMED_BREACH"
    assert data.get('pasta_summary'), "pasta_summary should be set for CONFIRMED_BREACH"
    assert data.get('event_chain_summary'), "event_chain_summary should be set when rows present"


def test_enrich_cluster_intelligence_adversarial_sequence_detected():
    data: dict = {}
    _enrich_cluster_intelligence(data, _breach_cluster(), _rows())
    # session_theft + data_exfiltration_snowflake is an adversarial sequence
    assert data['adversarial_sequence'] is True
    assert 'adversarial_sequence_detail' in data


def test_kill_chain_order():
    data: dict = {}
    _enrich_cluster_intelligence(data, _breach_cluster(), _rows())
    kc = data['kill_chain_summary']
    assert 'Session Theft' in kc
    assert 'Exfil' in kc or 'Exfiltration' in kc.replace(' Snowflake', '')


# ── 2. Float-string row_index tolerance ───────────────────────────────────────

def test_event_chain_handles_float_row_index():
    """row_index stored as float should not raise in _build_event_chain_summary."""
    result = _build_event_chain_summary(_breach_cluster(), _rows('float'))
    assert isinstance(result, str)


def test_event_chain_handles_float_string_row_index():
    """row_index stored as '1.0' (float-string) must not crash and must return a string."""
    result = _build_event_chain_summary(_breach_cluster(), _rows('float_str'))
    assert isinstance(result, str)


def test_enrich_cluster_intelligence_float_string_row_index():
    """Full enrichment must not raise or skip any field when row_index='1.0'."""
    data: dict = {}
    _enrich_cluster_intelligence(data, _breach_cluster(), _rows('float_str'))

    assert 'kill_chain_summary' in data
    assert 'adversarial_sequence' in data
    # dread_score requires rows — if rows look up correctly it should be set
    assert data.get('dread_score'), "dread_score should be computed even with float-string row_index"


# ── 3. Per-field isolation — bad event_chain_summary does not block other fields ──

def test_enrich_per_field_isolation_event_chain_failure():
    """A crash in _build_event_chain_summary must not prevent kill_chain_summary
    and the other deterministic fields from being written."""
    data: dict = {}

    with patch(
        'src.core.tier1_prefill.prefill_engine._build_event_chain_summary',
        side_effect=RuntimeError('simulated crash'),
    ):
        _enrich_cluster_intelligence(data, _breach_cluster(), _rows())

    # event_chain_summary may be absent or empty due to the injected crash
    # but ALL other fields must be present
    assert 'kill_chain_summary' in data, "kill_chain_summary must survive event_chain crash"
    assert 'adversarial_sequence' in data, "adversarial_sequence must survive event_chain crash"
    assert 'known_technical' in data, "known_technical must survive event_chain crash"
    assert 'dread_score' in data, "dread_score must survive event_chain crash"
    assert 'diamond_model' in data, "diamond_model must survive event_chain crash"
    assert 'pasta_summary' in data, "pasta_summary must survive event_chain crash"


def test_enrich_per_field_isolation_dread_failure():
    """A crash in _compute_dread_score must not prevent diamond_model or pasta_summary."""
    data: dict = {}

    with patch(
        'src.core.tier1_prefill.prefill_engine._compute_dread_score',
        side_effect=RuntimeError('simulated crash'),
    ):
        _enrich_cluster_intelligence(data, _breach_cluster(), _rows())

    assert 'kill_chain_summary' in data
    assert 'adversarial_sequence' in data
    assert 'diamond_model' in data, "diamond_model must survive dread_score crash"
    assert 'pasta_summary' in data, "pasta_summary must survive dread_score crash"


# ── 4. run_prefill parse_failed — deterministic fields survive bad LLM response ──

def test_run_prefill_parse_failed_preserves_stage5c_fields():
    """When the LLM returns unparseable JSON, existing tier1_prefill content
    (Stage-5c deterministic enrichments) must not be discarded."""
    os.environ['JANUSEC_DISABLE_T1_PREFILL'] = '0'
    try:
        from src.core.tier1_prefill.prefill_engine import run_prefill
    finally:
        os.environ['JANUSEC_DISABLE_T1_PREFILL'] = '1'

    # Pre-populate tier1_prefill with what Stage 5c would have written
    existing_t1 = {
        'kill_chain_summary': 'Session Theft → Secret Access → Exfil',
        'adversarial_sequence': True,
        'dread_score': {'total': 38, 'risk_tier': 'HIGH'},
        'diamond_model': {'adversary': 'External Threat Actor'},
    }
    cluster = _breach_cluster()
    cluster['tier1_prefill'] = dict(existing_t1)

    assessment = {
        'assessment_id': 'test-assessment-001',
        'correlation_clusters': [cluster],
        'rows': _rows(),
    }

    # Simulate an LLM that returns unparseable garbage
    fake_llm = type('FakeLLM', (), {
        'generate_batch': lambda self, **kw: [{'text': 'this is not json at all'}],
        'generate':       lambda self, **kw: {'text': 'not json'},
    })()

    os.environ['JANUSEC_DISABLE_T1_PREFILL'] = '0'
    try:
        with patch('src.core.tier1_prefill.prefill_engine.PREFILL_ENABLED', True), \
             patch('src.integrations.llm_client.DEFAULT_CLIENT', fake_llm, create=True):
            run_prefill(assessment=assessment, top_n=1)
    finally:
        os.environ['JANUSEC_DISABLE_T1_PREFILL'] = '1'

    result_t1 = cluster.get('tier1_prefill') or {}
    assert result_t1.get('kill_chain_summary') == existing_t1['kill_chain_summary'], \
        "kill_chain_summary was lost after LLM parse_failed — run_prefill must merge, not replace"
    assert result_t1.get('dread_score'), \
        "dread_score was lost after LLM parse_failed"
