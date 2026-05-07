"""Tests for the enriched executive summary pipeline.

Covers: belief trajectory extraction, evidence frame retrieval,
narrative synthesis with citation, grounding validation, rollup, persona adapters.
"""
from __future__ import annotations

import time

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_assessment(cluster_count: int = 2, rows_per_cluster: int = 5) -> dict:
    """Build a minimal assessment dict with clusters and rows."""
    rows = []
    clusters = []
    row_idx = 0
    for ci in range(cluster_count):
        cluster_rows = []
        for ri in range(rows_per_cluster):
            rows.append({
                'row_index': row_idx,
                'entity': f'user{ci}@corp.com',
                'severity': 'high' if ri == 0 else 'medium',
                'description': f'Event {ri} for cluster {ci}',
                'source': 'sysmon' if ri % 2 == 0 else 'okta',
                'timestamp_utc': f'2026-01-15T{10 + ri}:00:00Z',
                'event_type': 'login_failure' if ri % 2 == 0 else 'privilege_escalation',
                'user': f'user{ci}@corp.com',
                'ip': f'10.0.{ci}.{ri + 1}',
            })
            cluster_rows.append(row_idx)
            row_idx += 1
        clusters.append({
            'cluster_id': f'cluster-{ci}',
            'threat_case_id': f'TC-{ci:03d}',
            'verdict': 'CONFIRMED_BREACH' if ci == 0 else 'UNCERTAIN',
            'confidence': 0.92 if ci == 0 else 0.55,
            'row_refs': cluster_rows,
            'phases': [{'phase': 'initial_access'}, {'phase': 'lateral_movement'}] if ci == 0 else [],
            'shared_accounts': [f'user{ci}@corp.com'],
            'shared_hosts': [f'host-{ci}'],
            'shared_external_ips': [f'10.0.{ci}.1'],
            'tier1_prefill': {
                'incident_name': f'Test Incident {ci}',
                'headline_subtitle': f'Cluster {ci} subtitle',
                'affected_users': [f'user{ci}@corp.com'],
                'affected_assets': [f'host-{ci}'],
                'mitre_techniques': ['T1078', 'T1548'] if ci == 0 else ['T1110'],
            },
        })
    return {
        'assessment_id': 'test-assessment-001',
        'normalized_rows': rows,
        'threat_cases': clusters,
        'correlation_clusters': clusters,
        'rows_processed': len(rows),
        'overall_verdict': 'CONFIRMED_BREACH',
        'tenant_id': 'test-tenant',
    }


# ── Schema tests ──────────────────────────────────────────────────────────────


class TestSchemas:
    def test_cluster_scope_defaults(self):
        from src.exec_summary.schemas import ClusterScope
        scope = ClusterScope(cluster_id='c1')
        assert scope.cluster_id == 'c1'
        assert scope.verdict == 'UNCERTAIN'
        assert scope.evidence_row_ids == []

    def test_belief_trajectory_defaults(self):
        from src.exec_summary.schemas import BeliefTrajectory
        bt = BeliefTrajectory(cluster_id='c1')
        assert bt.current_classification == 'UNCERTAIN'
        assert bt.transitions == []
        assert not bt.data_available

    def test_claim_defaults(self):
        from src.exec_summary.schemas import Claim
        c = Claim(text='Something happened')
        assert not c.grounded
        assert c.evidence_row_ids == []

    def test_exec_summary_result(self):
        from src.exec_summary.schemas import ExecSummaryResult
        r = ExecSummaryResult(assessment_id='a1')
        assert r.cluster_narratives == []
        assert r.rollup_summary == ''


# ── Belief trajectory tests ───────────────────────────────────────────────────


class TestBeliefTrajectory:
    def test_extract_from_assessment_no_trace_store(self):
        """Falls back to inferring from cluster state when no trace store."""
        from src.exec_summary.belief_trajectory import extract_belief_trajectory
        assessment = _make_assessment()
        bt = extract_belief_trajectory(
            cluster_id='cluster-0',
            tenant_id='test-tenant',
            assessment=assessment,
        )
        assert bt.cluster_id == 'cluster-0'
        assert bt.current_classification == 'CONFIRMED_BREACH'
        assert len(bt.transitions) == 1  # Single-point from assessment state
        assert bt.transitions[0].new_classification == 'CONFIRMED_BREACH'

    def test_format_trajectory_oneliner_single(self):
        from src.exec_summary.belief_trajectory import (
            extract_belief_trajectory,
            format_trajectory_oneliner,
        )
        assessment = _make_assessment()
        bt = extract_belief_trajectory('cluster-0', assessment=assessment)
        oneliner = format_trajectory_oneliner(bt)
        assert 'CONFIRMED_BREACH' in oneliner
        assert '92%' in oneliner

    def test_format_trajectory_empty(self):
        from src.exec_summary.belief_trajectory import format_trajectory_oneliner
        from src.exec_summary.schemas import BeliefTrajectory
        bt = BeliefTrajectory(cluster_id='x')
        oneliner = format_trajectory_oneliner(bt)
        assert 'no history' in oneliner


# ── Evidence frame tests ──────────────────────────────────────────────────────


class TestEvidenceFrame:
    def test_retrieve_no_engine(self):
        """Returns empty frame when TemporalRAG engine not available."""
        from src.exec_summary.evidence_frame import retrieve_evidence_frame
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][0]
        rows = assessment['normalized_rows'][:5]
        ef = retrieve_evidence_frame(cluster, rows)
        assert ef.cluster_id == 'cluster-0'
        assert not ef.rag_available
        assert ef.snippets == []

    def test_cluster_query_text_construction(self):
        from src.exec_summary.evidence_frame import _cluster_query_text
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][0]
        rows = assessment['normalized_rows'][:5]
        qt = _cluster_query_text(cluster, rows)
        assert 'Test Incident 0' in qt
        assert 'user0@corp.com' in qt
        assert 'T1078' in qt


# ── Narrative synthesis tests ─────────────────────────────────────────────────


class TestNarrativeSynthesis:
    def test_deterministic_narrative(self):
        """Deterministic narrative when no LLM provided."""
        from src.exec_summary.belief_trajectory import extract_belief_trajectory
        from src.exec_summary.narrative_synthesis import synthesize_cluster_narrative
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][0]
        bt = extract_belief_trajectory('cluster-0', assessment=assessment)
        cn = synthesize_cluster_narrative(
            cluster, assessment, bt,
            deterministic_text='Test attack chain narrative.',
        )
        assert cn.cluster_id == 'cluster-0'
        assert cn.verdict == 'CONFIRMED_BREACH'
        assert cn.summary_paragraph == 'Test attack chain narrative.'
        assert cn.deterministic_fallback is True
        assert cn.provenance == 'deterministic'
        assert 'CONFIRMED_BREACH' in cn.belief_trajectory_oneliner

    def test_build_cluster_scope(self):
        from src.exec_summary.narrative_synthesis import build_cluster_scope
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][0]
        scope = build_cluster_scope(cluster, assessment)
        assert scope.cluster_id == 'cluster-0'
        assert scope.verdict == 'CONFIRMED_BREACH'
        assert len(scope.evidence_row_ids) == 5
        assert 'user0@corp.com' in scope.entities['accounts']
        assert scope.row_count == 5


# ── Grounding validator tests ─────────────────────────────────────────────────


class TestGroundingValidator:
    def test_validate_all_grounded(self):
        from src.exec_summary.grounding_validator import validate_claims, narrative_is_trustworthy
        from src.exec_summary.schemas import Claim, ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c1',
            summary_paragraph='Test',
            claims=[
                Claim(text='Claim 1', evidence_row_ids=[0, 1]),
                Claim(text='Claim 2', evidence_row_ids=[2]),
            ],
        )
        validated = validate_claims(cn, {0, 1, 2, 3, 4})
        assert all(c.grounded for c in validated.claims)
        assert narrative_is_trustworthy(validated)

    def test_validate_ungrounded(self):
        from src.exec_summary.grounding_validator import validate_claims, narrative_is_trustworthy
        from src.exec_summary.schemas import Claim, ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c1',
            summary_paragraph='Test',
            claims=[
                Claim(text='Bad claim', evidence_row_ids=[99, 100]),
            ],
        )
        validated = validate_claims(cn, {0, 1, 2})
        assert not validated.claims[0].grounded
        assert not narrative_is_trustworthy(validated)

    def test_validate_no_citation(self):
        from src.exec_summary.grounding_validator import validate_claims
        from src.exec_summary.schemas import Claim, ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c1',
            summary_paragraph='Test',
            claims=[Claim(text='Uncited claim')],
        )
        validated = validate_claims(cn, {0, 1})
        assert not validated.claims[0].grounded


# ── Rollup tests ──────────────────────────────────────────────────────────────


class TestRollupSynthesis:
    def test_deterministic_rollup(self):
        from src.exec_summary.rollup_synthesis import synthesize_rollup
        from src.exec_summary.schemas import ClusterNarrative
        narratives = [
            ClusterNarrative(
                cluster_id='c0', incident_name='Incident A',
                verdict='CONFIRMED', summary_paragraph='Breach via stolen creds.',
            ),
            ClusterNarrative(
                cluster_id='c1', incident_name='Incident B',
                verdict='UNCERTAIN', summary_paragraph='Suspicious lateral movement.',
            ),
        ]
        text, prov = synthesize_rollup(narratives, 'CONFIRMED_BREACH', 100)
        assert prov == 'deterministic'
        assert '100 evidence rows' in text
        assert '2 threat clusters' in text
        assert 'Incident A' in text
        assert 'CONFIRMED_BREACH' in text

    def test_empty_rollup(self):
        from src.exec_summary.rollup_synthesis import synthesize_rollup
        text, prov = synthesize_rollup([], 'UNCERTAIN', 0)
        assert 'No clusters' in text


# ── Persona adapter tests ────────────────────────────────────────────────────


class TestPersonaAdapters:
    def test_all_personas(self):
        from src.exec_summary.persona_adapters import adapt_all_personas
        from src.exec_summary.schemas import ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c0', incident_name='Test',
            verdict='CONFIRMED', summary_paragraph='A breach occurred.',
        )
        result = adapt_all_personas([cn])
        assert 'executive' in result
        assert 'soc_analyst' in result
        assert 'ciso' in result
        assert len(result) == 7
        for persona, pn_list in result.items():
            assert len(pn_list) == 1
            assert pn_list[0].persona == persona
            assert 'A breach occurred.' in pn_list[0].summary

    def test_unknown_persona(self):
        from src.exec_summary.persona_adapters import adapt_for_persona
        from src.exec_summary.schemas import ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c0', summary_paragraph='Test summary.',
        )
        pn = adapt_for_persona('unknown_role', cn)
        assert pn.framing == 'unknown persona'
        assert pn.summary == 'Test summary.'

    def test_persona_emphasis_in_summary(self):
        from src.exec_summary.persona_adapters import adapt_for_persona
        from src.exec_summary.schemas import ClusterNarrative
        cn = ClusterNarrative(
            cluster_id='c0', summary_paragraph='Attacker exfiltrated data.',
        )
        pn = adapt_for_persona('compliance', cn)
        assert 'COMPLIANCE' in pn.summary
        assert 'Regulatory' in pn.emphasis


# ── Orchestrator integration test ─────────────────────────────────────────────

class TestVerdictReasoning:
    def test_derive_verdict_reasoning_confirmed(self):
        from src.exec_summary.verdict_reasoning import derive_verdict_reasoning
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][0]
        rows = assessment['normalized_rows'][:5]
        vr = derive_verdict_reasoning(cluster, rows, assessment)
        assert vr['evidence_quality'] in ('strong', 'moderate', 'weak')
        assert vr['verdict_confidence_sentence']  # non-empty
        assert 'CONFIRMED' in vr['verdict_confidence_sentence'] or 'composite' in vr['verdict_confidence_sentence']
        assert isinstance(vr['disposition_breakdown'], dict)
        assert isinstance(vr['counter_hypotheses'], list)
        assert isinstance(vr['grader_reasons'], list)

    def test_derive_verdict_reasoning_uncertain(self):
        from src.exec_summary.verdict_reasoning import derive_verdict_reasoning
        assessment = _make_assessment()
        cluster = assessment['threat_cases'][1]  # UNCERTAIN verdict
        rows = assessment['normalized_rows'][5:10]
        vr = derive_verdict_reasoning(cluster, rows, assessment)
        assert vr['verdict_confidence_sentence']  # non-empty

    def test_extract_factors(self):
        from src.exec_summary.verdict_reasoning import _extract_factors
        row = {'description': 'Brute force credential access detected', 'factors': ['brute_force']}
        factors = _extract_factors(row)
        assert 'brute_force' in factors
        assert 'credential_access' in factors

class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_run_enriched_pipeline_deterministic(self):
        """Full pipeline with no LLM — all deterministic."""
        from src.exec_summary.orchestrator import run_enriched_pipeline
        assessment = _make_assessment()
        sorted_clusters = assessment['threat_cases']
        det_texts = {
            'cluster-0': 'Lead cluster attack chain.',
            'cluster-1': 'Secondary cluster events.',
        }
        result = await run_enriched_pipeline(
            assessment_id='test-assessment-001',
            assessment=assessment,
            sorted_clusters=sorted_clusters,
            deterministic_texts=det_texts,
        )
        assert result['pipeline_ran'] is True
        assert len(result['cluster_summaries']) == 2
        assert 'cluster-0' in result['belief_trajectories']
        assert 'cluster-1' in result['belief_trajectories']
        assert 'cluster-0' in result['verdict_reasoning']
        assert result['rollup_summary']
        assert result['rollup_provenance'] == 'deterministic'
        assert 'executive' in result['persona_summaries']
        # Verify cluster-0 narrative includes verdict reasoning
        c0 = result['cluster_summaries'][0]
        assert c0['cluster_id'] == 'cluster-0'
        assert c0['verdict'] == 'CONFIRMED_BREACH'
        assert c0['deterministic_fallback'] is True
        assert c0['evidence_quality']  # should be set
        assert c0['verdict_confidence_sentence']  # should contain reasoning
        # Verify verdict reasoning dict
        vr0 = result['verdict_reasoning']['cluster-0']
        assert 'composite_score' in vr0
        assert 'evidence_quality' in vr0
        # Verify belief trajectory
        bt0 = result['belief_trajectories']['cluster-0']
        assert bt0['current_classification'] == 'CONFIRMED_BREACH'

    @pytest.mark.asyncio
    async def test_run_enriched_pipeline_empty(self):
        """Pipeline with no clusters."""
        from src.exec_summary.orchestrator import run_enriched_pipeline
        result = await run_enriched_pipeline(
            assessment_id='empty',
            assessment={},
            sorted_clusters=[],
        )
        assert result['pipeline_ran'] is True
        assert result['cluster_summaries'] == []
        assert result['rollup_summary'] == ''
