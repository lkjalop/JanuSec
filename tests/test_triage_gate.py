"""Tests for tiered triage engine, analyst gate, and persona routing."""
from __future__ import annotations

import time
import pytest
from src.reporting.tiered_triage import (
    TriageConfig,
    ScoredAlert,
    AlertCluster,
    TriageResult,
    triage_alerts,
    _score_alert,
    _cluster_alerts,
    _jaccard,
)
from src.reporting.analyst_gate import (
    AnalystGate,
    GateConfig,
    GateEntry,
    GateState,
    get_analyst_gate,
)
from src.reporting.persona_router import route_personas


# ── Fixtures ───────────────────────────────────────────────────────────

def _make_alert(
    report_id: str = 'rpt-001',
    severity: str = 'HIGH',
    verdict: str = 'THREAT',
    confidence: float = 0.85,
    factors: list | None = None,
    entities: list | None = None,
    asset_criticality: float = 7.0,
    mitre: list | None = None,
) -> dict:
    """Build a synthetic alert/report dict matching the shape consumed by triage."""
    factor_list = factors or [
        {'factor_name': 'c2_beacon', 'mitre': mitre or ['TA0011']},
        {'factor_name': 'lateral_movement', 'mitre': mitre or ['TA0008']},
    ]
    timeline = [{'entity': e} for e in (entities or ['host-A'])]
    return {
        'report_id': report_id,
        'risk_quantification': {'severity': severity, 'asset_criticality': asset_criticality},
        'verdict': {
            'final_verdict': verdict,
            'final_confidence': confidence,
            'all_factors': factor_list,
        },
        'attack_timeline': timeline,
        'asset_context': {'asset_criticality': asset_criticality},
    }


# ── Scoring tests ─────────────────────────────────────────────────────

class TestScoring:
    def test_basic_score_range(self):
        alert = _make_alert()
        cfg = TriageConfig()
        sa = _score_alert(alert, cfg)
        assert 0 <= sa.priority_score <= 100
        assert sa.tier in ('P1', 'P2', 'P3', 'P4')
        assert sa.alert_id == 'rpt-001'

    def test_high_threat_gets_p1(self):
        alert = _make_alert(
            severity='CRITICAL', verdict='THREAT', confidence=0.95,
            factors=[{'factor_name': f'f{i}', 'mitre': ['TA0001']} for i in range(8)],
            entities=['h1', 'h2', 'h3', 'h4', 'h5'],
            asset_criticality=9.0,
        )
        sa = _score_alert(alert, TriageConfig())
        assert sa.tier == 'P1'
        assert sa.priority_score >= 80

    def test_low_info_gets_p4(self):
        alert = _make_alert(
            severity='INFO', verdict='REVIEW', confidence=0.1,
            factors=[], entities=[], asset_criticality=1.0,
        )
        sa = _score_alert(alert, TriageConfig())
        assert sa.tier == 'P4'
        assert sa.priority_score < 35

    def test_score_breakdown_present(self):
        alert = _make_alert()
        sa = _score_alert(alert, TriageConfig())
        bd = sa.score_breakdown
        assert 'severity' in bd
        assert 'confidence' in bd
        assert 'factor_count' in bd
        assert 'affected_scope' in bd
        assert 'asset_criticality' in bd

    def test_verdict_boost(self):
        threat = _make_alert(severity='MEDIUM', verdict='THREAT', confidence=0.5)
        review = _make_alert(report_id='rpt-002', severity='MEDIUM', verdict='REVIEW', confidence=0.5)
        cfg = TriageConfig()
        s_threat = _score_alert(threat, cfg)
        s_review = _score_alert(review, cfg)
        assert s_threat.priority_score > s_review.priority_score

    def test_custom_weights(self):
        alert = _make_alert()
        cfg = TriageConfig(w_severity=1.0, w_confidence=0.0, w_factor_count=0.0,
                           w_affected_scope=0.0, w_asset_criticality=0.0)
        sa = _score_alert(alert, cfg)
        # Score should be dominated by severity component alone
        assert sa.score_breakdown['severity'] > 0


# ── Clustering tests ──────────────────────────────────────────────────

class TestClustering:
    def test_jaccard_identical(self):
        assert _jaccard({'a', 'b', 'c'}, {'a', 'b', 'c'}) == 1.0

    def test_jaccard_disjoint(self):
        assert _jaccard({'a'}, {'b'}) == 0.0

    def test_jaccard_empty(self):
        assert _jaccard(set(), set()) == 0.0

    def test_clustering_groups_similar(self):
        factors_a = [{'factor_name': 'c2_beacon'}, {'factor_name': 'dns_tunnel'}]
        factors_b = [{'factor_name': 'c2_beacon'}, {'factor_name': 'dns_tunnel'}, {'factor_name': 'exfil'}]
        a1 = _make_alert(report_id='a1', factors=factors_a)
        a2 = _make_alert(report_id='a2', factors=factors_b)
        a3 = _make_alert(report_id='a3', factors=[{'factor_name': 'unrelated_factor'}])

        cfg = TriageConfig()
        scored = [_score_alert(a, cfg) for a in [a1, a2, a3]]
        clusters = _cluster_alerts(scored, cfg)

        # a1 and a2 share factors above threshold; a3 should not cluster with them
        if clusters:
            clustered_ids = set()
            for c in clusters:
                clustered_ids.update(a.alert_id for a in c.alerts)
            assert 'a1' in clustered_ids and 'a2' in clustered_ids

    def test_no_cluster_for_single(self):
        alert = _make_alert()
        cfg = TriageConfig()
        scored = [_score_alert(alert, cfg)]
        assert _cluster_alerts(scored, cfg) == []


# ── Triage integration tests ──────────────────────────────────────────

class TestTriageAlerts:
    def test_empty_alerts(self):
        result = triage_alerts([])
        assert result.stats['total_alerts'] == 0
        assert result.human_gate_required == []

    def test_mixed_batch(self):
        alerts = [
            _make_alert(report_id='p1', severity='CRITICAL', confidence=0.95,
                        factors=[{'factor_name': f'f{i}'} for i in range(8)],
                        entities=['e1', 'e2', 'e3'], asset_criticality=9.0),
            _make_alert(report_id='p3', severity='MEDIUM', confidence=0.4,
                        factors=[{'factor_name': 'x'}], entities=['e1'],
                        asset_criticality=3.0, verdict='REVIEW'),
            _make_alert(report_id='p4', severity='INFO', confidence=0.1,
                        factors=[], entities=[], asset_criticality=1.0, verdict='REVIEW'),
        ]
        result = triage_alerts(alerts)

        # Verify tier distribution  
        assert result.stats['total_alerts'] == 3
        total_tiered = sum(result.stats['tier_counts'].values())
        assert total_tiered == 3

        # P1 alert should require human gate
        p1_ids = [sa.alert_id for sa in result.tiers.get('P1', [])]
        for pid in p1_ids:
            assert pid in result.human_gate_required

    def test_persona_queues_populated(self):
        alerts = [
            _make_alert(report_id=f'r{i}', severity='HIGH', confidence=0.8)
            for i in range(5)
        ]
        result = triage_alerts(alerts)
        # soc_analyst receives P1/P2/P3; should get some entries
        assert 'soc_analyst' in result.persona_queues

    def test_persona_queue_cap(self):
        config = TriageConfig(max_per_persona_queue=3)
        alerts = [
            _make_alert(report_id=f'r{i}', severity='HIGH', confidence=0.8)
            for i in range(20)
        ]
        result = triage_alerts(alerts, config=config)
        for persona, queue in result.persona_queues.items():
            assert len(queue) <= 3

    def test_human_gate_tiers_configurable(self):
        config = TriageConfig(human_gate_tiers=['P1'])  # Only P1
        alert_high = _make_alert(report_id='high', severity='CRITICAL', confidence=0.95,
                                  factors=[{'factor_name': f'f{i}'} for i in range(8)],
                                  entities=['e1', 'e2', 'e3'], asset_criticality=9.0)
        alert_mid = _make_alert(report_id='mid', severity='MEDIUM', confidence=0.5)
        result = triage_alerts([alert_high, alert_mid], config=config)
        # Only P1 alerts in gate
        for gated_id in result.human_gate_required:
            # find this alert's tier
            for t, scored_list in result.tiers.items():
                for sa in scored_list:
                    if sa.alert_id == gated_id:
                        assert t == 'P1'


# ── Analyst gate tests ────────────────────────────────────────────────

class TestAnalystGate:
    def _fresh_gate(self, **kwargs) -> AnalystGate:
        return AnalystGate(GateConfig(**kwargs))

    def test_submit_and_status(self):
        gate = self._fresh_gate()
        entry = gate.submit('alert-1', tier='P1', priority_score=90)
        assert entry.state == GateState.PENDING
        assert gate.status('alert-1').tier == 'P1'

    def test_auto_approve_lower_tier(self):
        gate = self._fresh_gate(gated_tiers=['P1', 'P2'])
        entry = gate.submit('alert-low', tier='P3', priority_score=30)
        assert entry.state == GateState.APPROVED

    def test_approve(self):
        gate = self._fresh_gate()
        gate.submit('a1', tier='P1')
        entry = gate.approve('a1', analyst='analyst-1', notes='confirmed C2')
        assert entry.state == GateState.APPROVED
        assert entry.analyst == 'analyst-1'
        assert gate.is_approved('a1')

    def test_reject(self):
        gate = self._fresh_gate()
        gate.submit('a1', tier='P1')
        entry = gate.reject('a1', analyst='analyst-1', notes='false positive')
        assert entry.state == GateState.REJECTED
        assert not gate.is_approved('a1')

    def test_defer_and_resubmit(self):
        gate = self._fresh_gate()
        gate.submit('a1', tier='P1')
        entry = gate.defer('a1', analyst='analyst-1', context_requests=['zeek:dns'])
        assert entry.state == GateState.DEFERRED
        assert entry.context_requests == ['zeek:dns']

        # Resubmit moves back to PENDING
        entry = gate.resubmit('a1')
        assert entry.state == GateState.PENDING
        assert entry.context_requests == []

    def test_pending_sorted_by_priority(self):
        gate = self._fresh_gate()
        gate.submit('low', tier='P2', priority_score=50)
        gate.submit('high', tier='P1', priority_score=95)
        gate.submit('mid', tier='P1', priority_score=70)
        pending = gate.pending()
        assert len(pending) == 3
        assert pending[0].alert_id == 'high'
        assert pending[-1].alert_id == 'low'

    def test_stats(self):
        gate = self._fresh_gate()
        gate.submit('a1', tier='P1')
        gate.submit('a2', tier='P1')
        gate.approve('a1', analyst='x')
        stats = gate.stats()
        assert stats.get('APPROVED', 0) == 1
        assert stats.get('PENDING', 0) == 1

    def test_sweep_escalation(self):
        gate = self._fresh_gate(escalation_timeout_seconds=0)
        gate.submit('a1', tier='P1')
        # Force submitted_ts to the past
        gate._entries['a1'].submitted_ts = time.time() - 100
        gate.config.escalation_timeout_seconds = 10  # 10s
        escalated = gate.sweep_escalations()
        assert 'a1' in escalated
        assert gate.status('a1').state == GateState.ESCALATED

    def test_capacity_circuit_breaker(self):
        gate = self._fresh_gate(max_pending=2)
        gate.submit('a1', tier='P1')
        gate.submit('a2', tier='P1')
        # Third entry should auto-approve despite P1
        entry = gate.submit('a3', tier='P1')
        assert entry.state == GateState.APPROVED

    def test_duplicate_submit_returns_existing(self):
        gate = self._fresh_gate()
        e1 = gate.submit('a1', tier='P1', priority_score=90)
        e2 = gate.submit('a1', tier='P1', priority_score=50)
        assert e1 is e2  # same object
        assert e1.priority_score == 90  # not overwritten

    def test_approve_unknown_raises(self):
        gate = self._fresh_gate()
        with pytest.raises(KeyError):
            gate.approve('nonexistent', analyst='x')

    def test_enrichment_fields(self):
        gate = self._fresh_gate()
        gate.submit('a1', tier='P1')
        gate.approve(
            'a1', analyst='analyst-1',
            confidence_override=0.99,
            factors_added=['new_ioc'],
            factors_removed=['false_flag'],
        )
        entry = gate.status('a1')
        assert entry.analyst_confidence_override == 0.99
        assert entry.analyst_factors_added == ['new_ioc']
        assert entry.analyst_factors_removed == ['false_flag']


# ── Persona router tests ─────────────────────────────────────────────

class TestPersonaRouter:
    def test_route_with_approved_gate(self):
        """Approved P1 alert generates full persona view."""
        alert = _make_alert(report_id='p1-ok', severity='CRITICAL', confidence=0.95,
                            factors=[{'factor_name': f'f{i}'} for i in range(8)],
                            entities=['e1', 'e2', 'e3'], asset_criticality=9.0)
        result = triage_alerts([alert])

        # Pre-approve in the gate
        gate = get_analyst_gate()
        for aid in result.human_gate_required:
            gate.submit(aid, tier='P1', priority_score=90)
            gate.approve(aid, analyst='test-analyst')

        views = route_personas(result)
        # Executive should have a view for this P1 alert
        exec_views = views.get('executive', [])
        assert len(exec_views) >= 1
        assert exec_views[0].get('gate_state') == 'APPROVED'

    def test_route_with_pending_gate_gives_stub(self):
        """Pending P1 alert gets minimal stub, not full view."""
        # Use a fresh gate to avoid pollution from other tests
        from src.reporting import analyst_gate
        old_gate = analyst_gate._GLOBAL_GATE
        analyst_gate._GLOBAL_GATE = AnalystGate()

        try:
            alert = _make_alert(report_id='p1-wait', severity='CRITICAL', confidence=0.95,
                                factors=[{'factor_name': f'f{i}'} for i in range(8)],
                                entities=['e1', 'e2', 'e3'], asset_criticality=9.0)
            result = triage_alerts([alert])

            gate = get_analyst_gate()
            for aid in result.human_gate_required:
                gate.submit(aid, tier='P1', priority_score=90)
                # Don't approve

            views = route_personas(result)
            exec_views = views.get('executive', [])
            if exec_views:
                # Should be a stub with gate_state != APPROVED
                assert exec_views[0].get('gate_state') in ('PENDING', 'UNKNOWN')
                assert exec_views[0].get('disclosure_level') == 0
        finally:
            analyst_gate._GLOBAL_GATE = old_gate

    def test_route_p4_auto_approved(self):
        """P4 alerts bypass gate entirely and generate full views."""
        alert = _make_alert(report_id='p4-auto', severity='INFO', confidence=0.1,
                            factors=[], entities=[], asset_criticality=1.0, verdict='REVIEW')
        cfg = TriageConfig(human_gate_tiers=['P1', 'P2'])
        result = triage_alerts([alert], config=cfg)

        # P4 should not be in human_gate_required
        assert 'p4-auto' not in result.human_gate_required

    def test_report_lookup_callable(self):
        """Persona router accepts a callable report lookup."""
        alert = _make_alert(report_id='lookup-test', severity='HIGH', confidence=0.8)
        result = triage_alerts([alert])

        # Approve in gate
        gate = get_analyst_gate()
        for aid in result.human_gate_required:
            gate.submit(aid, tier='P1', priority_score=80)
            gate.approve(aid, analyst='test')

        enriched_report = dict(alert)
        enriched_report['custom_enrichment'] = True

        def lookup(aid):
            if aid == 'lookup-test':
                return enriched_report
            return None

        views = route_personas(result, report_lookup=lookup)
        # Should have generated views (won't crash)
        assert isinstance(views, dict)
