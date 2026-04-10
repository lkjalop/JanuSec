from fastapi.testclient import TestClient

from src.api.app import app
from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.analysis.auto_llm import _estimate_row_severity, _resolve_model_for_tier
from src.api import deep_analyze_endpoints as dae
from src.reporting.persona_views import generate_persona_view


client = TestClient(app)


def _fixture_assessment() -> dict:
    rows = [
        {
            'row_index': 1,
            'severity': 'high',
            'triage_score': 0.81,
            'verdict': 'SUSPICIOUS',
            'factors': ['credential_access', 'lateral_movement'],
            'accounts': ['alice@example.com'],
            'hosts': ['host-a'],
            'external_ips': ['203.0.113.10'],
            'mitre': ['T1003'],
            'description': 'Credential access on host-a followed by remote admin tooling.',
            'timestamp_epoch': 1710000000.0,
        },
        {
            'row_index': 2,
            'severity': 'medium',
            'triage_score': 0.64,
            'verdict': 'SUSPICIOUS',
            'factors': ['credential_access', 'lateral_movement'],
            'accounts': ['alice@example.com'],
            'hosts': ['host-b'],
            'external_ips': ['203.0.113.10'],
            'mitre': ['T1021'],
            'description': 'Second host contacted by the same account and external infrastructure.',
            'timestamp_epoch': 1710000120.0,
        },
        {
            'row_index': 3,
            'severity': 'low',
            'triage_score': 0.18,
            'verdict': 'BENIGN',
            'factors': ['misc_event'],
            'accounts': ['bob@example.com'],
            'hosts': ['host-z'],
            'external_ips': [],
            'mitre': [],
            'description': 'Unrelated standalone row.',
            'timestamp_epoch': 1710000500.0,
        },
    ]
    assessment = {
        'assessment_id': 'assess-cluster-v1',
        'report_id': 'assess-cluster-v1',
        'tenant_id': 'demo',
        'org': 'demo',
        'session_id': 'session-assess-cluster-v1',
        'rows': rows,
        'llm_rows': rows,
        'graph_summary': {
            'confidence': 0.73,
            'correlation_smoothed': {'cluster-a': {'cluster-b': 0.71}},
        },
        'reviews': {},
        '_human_gates': [],
        '_latest_gate': {},
        'verdict': {
            'final_verdict': 'THREAT',
            'final_confidence': 0.82,
            'all_factors': [
                {'factor_name': 'credential_access', 'mitre': ['T1003']},
                {'factor_name': 'lateral_movement', 'mitre': ['T1021']},
            ],
            'top_contributing_factors': [
                {'factor_name': 'credential_access', 'mitre': ['T1003']},
            ],
        },
        'risk_quantification': {'severity': 'HIGH', 'expected_loss_usd': 50000},
        'attack_timeline': [
            {'entity': 'host-a', 'timestamp': 1710000000.0, 'event_type': 'credential_access', 'description': 'host-a event'},
            {'entity': 'host-b', 'timestamp': 1710000120.0, 'event_type': 'lateral_movement', 'description': 'host-b event'},
        ],
        'recommended_actions': [{'primary_action': 'Investigate cluster', 'urgency': 'high'}],
    }
    return dae._hydrate_assessment_semantics(assessment)


def test_cluster_reasoning_state_generated_from_assessment():
    assessment = _fixture_assessment()
    state = assessment.get('cluster_reasoning_state') or {}
    assert state.get('primary_cluster_id')
    cluster_states = state.get('cluster_states') or []
    assert cluster_states
    primary = cluster_states[0]
    assert primary['routing_mode'] == 'cluster-first'
    assert primary['cluster_size'] >= 2
    assert primary['graph_score'] > 0
    assert primary['summary']['canonical_narrative']
    assert primary['corroboration']['status'] in {'completed', 'deferred'}
    assert 'alt_hypotheses' in primary
    assert 'claims' in primary
    assert 'leads' in primary
    assert 'reasoning_trace' in primary
    assert 'source_reliability' in primary
    assert 'close_conditions' in primary
    assert primary['close_conditions']['soc_close_conditions']
    assert (primary.get('provider_context') or {}).get('connector_freshness') is not None
    assert (primary.get('leads') or {}).get('confirmation_details')


def test_review_endpoint_updates_cluster_reasoning_and_corroboration():
    assessment = _fixture_assessment()
    dae.REPORT_STORE.clear()
    dae.REPORT_STORE[assessment['assessment_id']] = assessment
    cluster_id = (assessment.get('correlation_clusters') or [])[0]['cluster_id']

    resp = client.post(
        f"/api/v1/assessments/{assessment['assessment_id']}/rows/1/review",
        json={
            'status': 'investigated',
            'reviewer_tag': 'soc-tier2',
            'cluster_id': cluster_id,
            'hypothesis': 'Credential theft followed by lateral movement.',
            'disposition_delta': 0.4,
            'factors_added': ['temporal_match'],
            'confidence_override': 0.92,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    state = payload.get('cluster_reasoning_state') or {}
    assert state.get('cluster_id') == cluster_id
    assert 'temporal_match' in ((state.get('analyst_state') or {}).get('factors_added') or [])
    assert (payload.get('corroboration') or {}).get('status') == 'completed'


def test_cluster_detail_and_cluster_review_endpoint_round_trip():
    assessment = _fixture_assessment()
    dae.REPORT_STORE.clear()
    dae.REPORT_STORE[assessment['assessment_id']] = assessment
    cluster_id = (assessment.get('correlation_clusters') or [])[0]['cluster_id']

    detail_resp = client.get(f"/api/v1/assessments/{assessment['assessment_id']}/clusters/{cluster_id}")
    assert detail_resp.status_code == 200, detail_resp.text
    detail = detail_resp.json()
    assert detail['cluster_detail']['cluster_id'] == cluster_id
    assert detail['member_rows']

    review_resp = client.post(
        f"/api/v1/assessments/{assessment['assessment_id']}/clusters/{cluster_id}/review",
        json={
            'status': 'confirmed',
            'reviewer_tag': 'soc-tier2',
            'notes': 'Hypothesis: confirmed lateral movement\nAdd: endpoint_chain\nTelemetry: zeek:dns\nDelta: 0.3',
        },
    )
    assert review_resp.status_code == 200, review_resp.text
    payload = review_resp.json()
    assert payload['cluster_reasoning_state']['cluster_id'] == cluster_id
    analyst_state = payload['cluster_reasoning_state'].get('analyst_state') or {}
    assert 'endpoint_chain' in (analyst_state.get('factors_added') or [])
    assert payload['cluster_reasoning_state'].get('close_conditions', {}).get('hunter_close_conditions')


def test_persona_view_prefers_canonical_cluster_reasoning():
    assessment = _fixture_assessment()
    view = generate_persona_view(assessment, 'executive', disclosure_level=2, top_n=5)
    assert 'cluster_reasoning_state' in view
    summary = (view['cluster_reasoning_state'].get('summary') or {})
    assert summary.get('canonical_narrative')
    assert view['headline'] == summary.get('canonical_narrative')
    assert (view['cluster_reasoning_state'].get('provider_context') or {}).get('connector_freshness') is not None


def test_cluster_context_increases_row_severity_and_model_routing(monkeypatch):
    monkeypatch.setenv('T2_CLUSTER_MODEL', 'cluster-model')
    baseline_row = {
        'verdict': 'SUSPICIOUS',
        'triage_score': 0.6,
    }
    row = {
        'verdict': 'SUSPICIOUS',
        'triage_score': 0.6,
        'correlation_cluster_id': 'cluster-1',
        'cluster_reasoning_state': {
            'cluster_size': 3,
            'routing_score': 0.86,
            'graph_score': 0.7,
            'reasoning_mode': 'deep',
            'analyst_state': {'disposition_delta': 0.3},
        },
    }
    assert _estimate_row_severity(row) > _estimate_row_severity(baseline_row)
    model = _resolve_model_for_tier('tier2', row)
    assert model == 'cluster-model'


def test_attachment_clusters_emit_ocr_and_visual_confirmation_leads():
    rows = [
        {
            'row_index': 1,
            'severity': 'high',
            'triage_score': 0.82,
            'verdict': 'SUSPICIOUS',
            'factors': ['supplier_impersonation', 'email:qr_phish_lure'],
            'accounts': ['ceo@shopsquire.example'],
            'attachment_name': 'msi-SSN.png',
            'source_kind': 'attachment_forensics',
            'description': 'QR image lure referencing sensitive PII.',
            'timestamp_epoch': 1710000000.0,
        },
        {
            'row_index': 2,
            'severity': 'critical',
            'triage_score': 0.91,
            'verdict': 'MALICIOUS',
            'factors': ['macro_execution', 'lolbin_spawn', 'c2_beaconing'],
            'accounts': ['ceo@shopsquire.example'],
            'attachment_name': 'Harbourside_Acquisition_Details_CONFIDENTIAL.xlsm',
            'source_kind': 'attachment_forensics',
            'description': 'Macro-enabled workbook with LOLBIN and beaconing follow-on notes.',
            'timestamp_epoch': 1710000300.0,
        },
    ]
    assessment = build_offline_workbook_assessment(rows, assessment_id='attachment-ocr', org='shopsquire', auto_llm=False)
    state = assessment.get('cluster_reasoning_state') or {}
    primary = ((state.get('cluster_states') or [None])[0]) or {}
    confirmation_details = ((primary.get('leads') or {}).get('confirmation_details') or [])
    denial_details = ((primary.get('leads') or {}).get('denial_details') or [])
    missing = ((primary.get('leads') or {}).get('high_value_missing_telemetry') or [])
    assert any('ocr' in (item.get('lead') or '').lower() or 'visual inspection' in (item.get('lead') or '').lower() for item in confirmation_details)
    assert any('qr' in (item.get('lead') or '').lower() or 'branding' in (item.get('lead') or '').lower() for item in denial_details)
    assert any(token in missing for token in ('ocr_attachment_review', 'visual_brand_baseline', 'qr_destination_resolution'))
