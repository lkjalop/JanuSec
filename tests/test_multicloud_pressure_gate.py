from __future__ import annotations

from scripts.multicloud_pressure_replay import build_multicloud_rows, run_multicloud_gate


def test_multicloud_gate_okta_aws_azure_surfaces_cross_cloud_identity_chain(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    report = run_multicloud_gate(employee_count=200, concurrent_batches=3)
    variant = ((report.get('variants') or {}).get('okta_aws_azure') or {})
    payload = ((variant.get('full') or {}).get('payload') or {})
    clusters = payload.get('correlation_clusters') or []
    assert clusters
    top = clusters[0]
    providers = set(top.get('providers') or [])
    assert {'aws', 'azure', 'okta'} <= providers
    assert 'cross-cloud identity movement' in (top.get('business_significance') or '').lower()
    assert any('Okta System Log' in item for item in (top.get('recommended_logs') or []))
    assert any('Azure Activity Log' in item for item in (top.get('recommended_logs') or []))
    assert any('CloudTrail' in item for item in (top.get('recommended_logs') or []))
    correlated_rows = [row for row in (payload.get('evidence_rows') or []) if row.get('correlation_cluster_id') == top.get('cluster_id')]
    reasons = ' '.join(
        link.get('summary') or ''
        for row in correlated_rows
        for link in (row.get('correlation_reasons') or [])
    )
    threat_hunter = (payload.get('persona_reports') or {}).get('threat_hunter', {}) or {}
    text = ' '.join((threat_hunter.get('key_points') or []) + ([threat_hunter.get('text') or '']))
    assert 'shared' in reasons.lower() or 'same session' in reasons.lower() or 'within' in reasons.lower()
    assert 'okta' in text.lower() or 'azure' in text.lower() or 'aws' in text.lower()


def test_multicloud_gate_hybrid_bec_and_virtualization_chain(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    report = run_multicloud_gate(employee_count=200, concurrent_batches=3)
    variant = ((report.get('variants') or {}).get('ad_aws_vmware_bec') or {})
    payload = ((variant.get('full') or {}).get('payload') or {})
    clusters = payload.get('correlation_clusters') or []
    assert clusters
    top = clusters[0]
    providers = set(top.get('providers') or [])
    assert {'aws', 'active_directory', 'vmware', 'email'} <= providers
    assert 'email compromise or bec telemetry' in (top.get('business_significance') or '').lower()
    assert any('Windows Security 4624/4625/4768/4769' in item for item in (top.get('recommended_logs') or []))
    assert any('vCenter tasks and events' in item for item in (top.get('recommended_logs') or []))
    assert any('mailbox audit logs' in item for item in (top.get('recommended_logs') or []))
    executive = (payload.get('persona_reports') or {}).get('executive') or {}
    assert executive.get('mandatory_communications') is not None
    assert executive.get('legal_considerations') is not None


def test_multicloud_generator_includes_benign_and_malicious_controls():
    rows = build_multicloud_rows(employee_count=200, variant='okta_aws_azure')
    assert len(rows) >= 200
    assert any('Approved temporary guest onboarding' in str(row.get('description') or '') for row in rows)
    assert any('impossible travel' in str(row.get('description') or '').lower() for row in rows)
    hybrid_rows = build_multicloud_rows(employee_count=200, variant='ad_aws_vmware_bec')
    assert any('business email compromise' in str(row.get('description') or '').lower() for row in hybrid_rows)
    assert any((row.get('provider') == 'vmware') for row in hybrid_rows)
