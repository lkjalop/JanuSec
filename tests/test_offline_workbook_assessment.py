from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from scripts.offline_replay_harness import _load_rows


def test_offline_deep_analyze_derives_evidence_based_findings(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Network",
            "src_ip": "10.1.1.5",
            "dst_ip": "203.0.113.45",
            "dst_port": 445,
            "ts": 1700000000,
        },
        {
            "row_index": 1,
            "sheet": "Endpoint",
            "host": "host-a",
            "process": "evilproc.exe",
            "process_path": r"C:\Users\alice\evilproc.exe",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ts": 1700000020,
        },
        {
            "row_index": 2,
            "sheet": "Email",
            "subject": "Important: Invoice Attached",
            "body": "Please enable macros and review http://203.0.113.45/report.doc",
            "ts": 1700000030,
        },
    ]
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-test"},
        json={"org": "offline-test", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    findings = payload.get("findings") or []
    assert findings, payload
    factors = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    assert "network:lateral_movement_port" in factors
    assert "email:phishing_lure" in factors
    assert "corr:cross_sheet_indicator_pivot" in factors
    assert payload.get("canonical", {}).get("suspicious_row_count", 0) >= 1
    assert payload.get("llm_rows", [{}])[0].get("llm_summary") != "Lite mode summary generated for demo coverage"


def test_offline_tier2_grounding_references_real_rows(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Email",
            "subject": "Update Required",
            "body": "Reset credentials at http://198.51.100.22/login",
            "ts": 1700000050,
        }
    ]
    resp = client.post(
        "/api/v1/csv/tier2_summarize",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-test"},
        json={"org": "offline-test", "assessment_id": "offline-aid", "rows": rows},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    joined = "".join(chunk.get("chunk", "") for chunk in payload.get("chunks") or [])
    assert "198.51.100.22" in joined or "login" in joined


def test_offline_benign_windows_update_fixture_is_dampened(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = json.loads(Path("tests/fixtures/offline_benign_windows_update.json").read_text(encoding="utf-8"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-benign"},
        json={"org": "offline-benign", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") == "REVIEW"
    assert payload.get("risk_quantification", {}).get("severity") == "LOW"
    assert payload.get("canonical", {}).get("benign_context_rows", 0) >= 1


@pytest.mark.parametrize(
    ("fixture_path", "expected_host"),
    [
        ("tests/fixtures/offline_benign_windows_update.json", "wsus-client-01"),
        ("tests/fixtures/offline_benign_admin_maintenance.json", "admin-jump-01"),
        ("tests/fixtures/offline_benign_software_deployment.json", "sccm-node-01"),
        ("tests/fixtures/offline_benign_backup_activity.json", "backup-node-01"),
        ("tests/fixtures/offline_benign_identity_admin_changes.json", None),
    ],
)
def test_benign_gold_sets_remain_low_false_positive(monkeypatch, fixture_path, expected_host):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-benign-gold"},
        json={"org": "offline-benign-gold", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") == "REVIEW"
    assert float(payload.get("verdict", {}).get("final_confidence") or 0.0) <= 0.3
    assert payload.get("risk_quantification", {}).get("severity") == "LOW"
    if expected_host:
        assert expected_host in (payload.get("impact_metadata", {}).get("affected_hosts") or [])
    highlights = payload.get("canonical", {}).get("highlights") or []
    assert highlights
    assert any("suppressor" in " ".join(item.get("evidence") or []).lower() or item.get("benign_context") for item in highlights)


def test_offline_assessment_emits_recent_decisions(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Network",
            "src_ip": "10.1.1.5",
            "dst_ip": "203.0.113.45",
            "dst_port": 445,
            "ts": 1700000000,
        },
        {
            "row_index": 1,
            "sheet": "Endpoint",
            "host": "host-a",
            "process": "evilproc.exe",
            "process_path": r"C:\Users\alice\evilproc.exe",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ts": 1700000020,
        },
    ]
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-decisions"},
        json={"org": "offline-decisions", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    recent = client.get(
        "/api/v1/decisions/recent?limit=10",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-decisions"},
    )
    assert recent.status_code == 200, recent.text
    decisions = recent.json().get("items") or recent.json().get("decisions") or []
    assert decisions
    assert any(item.get("evidence_summary") for item in decisions)
    assert any(item.get("approval_state") for item in decisions)


def test_persona_view_uses_operational_and_corroboration_fields(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Email",
            "subject": "Urgent invoice",
            "body": "Review http://198.51.100.22/login and enable macros.",
            "ts": 1700000050,
        },
        {
            "row_index": 1,
            "sheet": "Endpoint",
            "host": "host-b",
            "process_name": "powershell.exe",
            "process_path": r"C:\Users\bob\AppData\Local\Temp\run.ps1",
            "ts": 1700000060,
        },
    ]
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-persona"},
        json={"org": "offline-persona", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    persona = client.post(
        "/api/v1/reports/persona_view?persona=threat_hunter&disclosure_level=2&top_n=5",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-persona"},
        json=resp.json(),
    )
    assert persona.status_code == 200, persona.text
    payload = persona.json()
    assert payload.get("corroboration_targets")
    assert payload.get("summary_signals", {}).get("recommended_actions")


@pytest.mark.skipif(not Path("dump/Cyberstash_csv2.xlsx").exists(), reason="Cyberstash workbook missing")
def test_cyberstash_workbook_remains_positive_gold(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)

    rows = _load_rows(Path("dump/Cyberstash_csv2.xlsx"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-gold"},
        json={"org": "offline-gold", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") in {"THREAT", "SUSPICIOUS"}
    factor_names = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    assert "corr:cross_sheet_indicator_pivot" in factor_names
    assert payload.get("canonical", {}).get("corroboration_count", 0) >= 2
    assert float(payload.get("decision_record", {}).get("hopgraph_context", {}).get("graph_anomaly_score") or 0.0) > 0.0
    assert payload.get("decision_record", {}).get("approval_state", {}).get("required") is True


def test_playbook_recommendations_are_evidence_gated(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = _load_rows(Path("dump/Cyberstash_csv2.xlsx"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-playbook"},
        json={"org": "offline-playbook", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    assessment = resp.json()
    playbook = client.post(
        "/api/v1/playbooks/generate",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-playbook"},
        json={
            "graph": {
                "nodes": [{"id": "n1"}, {"id": "n2"}],
                "edges": [{"source": "n1", "target": "n2"}],
                "metadata": {
                    "corroboration_count": assessment.get("canonical", {}).get("corroboration_count", 0),
                    "approval_state": assessment.get("decision_record", {}).get("approval_state", {}),
                    "missing_evidence": assessment.get("impact_metadata", {}).get("missing_evidence", []),
                },
            },
            "confidence_threshold": assessment.get("verdict", {}).get("final_confidence", 0.5),
        },
    )
    assert playbook.status_code == 200, playbook.text
    payload = playbook.json()
    guardrails = payload.get("playbook", {}).get("guardrails") or {}
    assert guardrails.get("corroborating_domain_count", 0) >= 2
    assert "approval_state" in guardrails


def test_offline_baseline_persists_across_runs(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "offline_baselines"))
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Network",
            "src_ip": "10.1.1.5",
            "dst_ip": "203.0.113.45",
            "dst_port": 443,
            "ts": 1700000000,
        },
        {
            "row_index": 1,
            "sheet": "Email",
            "subject": "Update Required",
            "body": "Reset credentials at http://203.0.113.45/login",
            "ts": 1700000060,
        },
    ]
    for _ in range(2):
        resp = client.post(
            "/api/v1/csv/deep_analyze",
            headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-baseline"},
            json={"org": "offline-baseline", "rows": rows, "options": {"auto_llm": True}},
        )
        assert resp.status_code == 200, resp.text
    baseline_path = tmp_path / "offline_baselines" / "offline-baseline.json"
    assert baseline_path.exists()
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert payload.get("graph_paths")
    assert payload.get("graph_path_meta")
    assert payload.get("entity_pairs")
    assert payload.get("graph_edges")
    assert payload.get("graph_edge_meta")
    assert payload.get("provider_action_frequency") is not None
    assert payload.get("provider_action_meta") is not None


def test_supervised_calibration_reduces_low_precision_factor(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_CALIBRATION_PATH", str(Path("tests/fixtures/offline_calibration_labels.json").resolve()))
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "offline_calibration_baselines"))
    app = create_app()
    client = TestClient(app)
    rows = [
        {
            "row_index": 0,
            "sheet": "Endpoint",
            "host": "host-c",
            "process_name": "unknown.exe",
            "process_path": r"C:\Temp\unknown.exe",
            "ts": 1700000200,
        }
    ]
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-calibrated"},
        json={"org": "offline-calibrated", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert float(payload.get("verdict", {}).get("final_confidence") or 0.0) < 0.5


def test_azure_export_chain_surfaces_cloud_specific_factors(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "azure_cloud_baselines"))
    app = create_app()
    client = TestClient(app)
    rows = []
    for name in (
        "tests/fixtures/cloud_exports/azure_entra_signin_export.json",
        "tests/fixtures/cloud_exports/azure_entra_audit_export.json",
        "tests/fixtures/cloud_exports/azure_defender_incidents_export.json",
        "tests/fixtures/cloud_exports/azure_activity_log_export.json",
        "tests/fixtures/cloud_exports/azure_nsg_flow_export.json",
    ):
        rows.extend(_load_rows(Path(name)))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-azure-cloud"},
        json={"org": "offline-azure-cloud", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    factors = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    assert payload.get("verdict", {}).get("final_verdict") in {"SUSPICIOUS", "THREAT"}
    assert "cloud:defender_high_severity" in factors
    assert "cloud:privilege_change" in factors or "cloud:resource_admin_write" in factors
    hop = payload.get("decision_record", {}).get("hopgraph_context", {})
    assert float(hop.get("graph_anomaly_score") or 0.0) > 0.0
    assert hop.get("chains")


def test_aws_export_chain_surfaces_cloud_specific_factors(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "aws_cloud_baselines"))
    app = create_app()
    client = TestClient(app)
    rows = []
    for name in (
        "tests/fixtures/cloud_exports/aws_cloudtrail_export.json",
        "tests/fixtures/cloud_exports/aws_guardduty_export.json",
        "tests/fixtures/cloud_exports/aws_securityhub_export.json",
    ):
        rows.extend(_load_rows(Path(name)))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-aws-cloud"},
        json={"org": "offline-aws-cloud", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    factors = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    assert payload.get("verdict", {}).get("final_verdict") in {"SUSPICIOUS", "THREAT"}
    assert "cloud:guardduty_high_severity" in factors
    assert "cloud:access_key_creation" in factors or "cloud:privilege_change" in factors
    assert "cloud:securityhub_high" in factors


def test_combined_azure_attack_chain_scores_full_chain(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "combined_azure_baselines"))
    monkeypatch.setenv("OFFLINE_CALIBRATION_PATH", str(Path("tests/fixtures/offline_calibration_labels.json").resolve()))
    app = create_app()
    client = TestClient(app)
    rows = _load_rows(Path("tests/fixtures/cloud_exports/azure_combined_attack_chain.json"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-azure-combined"},
        json={"org": "offline-azure-combined", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") in {"SUSPICIOUS", "THREAT"}
    assert payload.get("canonical", {}).get("corroboration_count", 0) >= 2
    factors = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    semantic = {factor["factor_name"] for factor in payload.get("verdict", {}).get("semantic_top_factors", [])}
    supporting = {factor["factor_name"] for factor in payload.get("verdict", {}).get("supporting_model_factors", [])}
    assert "cloud:defender_high_severity" in factors
    assert "cloud:privilege_change" in factors or "identity:conditional_access_failure" in factors
    assert "cloud:defender_high_severity" in semantic
    assert any(name.startswith(("graph:", "ml:", "stats:", "context:")) for name in supporting)
    hop = payload.get("decision_record", {}).get("hopgraph_context", {})
    assert float(hop.get("graph_anomaly_score") or 0.0) > 0.0
    assert hop.get("factor_views", {}).get("semantic_top_factors")
    assert len(hop.get("edges") or []) >= 2
    assert all(edge.get("edge_type") for edge in (hop.get("edges") or []))
    assert payload.get("tier_metadata", {}).get("calibration_status", {}).get("mode") == "replay_supervised_priors"


def test_combined_aws_attack_chain_scores_full_chain(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "combined_aws_baselines"))
    monkeypatch.setenv("OFFLINE_CALIBRATION_PATH", str(Path("tests/fixtures/offline_calibration_labels.json").resolve()))
    app = create_app()
    client = TestClient(app)
    rows = _load_rows(Path("tests/fixtures/cloud_exports/aws_combined_attack_chain.json"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-aws-combined"},
        json={"org": "offline-aws-combined", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") in {"SUSPICIOUS", "THREAT"}
    factors = {factor["factor_name"] for factor in payload.get("verdict", {}).get("top_contributing_factors", [])}
    semantic = {factor["factor_name"] for factor in payload.get("verdict", {}).get("semantic_top_factors", [])}
    assert "cloud:guardduty_high_severity" in factors
    assert "cloud:access_key_creation" in factors
    assert "cloud:config_drift" in factors
    assert "cloud:guardduty_high_severity" in semantic
    hop = payload.get("decision_record", {}).get("hopgraph_context", {})
    assert len(hop.get("edges") or []) >= 2
    assert payload.get("decision_record", {}).get("calibration_status", {}).get("live_labeled_corpus") is False


@pytest.mark.parametrize(
    "fixture_path",
    [
        "tests/fixtures/offline_benign_azure_admin_role_assignment_cab.json",
        "tests/fixtures/offline_benign_azure_service_principal_change.json",
        "tests/fixtures/offline_benign_guardduty_info.json",
        "tests/fixtures/offline_benign_backup_control_plane_activity.json",
    ],
)
def test_benign_cloud_gold_sets_remain_review(monkeypatch, fixture_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-benign-cloud"},
        json={"org": "offline-benign-cloud", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") == "REVIEW"
    assert float(payload.get("verdict", {}).get("final_confidence") or 0.0) <= 0.35
    assert payload.get("canonical", {}).get("benign_context_rows", 0) >= 1


@pytest.mark.parametrize(
    "fixture_path",
    [
        "tests/fixtures/offline_benign_aws_iam_admin_change.json",
        "tests/fixtures/offline_benign_aws_control_plane_backup.json",
        "tests/fixtures/offline_benign_aws_guardduty_info.json",
    ],
)
def test_benign_aws_gold_sets_remain_review(monkeypatch, fixture_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    rows = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    resp = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-benign-aws"},
        json={"org": "offline-benign-aws", "rows": rows, "options": {"auto_llm": True}},
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload.get("verdict", {}).get("final_verdict") == "REVIEW"
    assert float(payload.get("verdict", {}).get("final_confidence") or 0.0) <= 0.35


def test_persisted_baseline_ages_old_counts(monkeypatch, tmp_path):
    baseline_dir = tmp_path / "aged_baselines"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    old_ts = 1600000000.0
    payload = {
        "profiles": {},
        "family_profiles": {},
        "entity_pairs": {"user_app|alice|portal": [old_ts, old_ts + 60]},
        "graph_paths": {"identity->cloud": 4},
        "graph_path_meta": {"identity->cloud": {"count": 4, "last_seen_ts": old_ts}},
        "graph_edges": {"a=>b": 6},
        "graph_edge_meta": {"a=>b": {"count": 6, "last_seen_ts": old_ts}},
        "provider_action_frequency": {"azure_entra|signin": 5},
        "provider_action_meta": {"azure_entra|signin": {"count": 5, "last_seen_ts": old_ts}},
        "updated_ts": old_ts,
    }
    (baseline_dir / "tenant-aged.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(baseline_dir))
    monkeypatch.setenv("OFFLINE_BASELINE_MAX_AGE_DAYS", "7")
    from src.analysis.offline_workbook_assessment import _load_persisted_baseline

    aged = _load_persisted_baseline("tenant-aged")
    assert aged.get("entity_pairs") == {}
    assert aged.get("graph_paths") == {}
    assert aged.get("graph_edges") == {}
    assert aged.get("provider_action_frequency") == {}


def test_playbook_guardrails_block_response_without_corroboration(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    playbook = client.post(
        "/api/v1/playbooks/generate",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-playbook-guard"},
        json={
            "graph": {
                "nodes": [{"id": "u1"}, {"id": "r1"}],
                "edges": [{"source": "u1", "target": "r1"}],
                "metadata": {
                    "corroboration_count": 1,
                    "approval_state": {"status": "pending"},
                    "missing_evidence": ["entra_audit", "defender_incident"],
                },
                "taxonomies": {"cvss_base": 8.5},
            },
            "confidence_threshold": 0.7,
        },
    )
    assert playbook.status_code == 200, playbook.text
    payload = playbook.json()
    guardrails = payload.get("playbook", {}).get("guardrails") or {}
    assert guardrails.get("eligible_for_response") is False


def test_playbook_guardrails_require_approval_and_evidence(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    app = create_app()
    client = TestClient(app)
    playbook = client.post(
        "/api/v1/playbooks/generate",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-playbook-guard-2"},
        json={
            "graph": {
                "nodes": [{"id": "u1"}, {"id": "r1"}],
                "edges": [{"source": "u1", "target": "r1"}],
                "metadata": {
                    "corroboration_count": 3,
                    "approval_state": {"status": "pending", "required": True},
                    "missing_evidence": [],
                },
                "taxonomies": {"cvss_base": 8.5},
            },
            "confidence_threshold": 0.8,
        },
    )
    assert playbook.status_code == 200, playbook.text
    payload = playbook.json()
    guardrails = payload.get("playbook", {}).get("guardrails") or {}
    assert guardrails.get("eligible_for_response") is False


def test_persona_cloud_corroboration_targets_use_semantic_factors(monkeypatch, tmp_path):
    monkeypatch.setenv("LLM_MOCK", "1")
    monkeypatch.setenv("OFFLINE_BASELINE_DIR", str(tmp_path / "persona_cloud_baselines"))
    app = create_app()
    client = TestClient(app)
    rows = _load_rows(Path("tests/fixtures/cloud_exports/azure_combined_attack_chain.json"))
    analyze = client.post(
        "/api/v1/csv/deep_analyze",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-persona-cloud"},
        json={"org": "offline-persona-cloud", "rows": rows, "options": {"auto_llm": True}},
    )
    assert analyze.status_code == 200, analyze.text
    persona = client.post(
        "/api/v1/reports/persona_view?persona=soc_analyst&disclosure_level=2&top_n=5",
        headers={"x-api-key": "devkey123", "X-Tenant-ID": "offline-persona-cloud"},
        json=analyze.json(),
    )
    assert persona.status_code == 200, persona.text
    payload = persona.json()
    joined = " ".join(payload.get("corroboration_targets") or []).lower()
    assert "conditional access" in joined
    assert "control-plane activity" in joined
