import json
from pathlib import Path

from scripts.offline_replay_harness import _load_rows
from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.reporting.executive_reporting import build_executive_report_artifact, render_executive_report_html


def _build_artifact(pack_path: str, org: str) -> dict:
    rows = _load_rows(Path(pack_path))
    assessment = build_offline_workbook_assessment(
        rows,
        assessment_id=Path(pack_path).name + "-regression",
        org=org,
        auto_llm=True,
    )
    return build_executive_report_artifact(
        assessment,
        {
            "timeframe": "24h",
            "selection_mode": "selected_key_alerts",
            "include_overview": True,
            "include_claims": True,
            "include_selected_alerts": True,
            "include_review_state_chart": True,
            "include_trends": True,
            "include_appendix": True,
        },
    )


def test_aws_replay_pack_seeds_review_state_and_attack_mappings(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    artifact = _build_artifact("dump/tests/janusec_test_packs/aws_123456789012", "123456789012")

    counts = artifact["facts"]["review_state_counts"]
    assert counts["confirmed_malicious"] > 0
    assert counts["reviewed_benign"] > 0
    assert counts["unknown"] == 0

    frameworks = {item["title"] for item in artifact["facts"].get("framework_sections") or []}
    assert "MITRE ATT&CK" in frameworks

    appendix = artifact["appendix"]["evidence_appendix"]
    key_evidence = appendix.get("key_evidence_reviewed") or []
    kinds = {item.get("kind") for item in key_evidence}
    assert "privilege" in kinds
    assert "network" in kinds or "provider_detection" in kinds or "storage" in kinds


def test_executive_report_layout_keeps_key_evidence_in_appendix_only(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    artifact = _build_artifact("dump/tests/janusec_test_packs/azure_contoso_dev", "contoso.dev")
    html = render_executive_report_html(artifact)

    assert "Working Hypothesis" in html
    assert "Report Metadata" in html
    assert "Evidence Appendix" in html
    assert html.count("Key Evidence Reviewed") == 1
    assert "provider-chip" in html
    assert "Why It Matters" in html


def test_appendix_uses_event_grade_citations_and_humanized_timeline(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    artifact = _build_artifact("dump/tests/janusec_test_packs/azure_contoso_dev", "contoso.dev")
    appendix = artifact["appendix"]["evidence_appendix"]
    evidence_rows = appendix.get("source_evidence_rows") or []
    timeline = appendix.get("timeline_evidence") or []

    assert evidence_rows
    assert str(evidence_rows[0].get("_citation") or "").startswith("E1 - ")
    assert any("UTC" in str(row.get("_citation") or "") for row in evidence_rows)
    assert timeline
    assert any(str(item.get("entity") or "").startswith(("user:", "ip:")) for item in timeline)
    assert any(item.get("domain") not in (None, "", "Not recorded") for item in timeline)


def test_label_workflow_is_merged_into_executive_artifact(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    assessment = build_offline_workbook_assessment(
        _load_rows(Path("dump/tests/janusec_test_packs/aws_123456789012")),
        assessment_id="aws-workflow-merge",
        org="123456789012",
        auto_llm=True,
    )
    decision_id = str((assessment.get("rows") or [{}])[0].get("fingerprint") or (assessment.get("rows") or [{}])[0].get("id") or "")
    label_rows = [
        {
            "event_id": decision_id,
            "decision_id": decision_id,
            "label": "true_positive",
            "tenant_id": "123456789012",
            "evidence": json.dumps(
                {
                    "note": "Analyst contacted the user and found a ticket.",
                    "workflow": {
                        "user_contacted": True,
                        "change_ticket_found": True,
                        "owner_confirmed": False,
                        "change_ticket": "CHG-1234",
                    },
                }
            ),
            "created_at": "2026-04-03T11:00:00Z",
        }
    ]
    monkeypatch.setattr("src.reporting.executive_reporting._fetch_sqlite_labels", lambda tenant: label_rows)
    monkeypatch.setattr("src.reporting.executive_reporting._fetch_memory_labels", lambda: [])

    artifact = build_executive_report_artifact(assessment, {"include_appendix": True})
    workflow = (((artifact.get("canonical_report") or {}).get("impact_metadata") or {}).get("analyst_workflow") or {})

    assert workflow.get("user_contacted") is True
    assert workflow.get("change_ticket_found") is True
    assert "CHG-1234" in (workflow.get("change_tickets") or [])


def test_hybrid_vendor_family_seed_is_applied(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    rows = [
        {
            "export_source": "okta",
            "_janusec_label": "MALICIOUS_IDENTITY_CHAIN",
            "user": "analyst@example.com",
            "ipAddress": "198.51.100.44",
        },
        {
            "export_source": "suricata",
            "_janusec_label": "BENIGN_BACKGROUND",
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.44",
        },
    ]
    assessment = build_offline_workbook_assessment(
        rows,
        assessment_id="hybrid-vendor-regression",
        org="hybrid-test",
        auto_llm=True,
    )

    normalized_rows = assessment.get("rows") or []
    families = {row.get("provider_family") for row in normalized_rows}
    domains = {row.get("domain_hint") for row in normalized_rows}
    review_states = {row.get("review_state") for row in normalized_rows}

    assert "identity_access" in families
    assert "network_security" in families
    assert "identity" in domains
    assert "network" in domains
    assert "confirmed_malicious" in review_states
    assert "reviewed_benign" in review_states
