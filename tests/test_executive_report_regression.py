import json
from pathlib import Path
from datetime import datetime, timezone

from scripts.offline_replay_harness import _load_rows
from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.reporting.executive_reporting import build_executive_report_artifact, render_executive_report_html


def _seed_regression_labels(rows: list[dict]) -> list[dict]:
    malicious_sources = {
        "email_message",
        "attachment_forensics",
        "attachment_detonation",
        "click_telemetry",
        "cloudtrail",
        "guardduty",
        "securityhub",
        "entra_signin",
        "entra_audit",
        "defender_incident",
        "endpoint",
        "network",
    }
    benign_sources = {"supplier_baseline", "vendor_master_history", "mailbox_trace"}
    labelled = []
    benign_cloud_seeded = False
    for row in rows:
        rec = dict(row)
        raw_ts = rec.get("timestamp") or rec.get("createdDateTime") or rec.get("eventTime") or rec.get("time")
        if raw_ts and not rec.get("timestamp_epoch"):
            try:
                rec["timestamp_epoch"] = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
            except Exception:
                pass
        source = str(rec.get("export_source") or rec.get("source_kind") or rec.get("sheet") or "").lower()
        if source == "cloudtrail" and not benign_cloud_seeded:
            rec["_janusec_label"] = "BENIGN_BACKGROUND"
            rec["review_state"] = "reviewed_benign"
            benign_cloud_seeded = True
        elif source in malicious_sources:
            rec["_janusec_label"] = "MALICIOUS_IDENTITY_CHAIN"
            rec["review_state"] = "confirmed_malicious"
        elif source in benign_sources:
            rec["_janusec_label"] = "BENIGN_BACKGROUND"
            rec["review_state"] = "reviewed_benign"
        labelled.append(rec)
    return labelled


def _build_artifact(pack_path: str, org: str) -> dict:
    rows = _seed_regression_labels(_load_rows(Path(pack_path)))
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
    artifact = _build_artifact("tests/fixtures/export_packs/aws_email_compromise_chain", "123456789012")

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
    artifact = _build_artifact("tests/fixtures/export_packs/azure_email_compromise_chain", "contoso.dev")
    html = render_executive_report_html(artifact)

    assert "Working Hypothesis" in html
    assert "Report Metadata" in html
    assert "Evidence Appendix" in html
    assert html.count("Key Evidence Reviewed") == 1
    assert "provider-chip" in html
    assert "Why It Matters" in html


def test_appendix_uses_event_grade_citations_and_humanized_timeline(monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    artifact = _build_artifact("tests/fixtures/export_packs/azure_email_compromise_chain", "contoso.dev")
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
        _seed_regression_labels(_load_rows(Path("tests/fixtures/export_packs/aws_email_compromise_chain"))),
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
