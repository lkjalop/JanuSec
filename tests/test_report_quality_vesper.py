from __future__ import annotations

import json
from pathlib import Path

from src.core.ingest.evidence_assembler import get_assessment_clusters, get_assessment_rows
from src.api.report_aggregation import build_framework_rollups
from src.reporting.assessment_view_model import build_assessment_report_view
from src.reporting.comprehensive_report_generator import build_report_html


VESPER_ASSESSMENT = Path("tests/fixtures/assessments/quality/vesper_assessment.json")
MERIDIAN_ASSESSMENT = Path("tests/fixtures/assessments/quality/meridian_assessment.json")
CORRECTED_VESPER_SOURCE_COUNTS = {
    "janusec_network_v3.csv": 75960,
    "janusec_endpoint_lolbins_v3.ndjson": 14546,
    "janusec_identity_kerberos_v3.ndjson": 6986,
    "janusec_cloud_identity_v3.json": 1258,
}


def _load_vesper() -> dict:
    assert VESPER_ASSESSMENT.exists(), "VESPER persisted assessment fixture is missing"
    return json.loads(VESPER_ASSESSMENT.read_text(encoding="utf-8"))


def _load_meridian() -> dict:
    assert MERIDIAN_ASSESSMENT.exists(), "MERIDIAN persisted assessment fixture is missing"
    return json.loads(MERIDIAN_ASSESSMENT.read_text(encoding="utf-8"))


def test_vesper_assessment_view_model_promotes_confirmed_breach_evidence():
    assessment = _load_vesper()
    view = build_assessment_report_view(
        assessment,
        assessment_id=assessment["assessment_id"],
        corrected_source_counts=CORRECTED_VESPER_SOURCE_COUNTS,
    )

    assert view["title"].startswith("JanuSec Breach Assessment - ACMEVESPER")
    assert view["total_rows"] == 98750
    assert sum(view["source_counts"].values()) == view["total_rows"]
    assert view["validated_breach_count"] >= 1
    assert view["cluster_count"] >= 1

    top_factors = {item["factor"] for item in view["top_factors"]}
    assert "iam:golden_ticket" in top_factors
    assert "network:sharepoint_subdomain_mismatch" in top_factors
    assert "recon:sustained_offhours_sequence" in top_factors

    reason_titles = {item["title"] for item in view["confirmed_reasons"]}
    assert "Credential abuse confirmed" in reason_titles
    assert "Cloud persistence confirmed" in reason_titles
    assert "Exfil path confirmed" in reason_titles
    assert "Multi-day pattern confirmed" in reason_titles
    story = view["executive_story"]
    sequence_titles = {item["title"] for item in story["temporal_sequence"]}
    assert "Cloud persistence begins" in sequence_titles
    assert "Kerberos credential abuse" in sequence_titles
    assert "WMI lateral movement" in sequence_titles
    assert "Cumulative SharePoint exfil path" in sequence_titles
    assert "Remote access or lateral movement" not in sequence_titles
    assert story["control_impact"]["frameworks"]
    assert "Legal breach notification is a separate" in story["legal_boundary"]
    assert story["iso27035_lifecycle"]["standard"] == "ISO/IEC 27035"
    assert any(item["origins"] for item in view["top_factors"])


def test_vesper_report_framework_rollups_use_confirmed_breach_factors():
    assessment = _load_vesper()
    rollups = build_framework_rollups([], get_assessment_clusters(assessment))

    stride = {item["category"] for item in rollups["top_stride"]}
    maestro = {item["phase"] for item in rollups["maestro_phases"]}
    kill_chain = {item["phase"] for item in rollups["kill_chain_phases"]}

    assert {"spoofing", "elevation", "information_disclosure", "lateral_movement", "exfiltration"} <= stride
    assert {"initial_access", "credential_access", "lateral_movement", "collection", "exfiltration"} <= maestro
    assert {"delivery", "recon", "exploitation", "lateral_movement", "collection", "exfiltration"} <= kill_chain
    assert rollups["controls_overview"]


def test_vesper_html_report_prioritizes_breach_summary_over_raw_tables():
    assessment = _load_vesper()
    view = build_assessment_report_view(
        assessment,
        assessment_id=assessment["assessment_id"],
        corrected_source_counts=CORRECTED_VESPER_SOURCE_COUNTS,
    )
    payload = {
        "title": view["title"],
        "assessment_view": view,
        "rows": get_assessment_rows(assessment, limit=500),
        "clusters": get_assessment_clusters(assessment),
        "summary": {},
        "meta": {
            "assessment_id": assessment["assessment_id"],
            "source_counts": CORRECTED_VESPER_SOURCE_COUNTS,
            "total_rows": 98750,
        },
    }

    html = build_report_html(payload)

    assert "<title>JanuSec Breach Assessment - ACMEVESPER" in html
    assert "Why This Is Confirmed" in html
    assert "What Happened Over Time" in html
    assert "Why It Was Missed Earlier" in html
    assert "Business Decision Needed" in html
    assert "Technical Validation vs Legal Notification" in html
    assert "ISO 27035 Incident Lifecycle" in html
    assert "ISO 27001 ISMS controls" in html
    assert "Top Validated-Breach Factors" in html
    assert "Benchmark Comparison" in html
    assert "Source Coverage" in html
    assert "Correlated Breach Clusters" in html
    assert "Validated Breaches" in html
    assert "98,750" in html
    assert "75,960" in html
    assert "iam:golden_ticket" in html
    assert "network:sharepoint_subdomain_mismatch" in html
    assert "recon:sustained_offhours_sequence" in html
    assert "Unknown TTPs" not in html
    assert "errorCode" not in html
    assert "failureReason" not in html
    assert "<summary" in html and "Appendix - Flagged Event Preview" in html
    assert "<h3 style=\"margin-top:16px\">Flagged Events</h3>" not in html


def test_meridian_report_story_uses_meridian_evidence_not_vesper_chain():
    assessment = _load_meridian()
    view = build_assessment_report_view(
        assessment,
        assessment_id=assessment["assessment_id"],
    )

    assert view["title"].startswith("JanuSec Breach Assessment - MERIDIAN")
    story_text = json.dumps(view["executive_story"], sort_keys=True)
    assert "mailbox collection" in story_text
    assert "sensitive file access" in story_text
    assert "command-and-control beaconing" in story_text
    assert "Alibaba Cloud Singapore" in story_text
    assert "Alibaba Cloud China" in story_text
    assert "not state attribution" in story_text
    assert "Chinese government" not in story_text
    assert "SharePoint exfiltration path" not in story_text
    assert "WMI lateral movement" not in story_text

    reason_titles = {item["title"] for item in view["confirmed_reasons"]}
    assert "Mailbox persistence confirmed" in reason_titles
    assert "Sensitive data access confirmed" in reason_titles
    assert view["cluster_rollups"]
    assert len(view["cluster_rollups"]) <= view["cluster_count"]


def test_benign_assessment_does_not_claim_confirmed_breach():
    assessment = {
        "assessment_id": "assessment-benign-noisy",
        "org": "benignco",
        "rows_processed": 2,
        "source_counts": {"benign.csv": 2},
        "clusters": [
            {
                "cluster_id": "benign-1",
                "verdict": "BENIGN_EXPECTED",
                "severity": "low",
                "row_refs": [1, 2],
                "factor_tags": ["noise:admin_activity"],
                "lead_description": "Routine admin login cluster",
            }
        ],
        "rows": [
            {"row_index": 1, "timestamp": "2026-05-01T00:00:00Z", "event_name": "login_success"},
            {"row_index": 2, "timestamp": "2026-05-01T00:10:00Z", "event_name": "file_read"},
        ],
    }
    view = build_assessment_report_view(assessment, assessment_id="assessment-benign-noisy")
    story = view["executive_story"]

    assert view["validated_breach_count"] == 0
    assert "VALIDATED_BREACH" not in view["title"]
    assert "No validated technical breach" in story["what_happened"]
    assert "confirmed breach" not in story["what_happened"].lower()
    assert story["iso27035_lifecycle"]["phases"][2]["status"] == "Assessment required"
