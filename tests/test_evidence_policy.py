"""Evidence policy boundary tests.

These tests verify the production evidence boundary rules:
- only telemetry_evidence rows can create confirmed/suspicious findings
- platform priors cannot create fact fields by themselves
- context downgrade requires two attribute matches
- evaluation_answer_key rows cannot create findings
- material threat patterns rank above generic pivots
- Santos context does not bleed into non-Santos assessments
"""
from __future__ import annotations

from src.core.ingest.input_classifier import (
    LANE_TELEMETRY_EVIDENCE,
    LANE_BUSINESS_CONTEXT,
    LANE_EVALUATION_ANSWER_KEY,
    LANE_PLATFORM_PRIOR,
    LANE_LLM_NARRATIVE,
    can_create_finding,
    require_telemetry_provenance,
    validate_context_downgrade,
)
from src.core.ingest.threat_case_builder import build_threat_cases


# ── Lane policy ────────────────────────────────────────────────────────────────

def test_only_telemetry_evidence_can_create_finding():
    assert can_create_finding(LANE_TELEMETRY_EVIDENCE) is True
    assert can_create_finding(LANE_BUSINESS_CONTEXT) is False
    assert can_create_finding(LANE_EVALUATION_ANSWER_KEY) is False
    assert can_create_finding(LANE_PLATFORM_PRIOR) is False
    assert can_create_finding(LANE_LLM_NARRATIVE) is False


def test_require_telemetry_provenance_flags_non_evidence_sources():
    clean_finding = {
        "classification": "confirmed_threat",
        "sources": [{"lane": LANE_TELEMETRY_EVIDENCE, "row_refs": [1, 2]}],
    }
    assert require_telemetry_provenance(clean_finding) == []

    bad_finding = {
        "classification": "confirmed_threat",
        "sources": [{"lane": LANE_BUSINESS_CONTEXT, "row_refs": []}],
    }
    violations = require_telemetry_provenance(bad_finding)
    assert len(violations) > 0

    empty_finding = {"classification": "suspicious_unconfirmed", "sources": []}
    violations = require_telemetry_provenance(empty_finding)
    assert len(violations) > 0


def test_context_downgrade_requires_two_attribute_matches():
    finding = {
        "entity": "alice.walker",
        "time_window": "2026-03-17T10:00/2026-03-17T11:00",
        "source_infra": "WSRV-DC01",
        "tool": "rclone",
    }
    context = {
        "approved_scope": "pentest",
        "entity": "alice.walker",       # match 1
        "time_window": "2026-03-17",    # match 2
    }
    assert validate_context_downgrade(finding, context) is True

    thin_context = {
        "approved_scope": "pentest",
        "entity": "alice.walker",       # only 1 match
    }
    assert validate_context_downgrade(finding, thin_context) is False

    empty_context = {"approved_scope": "general pentest"}
    assert validate_context_downgrade(finding, empty_context) is False


# ── Evaluation answer key quarantine ──────────────────────────────────────────

def test_evaluation_answer_key_rows_do_not_create_findings():
    """Santos enrichment rows tagged evaluation_answer_key must not create threat cases."""
    clusters = [
        {"cluster_id": "pivot-1", "row_refs": [1, 2], "lead_description": "Shared pivot user:rachel.nakamura@santosfreight.com.au"},
    ]
    # Rows explicitly tagged as evaluation lane — should be ignored when creating findings
    santos_rows = [
        {"row_index": 1, "_lane": LANE_EVALUATION_ANSWER_KEY, "_source": "enrichment.xlsx",
         "description": "HR: rachel.nakamura approved travel Hanoi pentest sow"},
        {"row_index": 2, "_lane": LANE_EVALUATION_ANSWER_KEY, "_source": "enrichment.xlsx",
         "description": "Crown jewels register SFL_DATA"},
    ]
    result = build_threat_cases(clusters, santos_rows)
    cases = result["threat_cases"]
    # No confirmed/suspicious case should be built from evaluation-lane rows
    finding_cases = [c for c in cases if c.get("verdict") not in ("NO_VALIDATED_BREACH",)]
    assert all(
        c.get("case_role") not in ("primary_breach", "authorized_test", "approved_travel")
        for c in finding_cases
    ), f"Evaluation rows created production findings: {[c.get('incident_name') for c in finding_cases]}"


def test_non_evidence_lane_rows_do_not_trigger_authorized_test_case():
    """Business context containing pentest keywords must not create AUTHORIZED SECURITY TEST."""
    clusters = []
    biz_rows = [
        {"row_index": 1, "_lane": LANE_BUSINESS_CONTEXT, "_source": "cmdb.xlsx",
         "description": "pentest red team scope of work engagement Q1"},
        {"row_index": 2, "_lane": LANE_BUSINESS_CONTEXT, "_source": "cmdb.xlsx",
         "description": "approved travel overseas access rachel.nakamura"},
    ]
    result = build_threat_cases(clusters, biz_rows)
    cases = result["threat_cases"]
    benign_names = {c.get("incident_name") for c in cases}
    assert "AUTHORIZED SECURITY TEST" not in benign_names, \
        "Business-context rows created AUTHORIZED SECURITY TEST"
    assert "APPROVED OVERSEAS ACCESS" not in benign_names, \
        "Business-context rows created APPROVED OVERSEAS ACCESS"


# ── Cross-assessment isolation ─────────────────────────────────────────────────

SANTOS_TOKENS = [
    "santosfreight",
    "rachel.nakamura",
    "svc_sfl_analytics",
    "marcus.delacroix",
    "aaron.blackwood",
    "janusec_enrichment_context",
]


def test_cross_assessment_santos_tokens_do_not_bleed_into_clean_run():
    """After building threat cases from a clean dataset, no Santos tokens appear."""
    # Simulate a clean non-Santos assessment
    clean_clusters = [
        {"cluster_id": "pivot-1", "row_refs": [10, 11],
         "lead_description": "Shared pivot user:bob.jones@acme.com"},
        {"cluster_id": "pivot-2", "row_refs": [12, 13],
         "lead_description": "rclone backup to external cloud"},
    ]
    clean_rows = [
        {"row_index": 10, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "network.csv",
         "description": "bob.jones login from 10.0.0.1", "triage_score": 0.4},
        {"row_index": 11, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "network.csv",
         "description": "unusual outbound connection", "triage_score": 0.5},
        {"row_index": 12, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "endpoint.ndjson",
         "description": "rclone sync to external cloud destination", "triage_score": 0.9},
        {"row_index": 13, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "endpoint.ndjson",
         "description": "data exfil high volume transfer", "triage_score": 0.85},
    ]

    result = build_threat_cases(clean_clusters, clean_rows)
    result_text = str(result).lower()

    for token in SANTOS_TOKENS:
        assert token not in result_text, \
            f"Santos token '{token}' leaked into clean assessment threat_cases"


# ── Material finding ranking ───────────────────────────────────────────────────

def test_broad_pivot_demoted_below_specific_threat_pattern():
    """A 2-row LSASS chain must rank above a 200-row shared-user pivot."""
    clusters = [
        {
            "cluster_id": "pivot-big",
            "row_refs": list(range(100, 300)),  # 200 rows
            "lead_description": "Shared pivot user:alice@corp.com",
            "row_count": 200,
            "confidence": 0.95,
        },
        {
            "cluster_id": "lsass-chain",
            "row_refs": [1, 2],
            "lead_description": "lsass credential dumping via comsvcs",
            "row_count": 2,
            "confidence": 0.36,
        },
    ]
    lsass_rows = [
        {"row_index": 1, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "endpoint.ndjson",
         "description": "lsass.exe accessed by comsvcs.dll", "triage_score": 0.95},
        {"row_index": 2, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "endpoint.ndjson",
         "description": "credential dumping detected", "triage_score": 0.90},
    ]
    pivot_rows = [
        {"row_index": i, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "network.csv",
         "description": f"login event {i}", "triage_score": 0.3}
        for i in range(100, 300)
    ]

    result = build_threat_cases(clusters, lsass_rows + pivot_rows)
    cases = result["threat_cases"]

    # The LSASS material finding (VALIDATED_BREACH, critical) must be first —
    # regardless of whether it's named primary_breach or credential_theft.
    assert cases, "No threat cases produced"
    top_case = cases[0]
    assert top_case.get("verdict") in ("VALIDATED_BREACH", "CONFIRMED_BREACH"), \
        f"Top case should be a breach finding, got: {top_case.get('verdict')}"
    assert top_case.get("severity") == "critical", \
        f"Top case should be critical severity, got: {top_case.get('severity')}"
    # Must NOT be an unclassified telemetry or generic pivot case at the top
    assert top_case.get("case_id") != "case-unclassified-telemetry", \
        "Generic unclassified telemetry outranked the LSASS material finding"


def test_material_findings_ranked_above_unclassified():
    """Concrete attack patterns always sort above UNCLASSIFIED TELEMETRY."""
    clusters = [
        {"cluster_id": "rclone", "row_refs": [1], "lead_description": "rclone sync to backblaze b2"},
        {"cluster_id": "generic", "row_refs": [2, 3, 4, 5], "lead_description": "Shared pivot host:dc01"},
    ]
    rows = [
        {"row_index": 1, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "net.csv",
         "description": "rclone data exfiltration to external storage", "triage_score": 0.9},
        {"row_index": 2, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "net.csv",
         "description": "generic host login", "triage_score": 0.2},
        {"row_index": 3, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "net.csv",
         "description": "generic host login", "triage_score": 0.2},
        {"row_index": 4, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "net.csv",
         "description": "generic host login", "triage_score": 0.2},
        {"row_index": 5, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "net.csv",
         "description": "generic host login", "triage_score": 0.2},
    ]
    result = build_threat_cases(clusters, rows)
    cases = result["threat_cases"]

    unclassified_idx = next(
        (i for i, c in enumerate(cases) if c.get("case_id") == "case-unclassified-telemetry"), None
    )
    breach_idx = next(
        (i for i, c in enumerate(cases) if c.get("case_role") == "primary_breach"), None
    )
    assert breach_idx is not None, "No primary breach case found"
    if unclassified_idx is not None:
        assert breach_idx < unclassified_idx, \
            "UNCLASSIFIED ranked above PRIMARY BREACH"


def test_unclassified_telemetry_wording_not_background_noise():
    """Unclassified rows must use honest wording, not 'background noise'."""
    clusters = [{"cluster_id": "p1", "row_refs": [1], "lead_description": "unknown activity"}]
    rows = [{"row_index": 1, "_lane": LANE_TELEMETRY_EVIDENCE, "_source": "x.csv",
             "description": "some unrecognised event", "triage_score": 0.1}]

    result = build_threat_cases(clusters, rows)
    result_text = str(result).lower()

    assert "background noise" not in result_text, \
        "Output still uses 'background noise' — must use 'unclassified telemetry'"
