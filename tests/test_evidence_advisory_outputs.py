from __future__ import annotations

from src.reporting.executive_reporting import (
    build_executive_report_artifact,
    render_executive_report_html,
)


def _payload() -> dict:
    return {
        "assessment_id": "adv-001",
        "org": "ExampleCo",
        "review_state_counts": {"confirmed_malicious": 2, "needs_investigation": 1},
        "rows": [
            {
                "event_id": "e1",
                "severity": "critical",
                "verdict": "malicious",
                "description": "BEC invoice payment change with executive approval pressure",
                "factors": ["email:bec_replyto_mismatch", "identity:mfa_bypass"],
                "user": "ceo@example.com",
                "timestamp": "2026-04-10T10:00:00Z",
            },
            {
                "event_id": "e2",
                "severity": "high",
                "verdict": "malicious",
                "description": "Suspicious endpoint macro spawned shell process",
                "factors": ["endpoint:office_spawn_shell", "endpoint:persistence_novel"],
                "host": "FIN-WS-01",
                "timestamp": "2026-04-10T10:04:00Z",
            },
        ],
        "semantic_top_factors": [
            {"factor_name": "email:bec_replyto_mismatch"},
            {"factor_name": "identity:mfa_bypass"},
            {"factor_name": "endpoint:office_spawn_shell"},
        ],
        "_csv_model": {
            "malicious_count": 2,
            "suspicious_count": 1,
            "has_email": True,
            "has_identity": True,
            "has_endpoint": True,
            "has_pii": False,
            "evidence": [
                {
                    "code": "E01",
                    "verdict": "malicious",
                    "severity": "critical",
                    "factors": ["email:bec_replyto_mismatch", "identity:mfa_bypass"],
                    "row": {"subject": "invoice payment change"},
                }
            ],
        },
    }


def test_leadership_advisory_metadata_is_structured_and_conditional():
    artifact = build_executive_report_artifact(_payload(), options={"persona": "ciso"})
    advisory = artifact["facts"]["advisory_sections"]

    assert advisory["architecture_options"]
    assert advisory["potential_control_exposure"]
    assert advisory["business_review_triggers"]
    assert advisory["external_validation_needed"]
    assert "does not make definitive legal" in advisory["confidence_boundary"]

    first = advisory["architecture_options"][0]
    assert {"evidence_basis", "assumption", "confidence", "requires_external_validation", "recommended_owner", "optional_or_required"} <= set(first)
    assert first["requires_external_validation"] is True


def test_executive_html_renders_advisory_boundary_without_mandatory_claims():
    artifact = build_executive_report_artifact(_payload(), options={"persona": "executive"})
    html = render_executive_report_html(artifact)
    lower = html.lower()

    assert "evidence-based advisory boundary" in lower
    assert "security architecture options" in lower
    assert "business / finance review triggers" in lower
    assert "conditional advisory options" in lower
    assert "mandatory notification" not in lower
    assert "clock is running" not in lower
    assert "materiality requires finance/accounting" in lower or "accounting materiality" in lower


def test_compliance_html_uses_potential_exposure_not_verified_breach_language():
    artifact = build_executive_report_artifact(_payload(), options={"persona": "compliance"})
    html = render_executive_report_html(artifact)
    lower = html.lower()

    assert "regulatory trigger assessment - conditional" in lower
    assert "potential control exposure" in lower
    assert "external validation needed" in lower
    assert "notification required" not in lower
    assert "reportable breach" not in lower
    assert "control failure is not verified" in lower or "not verified" in lower

