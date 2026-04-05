from src.reporting.email_summaries import tier1_summary, tier2_summary
from src.reporting.comprehensive_report_generator import build_report_html


def test_t1_summary_is_human_readable_and_evidence_based():
    event = {
        "subject": "Urgent invoice review",
        "auth_failed": True,
        "raw_event": {
            "url_enrichment": {"risk": "review"},
            "click_events": [{"user": "alice"}],
        },
    }
    summary = tier1_summary(event)
    assert isinstance(summary.get("summary_text"), str)
    assert "invoice" in summary["summary_text"].lower()
    assert isinstance(summary.get("evidence_basis"), list)
    assert len(summary["evidence_basis"]) >= 2
    assert any("authentication" in item.lower() or "url" in item.lower() for item in summary["evidence_basis"])


def test_t2_summary_adds_next_steps_and_cross_domain_context():
    class Stage:
        def __init__(self, domain, event_id, timestamp, confidence):
            self.domain = domain
            self.event_id = event_id
            self.timestamp = timestamp
            self.confidence = confidence

    class Chain:
        confidence = 0.82
        stages = [
            Stage("identity", "evt-1", 1.0, 0.8),
            Stage("endpoint", "evt-2", 2.0, 0.7),
        ]

    summary = tier2_summary({"subject": "Suspicious sign-in"}, Chain())
    assert "Tier 2 enrichment" in summary["summary_text"]
    assert isinstance(summary.get("timeline"), list) and len(summary["timeline"]) == 2
    assert isinstance(summary.get("next_steps"), list) and len(summary["next_steps"]) >= 2


def test_persona_report_html_is_readable_not_raw_json_dump():
    payload = {
        "title": "Investigation Report",
        "session_id": "sess-1",
        "rows": [
            {
                "verdict": "suspicious",
                "host": "host-a",
                "process_name": "powershell.exe",
                "factors": [{"factor": "powershell_encoded_command"}],
                "dread": {"score": 8.2, "damage": 9},
                "mapping_semantics": {"score": 0.9, "reason": "canonical mapping matched"},
                "correlation_summary": {"verdict": "escalate", "confidence": 0.88, "reason": "same actor hit endpoint and cloud"},
            }
        ],
        "summary": {"rows": 1, "severity_distribution": {"high": 1}},
        "correlation": {
            "verdict": "escalate",
            "confidence": 0.88,
            "top_domains": ["identity", "endpoint"],
            "recommended_action": "Escalate to SOC",
        },
        "meta": {"company_name": "Acme"},
    }
    html = build_report_html(payload)
    assert "demo runner" not in html.lower()
    assert "<pre>" not in html.lower()
    assert "Key factors" in html
    assert "Correlation details" in html
    assert "Escalate to SOC" in html
