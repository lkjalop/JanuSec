from datetime import datetime

from src.reporting.summaries import (
    top5_risk_drivers, top5_factors, top5_iocs, top5_impacted_entities, top5_recommended_actions
)
from src.reporting.decision_support import DecisionSupportEngine
from src.reporting.persona_views import generate_persona_view
from src.reporting.attention_queue import categorize_reports
from src.reporting.feedback_hooks import mark_false_flag, adjust_confidence, factor_disagreement, playbook_mismatch, list_feedback


def _fixture_report():
    return {
        "report_id": "rpt-001",
        "tenant_id": "acme",
        "risk_quantification": {
            "severity": "HIGH",
            "impact_range_usd": (10000, 50000),
            "likelihood_percent": 0.6,
            "expected_loss_usd": 20000,
        },
        "verdict": {
            "final_verdict": "THREAT",
            "final_confidence": 0.86,
            "bayesian_prior": 0.01,
            "bayesian_posterior": 0.5,
            "likelihood_ratio": 15.0,
            "top_contributing_factors": [
                {"factor_name": "beacon_pattern", "factor_category": "network", "contribution_score": 0.9, "evidence_count": 4},
                {"factor_name": "credential_access", "factor_category": "identity", "contribution_score": 0.7, "evidence_count": 3},
            ],
            "all_factors": [
                {"factor_name": "beacon_pattern", "factor_category": "network", "contribution_score": 0.9, "evidence_count": 4},
                {"factor_name": "credential_access", "factor_category": "identity", "contribution_score": 0.7, "evidence_count": 3},
            ],
        },
        "attack_timeline": [
            {"sequence_id": 1, "timestamp": datetime.utcnow(), "event_type": "exfiltration", "description": "data sent", "entity": "host:pc-01", "evidence_refs": ["e1"]},
            {"sequence_id": 2, "timestamp": datetime.utcnow(), "event_type": "lateral_movement", "description": "rdp", "entity": "host:pc-02", "evidence_refs": ["e2"]},
        ],
        "evidence_items": [
            {"evidence_id": "e1", "extracted_iocs": {"ip": ["1.2.3.4"], "domain": ["bad.com"]}},
            {"evidence_id": "e2", "extracted_iocs": {"ip": ["5.6.7.8"], "hash": ["abc123"]}},
        ],
        "recommended_actions": [
            {"primary_action": "Isolate endpoints", "urgency": "immediate", "persona": "soc_analyst"},
            {"primary_action": "Block IOCs", "urgency": "urgent", "persona": "soc_analyst"},
            {"primary_action": "Notify Legal", "urgency": "urgent", "persona": "executive"},
        ],
        "framework_mappings": [
            {"framework": "ISO_27001", "control_id": "A.12.4", "status": "FAIL", "gap_description": "Logging gaps"}
        ],
        "dependency_status": {"seconds_since_ok": 1200},
        "pipeline_version": "p-1",
        "factor_weights_version": "w-1",
        "approval_status": "DRAFT",
    }


def test_summary_signals():
    rpt = _fixture_report()
    assert len(top5_risk_drivers(rpt)) > 0
    assert len(top5_factors(rpt)) > 0
    iocs = top5_iocs(rpt)
    assert "ip" in iocs and len(iocs["ip"]) == 2
    assert len(top5_impacted_entities(rpt)) == 2
    assert len(top5_recommended_actions(rpt)) == 3


def test_decision_gates():
    rpt = _fixture_report()
    gates = DecisionSupportEngine().generate(rpt)
    types = {g["type"] for g in gates}
    assert {"budget_approval", "containment_isolation", "blocklist_update", "disclosure_notification", "investigation_escalation"}.issubset(types)


def test_persona_views():
    rpt = _fixture_report()
    exec_view = generate_persona_view(rpt, "executive", 1)
    assert exec_view["persona"] == "executive"
    soc_view = generate_persona_view(rpt, "soc_analyst", 2)
    assert "timeline" in soc_view
    comp_view = generate_persona_view(rpt, "compliance", 2)
    assert "audit_trail" in comp_view
    hunter_view = generate_persona_view(rpt, "threat_hunter", 3)
    assert "factor_analysis" in hunter_view
    mssp_view = generate_persona_view(rpt, "mssp", 2)
    assert "sla" in mssp_view


def test_attention_queues_and_feedback():
    rpt = _fixture_report()
    queues = categorize_reports([rpt])
    assert rpt["report_id"] in queues["urgent_incidents"]
    assert rpt["report_id"] in queues["policy_gaps"]
    assert rpt["report_id"] in queues["dependency_issues"]

    fb1 = mark_false_flag(rpt, analyst_id="alice", reason="benign test")
    fb2 = adjust_confidence(rpt, analyst_id="bob", new_confidence=0.72, reason="limited evidence")
    fb3 = factor_disagreement(rpt, analyst_id="carol", factor_name="credential_access", reason="artifact weak")
    fb4 = playbook_mismatch(rpt, analyst_id="dan", playbook_id="pb-01", reason="wrong domain")
    all_fb = list_feedback(rpt["report_id"])
    assert len(all_fb) >= 4
