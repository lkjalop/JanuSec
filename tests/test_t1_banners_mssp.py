"""tests/test_t1_banners_mssp.py
===================================
Tests for:
  - T1 headline banners in executive, SOC, forensics, compliance, CISO, audit personas
  - MSSP persona section (_mssp) + _DISPATCH wiring
  - Anti-pattern fixes: empty recommended_actions, loss_range [0,0], MITRE plain-English dicts
"""
from __future__ import annotations
import pytest
from src.reporting.persona_section_builders import (
    _t1_banner,
    _MITRE_PLAIN,
    _FACTOR_NONTECHNICAL,
    _FACTOR_FORENSIC_PLAIN,
    build_persona_section_html,
    _DISPATCH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_model(*, n_mal=0, n_susp=0, has_c2=False, has_pii=False, has_email=False,
                has_network=False, has_endpoint=False, has_cloud=False,
                factors=None, verdict="good"):
    """Build a minimal CSV model for persona section testing."""
    ev = []
    factors = factors or (["c2_communication"] if has_c2 else ["malicious_process"] if n_mal else [])
    for i in range(n_mal):
        ev.append({
            "code": f"E{i+1:02d}", "verdict": "malicious", "severity": "critical",
            "factors": factors, "mitre": ["T1071"], "dread": 8.5,
            "ts_human": "2026-04-07T10:00:00Z",
            "row": {"src_ip": "10.0.0.1", "dst_ip": "185.1.2.3",
                    "hostname": "WIN-CORP-01", "user": "jdoe"},
            "sheet": "network",
        })
    for i in range(n_susp):
        ev.append({
            "code": f"S{i+1:02d}", "verdict": "suspicious", "severity": "high",
            "factors": ["legacy_auth"], "mitre": ["T1078"], "dread": 5.0,
            "ts_human": "2026-04-07T10:05:00Z",
            "row": {"src_ip": "10.0.0.2", "hostname": "WIN-CORP-02"},
            "sheet": "network",
        })
    return {
        "malicious_count": n_mal,
        "suspicious_count": n_susp,
        "has_c2": has_c2,
        "has_pii": has_pii,
        "has_email": has_email,
        "has_network": has_network,
        "has_endpoint": has_endpoint,
        "has_cloud": has_cloud,
        "overall_risk": "CRITICAL" if n_mal > 0 else "MEDIUM" if n_susp > 0 else "LOW",
        "evidence": ev,
        "iocs": {
            "public_ips": ["185.1.2.3"] if has_c2 or n_mal > 0 else [],
            "processes": [],
            "domains": [],
            "hashes": [],
            "hosts": {"WIN-CORP-01"} if n_mal > 0 else set(),
        },
        "attack_story": {
            "internal_hosts": ["WIN-CORP-01"] if n_mal > 0 else [],
            "attacker_ips": ["185.1.2.3"] if has_c2 or n_mal > 0 else [],
            "narrative": "C2 beaconing detected." if has_c2 else "",
            "start_ts": "2026-04-07T10:00:00Z" if ev else "",
            "end_ts": "2026-04-07T10:10:00Z" if ev else "",
            "event_deltas": {},
            "evidence_quality": {e["code"]: "COMPLETE" for e in ev},
            "sorted_events": ev,
        },
        "threat_models": {},
        "pivots": [],
        "total_events": n_mal + n_susp,
    }


def _make_artifact(model=None):
    return {
        "report_id": "test-001",
        "canonical_report": {"_csv_model": model, "assessment_id": "assess-001"},
        "meta": {},
    }


# ---------------------------------------------------------------------------
# _t1_banner helper
# ---------------------------------------------------------------------------

class TestT1Banner:
    def test_investigate_has_red_border(self):
        html = _t1_banner("Alert text", "investigate")
        assert "#c62828" in html
        assert "Alert text" in html

    def test_review_has_amber_border(self):
        html = _t1_banner("Warning text", "review")
        assert "#f57c00" in html

    def test_complete_has_green_border(self):
        html = _t1_banner("All clear", "complete")
        assert "#2e7d32" in html

    def test_html_escaping(self):
        html = _t1_banner("<script>xss</script>", "review")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_default_class_fallback(self):
        html = _t1_banner("text", "unknown_class")
        assert "text" in html


# ---------------------------------------------------------------------------
# MITRE / Factor plain-English dicts
# ---------------------------------------------------------------------------

class TestPlainEnglishDicts:
    def test_mitre_plain_has_t1003(self):
        assert "T1003" in _MITRE_PLAIN
        assert "password" in _MITRE_PLAIN["T1003"].lower()

    def test_mitre_plain_has_t1071(self):
        assert "T1071" in _MITRE_PLAIN
        assert "c2" in _MITRE_PLAIN["T1071"].lower() or "remote" in _MITRE_PLAIN["T1071"].lower()

    def test_factor_nontechnical_c2(self):
        assert "c2_communication" in _FACTOR_NONTECHNICAL
        assert "attacker" in _FACTOR_NONTECHNICAL["c2_communication"].lower()

    def test_factor_forensic_plain_c2(self):
        assert "c2_communication" in _FACTOR_FORENSIC_PLAIN

    def test_factor_nontechnical_no_jargon(self):
        """Non-technical descriptions must not contain raw MITRE IDs."""
        for key, desc in _FACTOR_NONTECHNICAL.items():
            assert "T10" not in desc, f"Factor {key} has MITRE ID in plain-English desc"


# ---------------------------------------------------------------------------
# Executive T1 banner
# ---------------------------------------------------------------------------

class TestExecutiveT1Banner:
    def test_confirmed_attack_headline(self):
        model = _make_model(n_mal=2, has_c2=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "executive")
        assert "confirmed attack" in html.lower() or "immediate escalation" in html.lower()

    def test_benign_headline(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "executive")
        assert "no threat detected" in html.lower()

    def test_suspicious_headline(self):
        model = _make_model(n_mal=0, n_susp=3)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "executive")
        assert "unusual activity" in html.lower() or "under investigation" in html.lower()

    def test_banner_appears_before_pasta(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "executive")
        t1_pos = html.lower().find("confirmed attack")
        pasta_pos = html.find("PASTA")
        assert t1_pos < pasta_pos, "T1 banner must appear before PASTA section"


# ---------------------------------------------------------------------------
# SOC T1 banner
# ---------------------------------------------------------------------------

class TestSOCT1Banner:
    def test_p1_contain_immediately(self):
        model = _make_model(n_mal=2, has_c2=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "soc_analyst")
        assert "P1" in html
        assert "CONTAIN IMMEDIATELY" in html or "CONTAIN" in html

    def test_p1_includes_host(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "soc_analyst")
        assert "WIN-CORP-01" in html or "P1" in html

    def test_p2_investigate(self):
        model = _make_model(n_mal=0, n_susp=2)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "soc_analyst")
        assert "P2" in html

    def test_p4_close_when_benign(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "soc_analyst")
        assert "P3" in html or "P4" in html

    def test_banner_appears_before_triage_queue(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "soc_analyst")
        banner_pos = html.find("border-left")
        triage_pos = html.find("Triage Queue")
        assert banner_pos < triage_pos, "T1 banner must appear before triage queue"


# ---------------------------------------------------------------------------
# Forensics T1 banner
# ---------------------------------------------------------------------------

class TestForensicsT1Banner:
    def test_malicious_includes_factor_plain_english(self):
        model = _make_model(n_mal=1, factors=["credential_harvest"])
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "forensics")
        # Should have a one-liner with plain-English factor text
        assert "credential" in html.lower()

    def test_malicious_includes_host(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "forensics")
        assert "WIN-CORP-01" in html

    def test_malicious_banner_is_red(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "forensics")
        assert "#c62828" in html  # investigate = red border

    def test_benign_banner_is_green(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "forensics")
        assert "#2e7d32" in html  # complete = green border

    def test_banner_before_evidence_inventory(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "forensics")
        banner_pos = html.find("border-left")
        inv_pos = html.find("Evidence Inventory")
        assert banner_pos < inv_pos


# ---------------------------------------------------------------------------
# Compliance T1 banner
# ---------------------------------------------------------------------------

class TestComplianceT1Banner:
    def test_ndb_notification_running(self):
        model = _make_model(n_mal=2, has_pii=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "compliance")
        assert "NDB" in html or "notification" in html.lower()

    def test_no_notification_benign(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "compliance")
        assert "no regulatory notification" in html.lower() or "no confirmed control failures" in html.lower()

    def test_soci_trigger_with_c2(self):
        model = _make_model(n_mal=2, has_c2=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "compliance")
        assert "SOCI" in html or "notification" in html.lower()

    def test_banner_before_notification_table(self):
        model = _make_model(n_mal=1, has_pii=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "compliance")
        banner_pos = html.find("border-left")
        table_pos = html.find("Regulatory Notification")
        assert banner_pos < table_pos


# ---------------------------------------------------------------------------
# CISO T1 banner
# ---------------------------------------------------------------------------

class TestCISOT1Banner:
    def test_confirmed_critical_incident(self):
        model = _make_model(n_mal=3, has_pii=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "ciso")
        assert "CONFIRMED CRITICAL INCIDENT" in html

    def test_includes_event_count(self):
        model = _make_model(n_mal=2)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "ciso")
        assert "2 malicious" in html or "2 event" in html

    def test_disclosure_not_triggered_benign(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "ciso")
        assert "no confirmed incident" in html.lower() or "routine review complete" in html.lower()

    def test_elevated_suspicion_no_confirmed(self):
        model = _make_model(n_mal=0, n_susp=5)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "ciso")
        assert "ELEVATED SUSPICION" in html

    def test_banner_before_risk_posture_table(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "ciso")
        banner_pos = html.find("border-left")
        table_pos = html.find("Current Risk Posture")
        assert banner_pos < table_pos


# ---------------------------------------------------------------------------
# Audit T1 banner
# ---------------------------------------------------------------------------

class TestAuditT1Banner:
    def test_major_nonconformity_text(self):
        model = _make_model(n_mal=2)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "audit")
        assert "AUDIT FINDING" in html
        assert "Major Nonconformity" in html or "immediate corrective action" in html.lower()

    def test_benign_no_nonconformities(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "audit")
        assert "No nonconformities" in html or "no nonconformity" in html.lower()

    def test_banner_before_control_failure_table(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "audit")
        banner_pos = html.find("border-left")
        table_pos = html.find("Control Failure Findings")
        assert banner_pos < table_pos


# ---------------------------------------------------------------------------
# MSSP persona
# ---------------------------------------------------------------------------

class TestMSSPPersona:
    def test_mssp_in_dispatch(self):
        assert "mssp" in _DISPATCH

    def test_mssp_alert_for_malicious(self):
        model = _make_model(n_mal=2, has_c2=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "ALERT" in html
        assert "confirmed malicious" in html.lower()

    def test_mssp_advisory_for_suspicious(self):
        model = _make_model(n_mal=0, n_susp=3)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "ADVISORY" in html or "suspicious" in html.lower()

    def test_mssp_clear_for_benign(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "INFO" in html or "no threats" in html.lower()

    def test_mssp_sla_status_present(self):
        model = _make_model(n_mal=2)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "SLA" in html

    def test_mssp_client_ready_section(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "Client-Ready" in html

    def test_mssp_no_raw_mitre_in_client_section(self):
        """Client findings section must not contain raw MITRE IDs like T1071."""
        model = _make_model(n_mal=1, factors=["c2_communication"])
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        # T1071 comes from evidence mitre field — it may appear in SOC/forensics but
        # in MSSP the client-ready section should use plain language
        client_section_start = html.find("Client-Ready")
        client_section = html[client_section_start:client_section_start + 800] if client_section_start >= 0 else ""
        assert "T1071" not in client_section, "Client section should not contain raw MITRE ID T1071"

    def test_mssp_escalation_steps_present(self):
        model = _make_model(n_mal=1)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "Escalation" in html or "escalation" in html.lower()

    def test_mssp_what_mssp_doing(self):
        model = _make_model(n_mal=1, has_c2=True)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "on Your Behalf" in html or "on your behalf" in html.lower()

    def test_mssp_p1_sla_breached_or_at_risk(self):
        # 2 critical events → BREACHED
        model = _make_model(n_mal=2)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "BREACHED" in html or "AT RISK" in html

    def test_mssp_within_target_for_benign(self):
        model = _make_model(n_mal=0, n_susp=0)
        artifact = _make_artifact(model)
        html = build_persona_section_html(artifact, "mssp")
        assert "WITHIN TARGET" in html

    def test_mssp_none_model_returns_empty(self):
        artifact = _make_artifact(None)
        html = build_persona_section_html(artifact, "mssp")
        assert html == ""


# ---------------------------------------------------------------------------
# Anti-patterns: top5_recommended_actions never empty
# ---------------------------------------------------------------------------

class TestRecommendedActionsAntiPattern:
    def test_empty_actions_returns_monitor_fallback(self):
        from src.reporting.summaries import top5_recommended_actions
        result = top5_recommended_actions({})
        assert len(result) >= 1
        assert "monitor" in result[0]["action"].lower() or "no action" in result[0]["action"].lower()

    def test_nonempty_actions_unchanged(self):
        from src.reporting.summaries import top5_recommended_actions
        report = {"recommended_actions": [
            {"primary_action": "Block IP 1.2.3.4", "urgency": "immediate"},
        ]}
        result = top5_recommended_actions(report)
        assert result[0]["action"] == "Block IP 1.2.3.4"


# ---------------------------------------------------------------------------
# Anti-patterns: loss range [0,0] replaced with text
# ---------------------------------------------------------------------------

class TestLossRangeAntiPattern:
    def test_zero_loss_range_replaced(self):
        from src.reporting.persona_views import _business_impact
        report = {"risk_quantification": {"impact_range_usd": [0, 0], "expected_loss_usd": 0}}
        impact = _business_impact(report)
        assert impact["estimated_loss_range"] == "Financial impact assessment pending"

    def test_real_loss_range_preserved(self):
        from src.reporting.persona_views import _business_impact
        report = {"risk_quantification": {"impact_range_usd": [10000, 50000], "expected_loss_usd": 25000}}
        impact = _business_impact(report)
        assert impact["estimated_loss_range"] == [10000, 50000]

    def test_none_loss_range_replaced(self):
        from src.reporting.persona_views import _business_impact
        report = {"risk_quantification": {}}
        impact = _business_impact(report)
        assert impact["estimated_loss_range"] == "Financial impact assessment pending"
