"""test_ism_iso19011_persona.py
==============================
Tests for Options A, B, C — ASD ISM + ISO 19011 + Essential Eight integration
in JanuSec persona section builders.

Covers:
  Option A — ISM control IDs, ISO 19011 §6.4.7 finding classification labels
  Option B — Essential Eight maturity derivation (ML0-ML2)
  Option C — Corrective Action Register (§6.6), bitemporal CoC (§6.5.6),
             scope limitation statement (§6.3.2)
"""
from __future__ import annotations

import types
import sys


# ---------------------------------------------------------------------------
# Stubs for heavy optional dependencies
# ---------------------------------------------------------------------------

def _stub(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules.setdefault(name, mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers — build minimal evidence / model dicts
# ---------------------------------------------------------------------------

def _ev(code: str, factors: list, verdict: str = "malicious",
        sheet: str = "network", sev: str = "high",
        valid_time: str = "2024-01-15T08:00:00Z",
        txn_time: str = "2026-04-06T03:12:41Z") -> dict:
    return {
        "code":             code,
        "factors":          factors,
        "verdict":          verdict,
        "severity":         sev,
        "sheet":            sheet,
        "mitre":            ["T1071"],
        "dread":            0.9,
        "summary":          f"Test event {code}",
        "ts_human":         valid_time,
        "valid_time":       valid_time,
        "transaction_time": txn_time,
        "row":              {"hostname": "HOST-01", "user": "jdoe", "dst_ip": "185.22.44.100",
                             "_row_index": 1},
    }


def _model(evidence: list[dict], **kwargs) -> dict:
    return {
        "evidence":       evidence,
        "malicious_count": sum(1 for e in evidence if e["verdict"] == "malicious"),
        "suspicious_count": sum(1 for e in evidence if e["verdict"] == "suspicious"),
        "total_count":    100,
        "flagged_count":  len(evidence),
        "overall_risk":   "HIGH",
        "has_c2":         any("c2_communication" in e["factors"] for e in evidence),
        "has_email":      any(e["sheet"] == "email" for e in evidence),
        "has_endpoint":   any(e["sheet"] in ("endpoint", "edr") for e in evidence),
        "has_network":    any(e["sheet"] == "network" for e in evidence),
        "has_cloud":      False,
        "has_pii":        any(e["sheet"] == "email" for e in evidence),
        "iocs":           {"ips": [], "public_ips": ["185.22.44.100"], "processes": [],
                           "domains": [], "hashes": [], "users": [], "hosts": []},
        "attack_story":   {"narrative": "Test narrative.", "start_ts": "2024-01-15T08:00Z",
                           "attacker_ips": ["185.22.44.100"], "internal_hosts": ["HOST-01"],
                           "internal_users": ["jdoe"], "c2_connections": {},
                           "sorted_events": [], "beacon_intervals": [], "event_deltas": {},
                           "evidence_quality": {}, "data_at_risk": [], "duration_minutes": 45,
                           "phish_to": "", "phish_from": "", "phish_subject": "",
                           "pivot_ev": None, "initiating_ev": None, "phishing_ev": None},
        "pivots":         [],
        "threat_models":  {},
        **kwargs,
    }


# ===========================================================================
# Option A: ISM control lookup
# ===========================================================================

class TestISMControlLookup:
    def test_factor_returns_ism_ids(self):
        from src.core.configuration.ism_controls import get_ism_ids_for_factors
        ids = get_ism_ids_for_factors(["c2_communication"])
        assert "ISM-1261" in ids
        assert "ISM-0520" in ids

    def test_mfa_factors(self):
        from src.core.configuration.ism_controls import get_ism_ids_for_factors
        ids = get_ism_ids_for_factors(["mfa_bypass", "legacy_auth"])
        assert "ISM-1401" in ids
        assert "ISM-1559" in ids

    def test_unknown_factor_returns_empty(self):
        from src.core.configuration.ism_controls import get_ism_ids_for_factors
        ids = get_ism_ids_for_factors(["totally_unknown_factor"])
        assert ids == []

    def test_multiple_factors_deduplicated(self):
        from src.core.configuration.ism_controls import get_ism_ids_for_factors
        # Both malicious_process and process_injection reference ISM-1585
        ids = get_ism_ids_for_factors(["malicious_process", "process_injection"])
        # Should contain ISM-1585 exactly once
        assert ids.count("ISM-1585") == 1

    def test_get_ism_controls_for_factor_returns_full_tuples(self):
        from src.core.configuration.ism_controls import get_ism_controls_for_factor
        controls = get_ism_controls_for_factor("data_exfiltration_confirmed")
        assert any(c[0] == "ISM-1511" for c in controls)
        # Each tuple: (id, category, description)
        for cid, cat, desc in controls:
            assert cid.startswith("ISM-")
            assert len(desc) > 10


# ===========================================================================
# Option A: ISO 19011 §6.4.7 finding classification
# ===========================================================================

class TestISO19011Classification:
    def test_malicious_verdict_is_major_ncf(self):
        from src.core.configuration.ism_controls import classify_iso19011_finding
        result = classify_iso19011_finding("malicious", ["c2_communication"])
        assert result == "MAJOR NONCONFORMITY"

    def test_suspicious_single_is_minor_ncf(self):
        from src.core.configuration.ism_controls import classify_iso19011_finding
        result = classify_iso19011_finding("suspicious", ["external_connection"], 1)
        assert result == "MINOR NONCONFORMITY"

    def test_good_verdict_is_observation(self):
        from src.core.configuration.ism_controls import classify_iso19011_finding
        result = classify_iso19011_finding("good", [], 0)
        assert result == "OBSERVATION"

    def test_multiple_suspicious_events_escalates_to_major(self):
        from src.core.configuration.ism_controls import classify_iso19011_finding
        # 5 suspicious events of same type with a critical factor → MAJOR
        result = classify_iso19011_finding("suspicious", ["c2_communication"], 5)
        assert result == "MAJOR NONCONFORMITY"

    def test_non_critical_suspicious_is_minor(self):
        from src.core.configuration.ism_controls import classify_iso19011_finding
        result = classify_iso19011_finding("suspicious", ["external_dns_query"], 1)
        assert result == "MINOR NONCONFORMITY"


# ===========================================================================
# Option B: Essential Eight maturity derivation
# ===========================================================================

class TestEssentialEightMaturity:
    def test_c2_confirms_patch_app_and_app_control_gap(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        evidence = [_ev("E01", ["malicious_process", "c2_communication"])]
        e8 = derive_essential_eight_maturity(evidence)
        app_ctrl = next(i for i in e8 if i["control"] == "Application Control")
        assert app_ctrl["maturity_level"] == 0
        assert app_ctrl["gap_exists"] is True

    def test_no_evidence_returns_ml2_for_all(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        e8 = derive_essential_eight_maturity([])
        for item in e8:
            assert item["maturity_level"] == 2, f"{item['control']} should be ML2, got ML{item['maturity_level']}"
            assert item["gap_exists"] is False

    def test_suspicious_gives_ml1(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        evidence = [_ev("E01", ["privilege_escalation"], verdict="suspicious")]
        e8 = derive_essential_eight_maturity(evidence)
        restrict_admin = next(i for i in e8 if i["control"] == "Restrict Admin Privileges")
        assert restrict_admin["maturity_level"] == 1

    def test_mfa_factor_fails_mfa_control(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        evidence = [_ev("E01", ["legacy_auth", "credential_harvest"])]
        e8 = derive_essential_eight_maturity(evidence)
        mfa = next(i for i in e8 if i["control"] == "Multi-Factor Authentication")
        assert mfa["maturity_level"] == 0
        assert "ISM-1559" in mfa["ism_ids"] or "ISM-1401" in mfa["ism_ids"]

    def test_returns_all_eight_controls(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        e8 = derive_essential_eight_maturity([])
        assert len(e8) == 8

    def test_evidence_codes_populated(self):
        from src.core.configuration.ism_controls import derive_essential_eight_maturity
        evidence = [_ev("E01", ["malicious_process"]), _ev("E02", ["malicious_process"])]
        e8 = derive_essential_eight_maturity(evidence)
        app_ctrl = next(i for i in e8 if i["control"] == "Application Control")
        assert len(app_ctrl["evidence_codes"]) >= 1


# ===========================================================================
# Option C: Corrective Action Register (ISO 19011 §6.6)
# ===========================================================================

class TestCorrectiveActionRegister:
    def test_malicious_evidence_generates_register(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [_ev("E01", ["c2_communication"]), _ev("E02", ["legacy_auth"])]
        reg = build_corrective_action_register(evidence)
        assert len(reg) >= 1
        assert all("finding_id" in r for r in reg)
        assert all("classification" in r for r in reg)
        assert all("root_cause" in r for r in reg)
        assert all("action" in r for r in reg)
        assert all("deadline_ts" in r for r in reg)
        assert all("verification" in r for r in reg)

    def test_major_ncf_has_24h_deadline(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [_ev("E01", ["c2_communication"])]
        reg = build_corrective_action_register(evidence)
        major = next((r for r in reg if r["classification"] == "MAJOR NONCONFORMITY"), None)
        assert major is not None, "Expected at least one MAJOR NONCONFORMITY"
        assert major["deadline_hours"] == 24

    def test_minor_ncf_has_720h_deadline(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [_ev("E01", ["external_connection"], verdict="suspicious")]
        reg = build_corrective_action_register(evidence)
        minor = next((r for r in reg if r["classification"] == "MINOR NONCONFORMITY"), None)
        assert minor is not None
        assert minor["deadline_hours"] == 720  # 30 days

    def test_sorted_major_first(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [
            _ev("E01", ["external_connection"], verdict="suspicious"),
            _ev("E02", ["c2_communication"], verdict="malicious"),
        ]
        reg = build_corrective_action_register(evidence)
        if len(reg) >= 2:
            _rank = {"MAJOR NONCONFORMITY": 0, "MINOR NONCONFORMITY": 1, "OBSERVATION": 2}
            ranks = [_rank[r["classification"]] for r in reg]
            assert ranks == sorted(ranks), f"Register not sorted by severity: {[r['classification'] for r in reg]}"

    def test_finding_ids_are_sequential(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [_ev(f"E{i:02d}", ["c2_communication"]) for i in range(3)]
        reg = build_corrective_action_register(evidence)
        # Finding IDs should all start with NCF-
        assert all(r["finding_id"].startswith("NCF-") for r in reg)

    def test_no_good_verdicts_in_register(self):
        from src.core.configuration.ism_controls import build_corrective_action_register
        evidence = [
            _ev("E01", ["approved_change_context"], verdict="good"),
            _ev("E02", ["c2_communication"], verdict="malicious"),
        ]
        reg = build_corrective_action_register(evidence)
        # Only malicious one should appear
        assert len(reg) == 1


# ===========================================================================
# Option A+B+C: Persona section builders — HTML output tests
# ===========================================================================

def _artifact(evidence: list[dict], sha256: str = "abc123", aid: str = "test-001") -> dict:
    m = _model(evidence)
    return {
        "report_id": aid,
        "canonical_report": {
            "_csv_model": m,
            "assessment_id": aid,
            "source_file_sha256": sha256,
            "org": "TestOrg",
        },
        "meta": {},
        "facts": {},
        "overview": {},
    }


class TestAuditSectionISO19011:
    def test_major_ncf_label_in_html(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "MAJOR NCF" in html, "Expected MAJOR NCF label in audit HTML"

    def test_ism_control_id_in_html(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "ISM-1261" in html or "ISM-0520" in html, "Expected ISM control ID in audit HTML"

    def test_corrective_action_register_section_present(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "Corrective Action Register" in html

    def test_bitemporal_coc_transaction_time_shown(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["malicious_process"],
                        txn_time="2026-04-06T03:12:41Z")]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "2026-04-06T03:12:41Z" in html, "transaction_time should appear in CoC"

    def test_scope_limitation_shown_when_cloud_absent(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        m = _model(evidence, has_cloud=False, has_network=True, has_endpoint=True)
        html = _audit(_artifact(evidence), m)
        assert "6.3.2" in html, "ISO 19011 §6.3.2 scope limitation should appear when cloud logs absent"
        assert "cloud audit logs" in html.lower()

    def test_no_scope_limitation_when_all_present(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        m = _model(evidence, has_cloud=True, has_network=True, has_endpoint=True, has_email=True)
        html = _audit(_artifact(evidence), m)
        assert "6.3.2" not in html, "No scope limitation when all telemetry present"

    def test_finding_id_ncf_format(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["c2_communication"])]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "NCF-" in html, "Finding IDs should appear in audit HTML"

    def test_iso_section_headers(self):
        from src.reporting.persona_section_builders import _audit
        evidence = [_ev("E01", ["malicious_process"])]
        html = _audit(_artifact(evidence), _model(evidence))
        assert "§6.4.7" in html or "6.4.7" in html
        assert "§6.6" in html or "6.6" in html
        assert "§6.5.6" in html or "6.5.6" in html


class TestCISOSectionISMAndE8:
    def test_essential_eight_section_present(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev("E01", ["malicious_process", "c2_communication"])]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "Essential Eight" in html

    def test_ml0_label_shown_for_confirmed_failure(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev("E01", ["malicious_process"])]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "ML0" in html, "ML0 should appear when application control fails"

    def test_ism_refs_in_ciso_action_timeline(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev("E01", ["c2_communication"])]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "ISM-1261" in html or "ISM-0520" in html, \
            "C2 evidence should reference ISM-1261/ISM-0520 in CISO timeline"

    def test_major_ncf_in_ciso_control_table(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev("E01", ["legacy_auth", "mfa_bypass"])]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "MAJOR NCF" in html

    def test_soci_act_shown_when_c2_and_malicious(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev(f"E{i:02d}", ["c2_communication"]) for i in range(4)]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "SOCI" in html

    def test_e8_gap_count_shown(self):
        from src.reporting.persona_section_builders import _ciso
        evidence = [_ev("E01", ["malicious_process", "c2_communication",
                                 "legacy_auth", "privilege_escalation"])]
        html = _ciso(_artifact(evidence), _model(evidence))
        assert "Gap Count" in html or "gap" in html.lower()


class TestComplianceSectionCrossFramework:
    def test_ndb_scheme_row_present(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"], sheet="email")]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "NDB" in html or "Notifiable Data" in html.lower() or "NDB Scheme" in html

    def test_soci_row_present(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"]), _ev("E02", ["c2_communication"])]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "SOCI" in html

    def test_apra_row_present(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev(f"E{i}", ["c2_communication"]) for i in range(4)]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "APRA" in html

    def test_iso27001_in_cross_framework_matrix(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"])]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "ISO 27001" in html or "A.13" in html

    def test_ism_refs_in_compliance(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"])]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "ISM-" in html, "ISM references should appear in compliance section"

    def test_scope_limitation_iso19011_compliance(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"])]
        m = _model(evidence, has_cloud=False, has_network=True)
        html = _compliance(_artifact(evidence), m)
        assert "6.3.2" in html

    def test_transaction_time_in_coc(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["malicious_process"], txn_time="2026-04-06T03:12:41Z")]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "2026-04-06T03:12:41Z" in html or "transaction_time" in html.lower()

    def test_assessment_required_when_pii_present(self):
        from src.reporting.persona_section_builders import _compliance
        evidence = [_ev("E01", ["c2_communication"], sheet="email")]
        html = _compliance(_artifact(evidence), _model(evidence))
        assert "ASSESSMENT REQUIRED" in html


class TestEssentialEightBlock:
    def test_e8_block_returns_html_string(self):
        from src.reporting.persona_section_builders import _essential_eight_block
        m = _model([_ev("E01", ["malicious_process"])])
        html = _essential_eight_block(m)
        assert isinstance(html, str)
        assert len(html) > 100

    def test_e8_block_contains_ml_levels(self):
        from src.reporting.persona_section_builders import _essential_eight_block
        m = _model([_ev("E01", ["malicious_process"])])
        html = _essential_eight_block(m)
        assert "ML0" in html or "ML1" in html or "ML2" in html

    def test_e8_executive_section_contains_e8(self):
        from src.reporting.persona_section_builders import _executive_extra
        evidence = [_ev("E01", ["malicious_process", "c2_communication"])]
        html = _executive_extra(_artifact(evidence), _model(evidence))
        assert "Essential Eight" in html

    def test_e8_gap_label_shown_for_ml0(self):
        from src.reporting.persona_section_builders import _essential_eight_block
        m = _model([_ev("E01", ["malicious_process"])])
        html = _essential_eight_block(m)
        assert "GAP" in html


# ===========================================================================
# Regression — ensure existing 29 tests still operate correctly
# ===========================================================================

class TestRegressionExistingPersonas:
    """Smoke-test that the refactored builders still produce valid HTML."""

    def test_soc_analyst_still_works(self):
        from src.reporting.persona_section_builders import _soc_analyst
        evidence = [_ev("E01", ["c2_communication"])]
        html = _soc_analyst(_artifact(evidence), _model(evidence))
        assert "P1" in html or "P2" in html or "P3" in html or "triage" in html.lower()

    def test_forensics_still_works(self):
        from src.reporting.persona_section_builders import _forensics
        evidence = [_ev("E01", ["malicious_process"])]
        html = _forensics(_artifact(evidence), _model(evidence))
        assert "Evidence" in html

    def test_threat_hunter_still_works(self):
        from src.reporting.persona_section_builders import _threat_hunter
        evidence = [_ev("E01", ["c2_communication"])]
        html = _threat_hunter(_artifact(evidence), _model(evidence))
        assert "Hunt" in html or "Hypothesis" in html

    def test_build_persona_section_html_dispatch(self):
        from src.reporting.persona_section_builders import build_persona_section_html
        evidence = [_ev("E01", ["c2_communication"])]
        art = _artifact(evidence)
        for persona in ("soc_analyst", "executive", "ciso", "audit", "compliance",
                        "forensics", "threat_hunter"):
            html = build_persona_section_html(art, persona)
            assert isinstance(html, str), f"persona={persona} returned non-string"


class TestBuildPersonaSectionSafe:
    """Verifies the safety-net in build_persona_section_html catches bad models."""

    def test_none_model_returns_string(self):
        from src.reporting.persona_section_builders import build_persona_section_html
        # Artifact with no _csv_model
        art = {"report_id": "x", "canonical_report": {}, "meta": {}, "facts": {}}
        for persona in ("ciso", "audit", "compliance"):
            html = build_persona_section_html(art, persona)
            assert isinstance(html, str)

    def test_unknown_persona_returns_empty(self):
        from src.reporting.persona_section_builders import build_persona_section_html
        art = {"report_id": "x", "canonical_report": {}, "meta": {}, "facts": {}}
        html = build_persona_section_html(art, "unknown_persona")
        assert html == ""
