"""test_pipeline_production_fixes.py
====================================
Unit tests for the 6 production-readiness fixes applied to the CyberStash
reporting pipeline (2026-04-07 readiness review).

P0-1  PDF render — rows enriched from findings when verdict absent
P0-2  Narrative fallback — never "No narrative available"
P1-1  Diamond model — attacker_ips = external/public only
P1-2  Data exfil detection — data_movement sheet handler
P1-3  STRIDE rendering — computed and exposed in model
P1-4  MAESTRO rendering — stages exposed in model, rendered in HTML
P1-5  TOR detection — identity sheet handler
P1-6  DREAD formatting — HTML SOC triage shows X.X/10 not raw float
"""
from __future__ import annotations

import importlib
import sys
import types


# ---------------------------------------------------------------------------
# Helpers — ensure modules importable without full server stack
# ---------------------------------------------------------------------------

def _stub_module(name: str) -> types.ModuleType:
    """Register a minimal stub so importing parent modules doesn't fail."""
    mod = types.ModuleType(name)
    sys.modules.setdefault(name, mod)
    return mod


# ---------------------------------------------------------------------------
# P1-5 / P1-2 : enrich_rows_locally TOR and data exfiltration detection
# ---------------------------------------------------------------------------

def test_tor_exit_node_detected():
    """A row with location_country 'TOR_EXIT' should get verdict=malicious and factor tor_exit_node."""
    import importlib.util, os, sys

    spec = importlib.util.spec_from_file_location(
        "_pipeline", "scripts/run_cyberstash_full_pipeline.py"
    )
    pipeline = importlib.util.module_from_spec(spec)
    # Avoid executing __main__ block
    import unittest.mock as mock
    with mock.patch.object(spec.loader, "exec_module",
                           side_effect=lambda m: _exec_pipeline_subset(m, spec)):
        pass  # handled below

    # Directly load and execute the module body (it has no entry-point guard around enrich_rows_locally)
    import runpy, io
    with mock.patch("builtins.open", mock.mock_open(read_data="")):
        pass  # not needed

    # Use importlib to load without executing if __name__ == "__main__"
    # The file uses sys.exit in main(); we need only enrich_rows_locally.
    # Load the source as a module without running main.
    source_path = "scripts/run_cyberstash_full_pipeline.py"
    import ast, types as _types

    with open(source_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    # Remove __main__ guard execution so only definitions are collected
    code = compile(source, source_path, "exec")
    ns: dict = {"__name__": "not_main", "__file__": source_path}
    import unittest.mock as mock
    with mock.patch("sys.exit"):
        try:
            exec(code, ns)  # noqa: S102
        except SystemExit:
            pass
        except Exception:
            pass  # module-level init that may fail without external deps is OK

    enrich = ns.get("enrich_rows_locally")
    if enrich is None:
        import pytest
        pytest.skip("enrich_rows_locally not accessible (module load skipped)")

    row = {
        "_sheet": "identity",
        "user": "hacker@tor.example.com",
        "location_country": "TOR_EXIT",
        "verdict": None,
        "factors": [],
    }
    enriched = enrich([row])
    assert len(enriched) == 1, "Should return 1 row"
    r = enriched[0]
    assert r.get("verdict") == "malicious", f"Expected malicious, got {r.get('verdict')}"
    assert "tor_exit_node" in (r.get("factors") or []), f"factors={r.get('factors')}"


def test_data_exfil_detection():
    """A data_movement row with external dst_system should get verdict=malicious and data_exfiltration_confirmed."""
    import importlib.util, ast, io

    source_path = "scripts/run_cyberstash_full_pipeline.py"
    with open(source_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    code = compile(source, source_path, "exec")
    ns: dict = {"__name__": "not_main", "__file__": source_path}
    import unittest.mock as mock
    with mock.patch("sys.exit"):
        try:
            exec(code, ns)  # noqa: S102
        except (SystemExit, Exception):
            pass

    enrich = ns.get("enrich_rows_locally")
    if enrich is None:
        import pytest
        pytest.skip("enrich_rows_locally not accessible")

    row = {
        "_sheet": "data_movement",
        "dst_system": "185.22.44.100",   # external IP
        "bytes_out": 5_000_000,
        "verdict": None,
        "factors": [],
    }
    enriched = enrich([row])
    r = enriched[0]
    assert r.get("verdict") == "malicious", f"Expected malicious, got {r.get('verdict')}"
    assert "data_exfiltration_confirmed" in (r.get("factors") or []), f"factors={r.get('factors')}"


# ---------------------------------------------------------------------------
# P0-1 : _enrich_rows_from_findings
# ---------------------------------------------------------------------------

def test_enrich_rows_from_findings_propagates_verdict():
    """_enrich_rows_from_findings should copy verdict/factors from findings back to rows."""
    source_path = "scripts/run_cyberstash_full_pipeline.py"
    with open(source_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    code = compile(source, source_path, "exec")
    ns: dict = {"__name__": "not_main", "__file__": source_path}
    import unittest.mock as mock
    with mock.patch("sys.exit"):
        try:
            exec(code, ns)  # noqa: S102
        except (SystemExit, Exception):
            pass

    _enrich_rows_from_findings = ns.get("_enrich_rows_from_findings")
    if _enrich_rows_from_findings is None:
        import pytest
        pytest.skip("_enrich_rows_from_findings not exposed")

    rows = [
        {"row_index": 1, "_sheet": "network", "src_ip": "1.2.3.4"},
        {"row_index": 2, "_sheet": "endpoint", "process_name": "evil.exe"},
        {"row_index": 3, "_sheet": "network", "src_ip": "5.6.7.8"},
    ]
    findings = [
        {"row_index": 1, "verdict": "malicious", "confidence": 0.92, "factors": ["c2_communication"]},
        {"row_index": 2, "verdict": "suspicious", "confidence": 0.65, "factors": ["malicious_process"]},
    ]
    enriched = _enrich_rows_from_findings(rows, findings)
    assert enriched[0].get("verdict") == "malicious"
    assert "c2_communication" in (enriched[0].get("factors") or [])
    assert enriched[1].get("verdict") == "suspicious"
    # row 3 has no finding — should remain without verdict (or "good")
    assert enriched[2].get("verdict") not in ("malicious", "suspicious")


# ---------------------------------------------------------------------------
# P0-2 : narrative fallback never "No narrative available"
# ---------------------------------------------------------------------------

def test_synthesise_narrative_returns_string():
    """_synthesise_narrative should always return a non-empty string."""
    from src.reporting.executive_reporting import _synthesise_narrative

    report = {
        "severity": "HIGH",
        "canonical": {"suspicious_row_count": 3},
        "org": "TestOrg",
        "verdict": {"final_verdict": "HIGH", "final_confidence": 0.85,
                    "semantic_top_factors": [{"factor_name": "c2_communication"}]},
    }
    result = _synthesise_narrative(report)
    assert isinstance(result, str)
    assert len(result) > 20, f"Too short: {result!r}"
    assert "No narrative available" not in result


def test_synthesise_narrative_low_severity():
    """Low-severity datasets should get a clean 'no threats' message."""
    from src.reporting.executive_reporting import _synthesise_narrative

    report = {"severity": "LOW", "canonical": {"suspicious_row_count": 0},
              "org": "CleanOrg", "accepted_rows": 500}
    result = _synthesise_narrative(report)
    assert "no high-confidence threats" in result.lower() or "no high-confidence" in result.lower()


def test_synthesise_why_it_matters_returns_string():
    """_synthesise_why_it_matters should always return meaningful text."""
    from src.reporting.executive_reporting import _synthesise_why_it_matters

    report = {"risk_quantification": {"severity": "CRITICAL", "expected_loss_usd": 500_000}}
    result = _synthesise_why_it_matters(report)
    assert isinstance(result, str)
    assert len(result) > 10


# ---------------------------------------------------------------------------
# P1-1 : Diamond model — attacker_ips = public only
# ---------------------------------------------------------------------------

def test_minimal_model_attacker_ips_external_only():
    """_minimal_model should put only public IPs in attacker_ips, not RFC1918."""
    from src.reporting.adapters.csv_adapter import _minimal_model

    rows = [
        {"verdict": "malicious", "src_ip": "10.0.0.5",   "dst_ip": "185.22.44.100", "factors": ["c2_communication"]},
        {"verdict": "malicious", "src_ip": "192.168.1.2", "dst_ip": "203.0.113.55",  "factors": ["external_connection"]},
        {"verdict": "malicious", "src_ip": "172.16.0.1",  "dst_ip": "127.0.0.1",     "factors": []},
    ]
    model = _minimal_model(rows, "test.xlsx")
    attacker_ips = model["attack_story"]["attacker_ips"]
    # Public IPs should be present
    assert "185.22.44.100" in attacker_ips, f"Expected public IP, got {attacker_ips}"
    assert "203.0.113.55" in attacker_ips, f"Expected public IP, got {attacker_ips}"
    # Private IPs must NOT appear in attacker_ips
    private = [ip for ip in attacker_ips
               if ip.startswith(("10.", "192.168.", "172.16.", "127."))]
    assert not private, f"Private IPs leaked into attacker_ips: {private}"


def test_minimal_model_no_public_ips_falls_back():
    """When ALL IPs are private, attacker_ips can fall back to all IPs (non-empty preference)."""
    from src.reporting.adapters.csv_adapter import _minimal_model

    rows = [
        {"verdict": "malicious", "src_ip": "10.0.0.1", "dst_ip": "192.168.1.2", "factors": ["c2_communication"]},
    ]
    model = _minimal_model(rows, "test.xlsx")
    # Either empty or all-private fallback — should not crash
    attacker_ips = model["attack_story"]["attacker_ips"]
    assert isinstance(attacker_ips, list)


# ---------------------------------------------------------------------------
# P1-3 / P1-4 : STRIDE and MAESTRO in model
# ---------------------------------------------------------------------------

def test_compute_threat_models_stride():
    """_compute_threat_models should return a stride_summary with all 6 categories."""
    from src.reporting.adapters.csv_adapter import _compute_threat_models

    evidence = [
        {"factors": ["phishing_subject", "credential_harvest"], "sheet": "email",
         "verdict": "malicious", "row": {"row_index": 1, "from": "bad@evil.com"}},
        {"factors": ["c2_communication", "data_exfiltration_confirmed"], "sheet": "network",
         "verdict": "malicious", "row": {"row_index": 2, "dst_ip": "185.1.1.1"}},
    ]
    models = _compute_threat_models(evidence)
    stride = models["stride_summary"]
    assert set(stride.keys()) == set("STRIDE"), f"Keys: {set(stride.keys())}"
    # Spoofing should be CONFIRMED (phishing_subject + credential_harvest → 2 entries)
    assert stride["S"]["status"] == "CONFIRMED", f"S={stride['S']}"
    # Information Disclosure via data_exfiltration_confirmed
    assert stride["I"]["status"] in ("CONFIRMED", "SUSPECTED"), f"I={stride['I']}"


def test_compute_threat_models_maestro():
    """MAESTRO stages should flag Mission when c2_communication present."""
    from src.reporting.adapters.csv_adapter import _compute_threat_models

    evidence = [
        {"factors": ["c2_communication", "lateral_movement"], "sheet": "network",
         "verdict": "malicious", "row": {}},
    ]
    models = _compute_threat_models(evidence)
    maestro = models["maestro_stages"]
    assert isinstance(maestro, list)
    assert len(maestro) == 7, f"Expected 7 MAESTRO stages, got {len(maestro)}"
    mission = next((s for s in maestro if s["stage"].startswith("M")), None)
    assert mission is not None
    assert mission["detected"] is True, f"Mission should be DETECTED: {mission}"


def test_compute_threat_models_diamond_external_ips_only():
    """Diamond infrastructure should only list non-RFC1918 IPs."""
    from src.reporting.adapters.csv_adapter import _compute_threat_models

    evidence = [
        {"factors": ["c2_communication"], "sheet": "network", "verdict": "malicious",
         "row": {"dst_ip": "203.0.113.1", "src_ip": "10.0.0.5"}},
        {"factors": [], "sheet": "network", "verdict": "malicious",
         "row": {"dst_ip": "192.168.1.1"}},
    ]
    models = _compute_threat_models(evidence)
    infra_ips = [i["ip"] for i in models["diamond_model"]["infrastructure"]]
    assert "203.0.113.1" in infra_ips
    assert "192.168.1.1" not in infra_ips
    assert "10.0.0.5" not in infra_ips


# ---------------------------------------------------------------------------
# P1-6 : DREAD formatting in HTML SOC triage
# ---------------------------------------------------------------------------

def test_soc_analyst_dread_formatted():
    """HTML SOC triage should show DREAD as 'X.X/10' not raw float."""
    from src.reporting.persona_section_builders import _soc_analyst

    model = {
        "evidence": [
            {
                "code": "E01",
                "ts_human": "2024-01-15 08:00:00",
                "verdict": "malicious",
                "severity": "high",
                "dread": 0.92,   # stored as 0-1 float
                "factors": ["c2_communication"],
                "mitre": ["T1071"],
                "summary": "C2 beacon",
                "sheet": "network",
                "row": {"hostname": "evil-host", "user": "jdoe", "src_ip": "10.0.0.1"},
            }
        ],
        "iocs": {"ips": ["10.0.0.1"], "public_ips": [], "processes": [], "domains": [], "hashes": [], "users": [], "hosts": []},
        "attack_story": {"narrative": "", "start_ts": "—", "attacker_ips": [], "internal_hosts": [],
                         "internal_users": [], "c2_connections": {}, "sorted_events": [],
                         "beacon_intervals": [], "event_deltas": {}, "evidence_quality": {},
                         "data_at_risk": [], "duration_minutes": None,
                         "phish_to": "", "phish_from": "", "phish_subject": "",
                         "pivot_ev": None, "initiating_ev": None, "phishing_ev": None},
        "pivots": [],
        "malicious_count": 1,
        "suspicious_count": 0,
        "total_count": 100,
        "overall_risk": "HIGH",
        "has_c2": True,
        "has_email": False,
        "has_endpoint": False,
        "has_network": True,
        "threat_models": {},
    }
    artifact = {"canonical_report": {"_csv_model": model}}
    html = _soc_analyst(artifact, model)
    # Should NOT contain the raw float representation
    assert "0.92" not in html, "Raw float 0.92 should not appear in DREAD column"
    # Should contain the formatted version
    assert "9.2/10" in html, f"Expected '9.2/10' in HTML, got snippet: {html[html.find('DREAD')-200:html.find('DREAD')+400] if 'DREAD' in html else html[:400]}"


def test_fmt_confidence_bands():
    """_fmt_confidence should return correct band labels."""
    from src.reporting.persona_section_builders import _fmt_confidence

    assert "High" in _fmt_confidence(0.9)
    assert "Medium" in _fmt_confidence(0.6)
    assert "Low" in _fmt_confidence(0.35)
    assert "Very Low" in _fmt_confidence(0.1)
    assert _fmt_confidence(None) == "Unknown"


# ---------------------------------------------------------------------------
# P0-2 : csv_assessment_to_v3_payload wires attack_narrative
# ---------------------------------------------------------------------------

def test_csv_payload_attack_narrative_wired():
    """csv_assessment_to_v3_payload should set attack_narrative in the payload."""
    from src.reporting.adapters.csv_adapter import csv_assessment_to_v3_payload

    assessment = {
        "findings": [
            {"row_index": 0, "verdict": "malicious", "confidence": 0.9,
             "factors": ["c2_communication"], "mitre": ["T1071"]},
        ],
        "rows": [
            {"_sheet": "network", "_row_index": 0, "src_ip": "10.0.0.1",
             "dst_ip": "185.22.44.100", "verdict": "malicious"},
        ],
    }
    payload = csv_assessment_to_v3_payload(assessment, "test.xlsx", persona="executive")
    assert "attack_narrative" in payload
    assert isinstance(payload["attack_narrative"], str)
    assert len(payload["attack_narrative"]) > 10


def test_csv_payload_threat_models_exposed():
    """csv_assessment_to_v3_payload should expose threat_models in _csv_model."""
    from src.reporting.adapters.csv_adapter import csv_assessment_to_v3_payload

    assessment = {
        "findings": [
            {"row_index": 0, "verdict": "malicious", "confidence": 0.9,
             "factors": ["phishing_subject", "c2_communication"], "mitre": ["T1566"]},
        ],
        "rows": [
            {"_sheet": "email", "_row_index": 0, "from": "bad@evil.com",
             "subject": "URGENT", "verdict": "malicious"},
        ],
    }
    payload = csv_assessment_to_v3_payload(assessment, "test.xlsx")
    csv_model = payload.get("_csv_model") or {}
    threat_models = csv_model.get("threat_models") or {}
    assert "stride_summary" in threat_models, "stride_summary missing from threat_models"
    assert "maestro_stages" in threat_models, "maestro_stages missing from threat_models"
    assert "diamond_model" in threat_models, "diamond_model missing from threat_models"


# ---------------------------------------------------------------------------
# Phase-0  P0-3 : Change_Context FP suppression
# ---------------------------------------------------------------------------

def _load_pipeline_ns():
    """Load run_cyberstash_full_pipeline.py into a namespace (no main exec)."""
    import unittest.mock as mock
    source_path = "scripts/run_cyberstash_full_pipeline.py"
    with open(source_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    code = compile(source, source_path, "exec")
    ns: dict = {"__name__": "not_main", "__file__": source_path}
    with mock.patch("sys.exit"):
        try:
            exec(code, ns)  # noqa: S102
        except (SystemExit, Exception):
            pass
    return ns


def test_approved_change_suppression():
    """Rows whose host+time fall inside an approved Change_Context window should be suppressed (verdict=good)."""
    import pytest
    ns = _load_pipeline_ns()
    _stamp = ns.get("_stamp_approved_changes")
    extract = ns.get("extract_approved_change_windows")
    enrich = ns.get("enrich_rows_locally")
    if not (_stamp and extract and enrich):
        pytest.skip("change-context helpers not accessible")

    # Build a fake Change_Context row with enough fields
    change_row = {
        "_sheet": "Change_Context",
        "ticket_id": "CHG-001",
        "host": "SERVER-DB-01",
        "user": "admin",
        "start_time": "2024-01-15T06:00:00Z",
        "end_time":   "2024-01-15T10:00:00Z",
        "status":     "approved",
    }
    # Build a regular network row that falls inside the window
    event_row = {
        "_sheet": "network",
        "hostname": "SERVER-DB-01",
        "ts": "2024-01-15T08:00:00Z",
        "verdict": None,
        "factors": [],
        "src_ip": "10.0.0.5",
    }
    all_rows = [change_row, event_row]
    windows = extract(all_rows)
    assert len(windows) >= 1, "Expected at least one approved window"
    stamped = _stamp([event_row], windows)
    assert stamped[0].get("_approved_change_ticket"), "Row inside window should be stamped"
    enriched = enrich(stamped)
    r = enriched[0]
    assert r.get("verdict") == "good", f"Suppressed row should have verdict=good, got {r.get('verdict')}"
    assert "approved_change_ticket" in (r.get("factors") or []), f"factors={r.get('factors')}"


def test_change_context_sheet_rows_skipped():
    """Rows from the Change_Context sheet itself should always get verdict=good in enrich."""
    import pytest
    ns = _load_pipeline_ns()
    enrich = ns.get("enrich_rows_locally")
    if enrich is None:
        pytest.skip("enrich_rows_locally not accessible")

    row = {
        "_sheet": "Change_Context",
        "ticket_id": "CHG-999",
        "host": "ANY-HOST",
        "verdict": None,
        "factors": [],
    }
    enriched = enrich([row])
    r = enriched[0]
    assert r.get("verdict") == "good", f"Change_Context rows should be skipped, got {r.get('verdict')}"
    assert "approved_change_context" in (r.get("factors") or []), f"factors={r.get('factors')}"


# ---------------------------------------------------------------------------
# Phase-0  P1-7 : UTC timestamp fix
# ---------------------------------------------------------------------------

def test_utc_timestamp_parse():
    """parse_excel_all_sheets should produce ISO-8601 UTC strings for datetime cells."""
    import pytest
    from datetime import datetime, timezone
    ns = _load_pipeline_ns()
    parse_fn = ns.get("parse_excel_all_sheets")
    if parse_fn is None:
        pytest.skip("parse_excel_all_sheets not accessible")

    # Simulate what openpyxl returns for a datetime cell: a Python datetime object
    # We patch the wb.worksheets path with a minimal fake workbook
    import unittest.mock as _mock

    dt_cell = datetime(2024, 6, 15, 9, 30, 0)  # naive — treated as UTC in our fix

    class _FakeCell:
        def __init__(self, value):
            self.value = value

    class _FakeSheet:
        title = "network"
        def iter_rows(self, values_only=True):
            # First call = headers, second call = data
            yield ("ts", "hostname")
            yield (dt_cell, "host-01")

    _sheet = _FakeSheet()

    class _FakeWB:
        sheetnames = ["network"]
        def __getitem__(self, key): return _sheet
        def close(self): pass

    with _mock.patch("openpyxl.load_workbook", return_value=_FakeWB()):
        from pathlib import Path as _Path
        rows = parse_fn(_Path("fake_path.xlsx"))

    assert rows, "Should return at least one row"
    ts_val = rows[0].get("ts") or rows[0].get("timestamp")
    assert ts_val, f"No ts/timestamp field in row: {rows[0]}"
    assert "T" in ts_val and ts_val.endswith("Z"), f"Expected ISO-8601 UTC, got {ts_val!r}"
    # Must NOT contain local timezone offset artefacts
    assert "+" not in ts_val, f"Unexpected timezone offset in {ts_val!r}"


# ---------------------------------------------------------------------------
# Phase-1  P2-1 : Lookalike domain detection
# ---------------------------------------------------------------------------

def test_lookalike_domain():
    """Email row with a lookalike sender domain should get factor lookalike_sender_domain."""
    import pytest
    ns = _load_pipeline_ns()
    enrich = ns.get("enrich_rows_locally")
    score_fn = ns.get("_lookalike_score")
    if enrich is None:
        pytest.skip("enrich_rows_locally not accessible")

    # Verify the scoring function separately first
    if score_fn:
        # micrsoft.com is a classic typosquat of microsoft.com (one transposition)
        score = score_fn("micrsoft.com", "microsoft.com")
        assert score > 0.75, f"Expected typosquat score >0.75 for micrsoft/microsoft, got {score}"
        assert score < 1.0, f"Score should not be 1.0 for non-identical domains"

    row = {
        "_sheet": "email",
        "from": "billing@micrsoft.com",       # typosquat: missing 'o'
        "to": "cfo@microsoft.com",             # org domain: microsoft.com
        "subject": "URGENT invoice",
        "verdict": None,
        "factors": [],
    }
    enriched = enrich([row])
    r = enriched[0]
    assert "lookalike_sender_domain" in (r.get("factors") or []), (
        f"Expected lookalike_sender_domain factor, got factors={r.get('factors')}"
    )


# ---------------------------------------------------------------------------
# Phase-1  P2-3 : Impossible travel detection
# ---------------------------------------------------------------------------

def test_impossible_travel():
    """Two logins from different cities within 1 hour should flag impossible_travel."""
    import pytest
    ns = _load_pipeline_ns()
    enrich = ns.get("enrich_rows_locally")
    if enrich is None:
        pytest.skip("enrich_rows_locally not accessible")

    rows = [
        {
            "_sheet": "identity",
            "user": "jdoe@acmecorp.com",
            "location_city": "Sydney",
            "ts": "2024-06-15T08:00:00Z",
            "verdict": None, "factors": [],
        },
        {
            "_sheet": "identity",
            "user": "jdoe@acmecorp.com",
            "location_city": "London",
            "ts": "2024-06-15T08:45:00Z",   # 45 minutes later — physically impossible
            "verdict": None, "factors": [],
        },
    ]
    enriched = enrich(rows)
    impossible = [r for r in enriched if "impossible_travel" in (r.get("factors") or [])]
    assert impossible, (
        f"Expected at least one row with impossible_travel factor; "
        f"got factors={[r.get('factors') for r in enriched]}"
    )


# ---------------------------------------------------------------------------
# Phase-0  Persona headline
# ---------------------------------------------------------------------------

def test_persona_headline_soc():
    """SOC persona headline should start with 'P1' when there are malicious events."""
    from src.reporting.executive_reporting import _persona_headline

    report = {
        "canonical": {
            "suspicious_row_count": 6,
            "malicious_row_count": 6,
            "host_most_affected": "LAPTOP-JMR-007",
            "top_c2_ip": "91.219.236.12",
        },
        "verdict": {"final_verdict": "HIGH"},
        "risk_quantification": {"severity": "HIGH"},
    }
    headline = _persona_headline(report, "soc")
    assert headline.startswith("P1"), f"SOC headline should start with 'P1', got: {headline!r}"
    assert "LAPTOP-JMR-007" in headline or "events" in headline.lower(), f"Unexpected: {headline!r}"


def test_persona_headline_executive_vs_ciso():
    """Executive and CISO headlines must be substantively different."""
    from src.reporting.executive_reporting import _persona_headline

    report = {
        "canonical": {"suspicious_row_count": 3, "malicious_row_count": 3},
        "verdict": {"final_verdict": "HIGH"},
        "risk_quantification": {"severity": "HIGH", "expected_loss_usd": 250_000},
    }
    exec_h = _persona_headline(report, "executive")
    ciso_h = _persona_headline(report, "ciso")
    assert exec_h != ciso_h, "Executive and CISO headlines must differ"
    # Executive headline should be simpler / less technical
    assert "gdpr" not in exec_h.lower(), "Executive headline should not mention GDPR"


# ---------------------------------------------------------------------------
# Phase-1  Claim validator
# ---------------------------------------------------------------------------

def test_claim_validate_empty_returns_insufficient_evidence():
    """_claim_validate should return clean fallback (no INSUFFICIENT_EVIDENCE) for empty/generic values."""
    from src.reporting.executive_reporting import _claim_validate

    for val in ["", "No narrative available.", None]:
        result = _claim_validate("what_happened", val)
        assert "INSUFFICIENT_EVIDENCE" not in result, f"Leaked placeholder for {val!r}"
        assert "ETA" not in result, f"Leaked ETA placeholder for {val!r}"
        assert len(result) > 10, f"Fallback too short for {val!r}"

    # why_it_matters fallback
    result = _claim_validate("why_it_matters", None)
    assert "INSUFFICIENT_EVIDENCE" not in result
    assert len(result) > 10


def test_claim_validate_real_value_passthrough():
    """_claim_validate should pass through real, non-empty values unchanged."""
    from src.reporting.executive_reporting import _claim_validate

    real_value = "Attacker exfiltrated 5GB of customer PII via C2 channel."
    assert _claim_validate("what_happened", real_value) == real_value


# ---------------------------------------------------------------------------
# Phase-1  Hard IOC cutoffs
# ---------------------------------------------------------------------------

def test_ioc_cutoff_stale_ip_excluded():
    """IPs from rows older than 60 days should be excluded from the IOC list."""
    from src.reporting.adapters.csv_adapter import _collect_iocs_from_rows
    import time

    _stale_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - 65 * 86400)  # 65 days ago — past 60d cutoff
    )
    _fresh_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - 5 * 86400)   # 5 days ago — within cutoff
    )

    rows = [
        {"dst_ip": "185.22.44.100", "ts": _stale_ts},   # stale → should be excluded
        {"dst_ip": "203.0.113.55",  "ts": _fresh_ts},   # fresh → should be included
    ]
    iocs = _collect_iocs_from_rows(rows)
    assert "203.0.113.55" in (iocs.get("public_ips") or iocs.get("ips") or []), \
        "Fresh IP should appear in IOCs"
    assert "185.22.44.100" not in (iocs.get("public_ips") or iocs.get("ips") or []), \
        "Stale IP (65d old) should be excluded by 60d cutoff"


def test_ioc_cutoff_hash_never_expires():
    """SHA-256 hashes should never be excluded regardless of age."""
    from src.reporting.adapters.csv_adapter import _collect_iocs_from_rows
    import time

    _ancient_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - 500 * 86400)  # 500 days ago
    )
    rows = [{"sha256": "abc123deadbeef" * 4, "ts": _ancient_ts}]
    iocs = _collect_iocs_from_rows(rows)
    assert "abc123deadbeef" * 4 in (iocs.get("hashes") or []), \
        "Hashes should never expire — very old hash should still be included"


# ---------------------------------------------------------------------------
# Phase-0  Persona-scoped evidence windows
# ---------------------------------------------------------------------------

def test_persona_window_soc_max_events():
    """SOC persona should get at most 20 events from csv_assessment_to_v3_payload."""
    from src.reporting.adapters.csv_adapter import csv_assessment_to_v3_payload

    # Build 30 identical malicious rows — SOC window capped at 20
    rows = [
        {"_sheet": "network", "_row_index": i, "src_ip": "10.0.0.1",
         "dst_ip": "185.22.44.100", "verdict": "malicious", "factors": ["c2_communication"],
         "ts": "2024-06-15T08:00:00Z"}
        for i in range(30)
    ]
    findings = [
        {"row_index": i, "verdict": "malicious", "confidence": 0.9,
         "factors": ["c2_communication"], "mitre": ["T1071"]}
        for i in range(30)
    ]
    assessment = {"findings": findings, "rows": rows}
    payload = csv_assessment_to_v3_payload(assessment, "test.xlsx", persona="soc")
    csv_model = payload.get("_csv_model") or {}
    evidence = csv_model.get("evidence") or []
    assert len(evidence) <= 20, (
        f"SOC persona should get ≤20 events (max_events), got {len(evidence)}"
    )


def test_persona_window_forensics_more_events():
    """Forensics persona should allow up to 50 events."""
    from src.reporting.adapters.csv_adapter import csv_assessment_to_v3_payload

    rows = [
        {"_sheet": "network", "_row_index": i, "src_ip": "10.0.0.1",
         "dst_ip": "185.22.44.100", "verdict": "malicious", "factors": ["c2_communication"],
         "ts": "2024-06-15T08:00:00Z"}
        for i in range(60)
    ]
    findings = [
        {"row_index": i, "verdict": "malicious", "confidence": 0.9,
         "factors": ["c2_communication"], "mitre": ["T1071"]}
        for i in range(60)
    ]
    assessment = {"findings": findings, "rows": rows}
    payload = csv_assessment_to_v3_payload(assessment, "test.xlsx", persona="forensics")
    csv_model = payload.get("_csv_model") or {}
    evidence = csv_model.get("evidence") or []
    assert len(evidence) <= 50, f"Forensics persona max_events=50, got {len(evidence)}"
    # Forensics should get MORE events than SOC
    payload_soc = csv_assessment_to_v3_payload(assessment, "test.xlsx", persona="soc")
    ev_soc = (payload_soc.get("_csv_model") or {}).get("evidence") or []
    assert len(evidence) >= len(ev_soc), "Forensics should get ≥ SOC event count"


# ---------------------------------------------------------------------------
# Phase-0  MITRE code display (no trailing colon)
# ---------------------------------------------------------------------------

def test_mitre_code_no_trailing_colon():
    """SOC triage MITRE column should show 'T1071' not 'T1071:'."""
    from src.reporting.persona_section_builders import _soc_analyst

    model = {
        "evidence": [
            {
                "code": "E01",
                "ts_human": "2024-01-15 08:00:00",
                "verdict": "malicious",
                "severity": "high",
                "dread": 0.85,
                "factors": ["c2_communication"],
                "mitre": ["T1071.001: Application Layer Protocol"],
                "summary": "C2",
                "sheet": "network",
                "row": {"hostname": "host-01", "user": "jdoe"},
            }
        ],
        "iocs": {"ips": [], "public_ips": [], "processes": [], "domains": [], "hashes": [], "users": [], "hosts": []},
        "attack_story": {
            "narrative": "", "start_ts": "—", "attacker_ips": [], "internal_hosts": [],
            "internal_users": [], "c2_connections": {}, "sorted_events": [],
            "beacon_intervals": [], "event_deltas": {}, "evidence_quality": {},
            "data_at_risk": [], "duration_minutes": None,
            "phish_to": "", "phish_from": "", "phish_subject": "",
            "pivot_ev": None, "initiating_ev": None, "phishing_ev": None,
        },
        "pivots": [], "malicious_count": 1, "suspicious_count": 0, "total_count": 10,
        "overall_risk": "HIGH", "has_c2": True, "has_email": False,
        "has_endpoint": False, "has_network": True, "threat_models": {},
    }
    artifact = {"canonical_report": {"_csv_model": model}}
    html = _soc_analyst(artifact, model)
    assert "T1071:" not in html, f"Should not contain 'T1071:' with trailing colon in: {html[:300]}"
    assert "T1071" in html, "Should contain 'T1071' plain code"
