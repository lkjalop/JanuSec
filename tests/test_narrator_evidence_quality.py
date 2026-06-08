"""Tests for narrator evidence quality: source balance, diagnostics, row-citation precision.

These tests verify that:
1. The multi-source VESPER fixture has proper source diversity
2. Evidence diagnostics report quality >= 0.80 for the attack cluster
3. Evidence snippets for Kerberoasting rows contain 4769/RC4/SPN markers
4. Source-balanced preview samples from all 4 source types
5. narrate_cluster() populates _evidence_diagnostics on the cluster dict
"""
from __future__ import annotations

import json
import pathlib
import pytest

FIXTURE_PATH = (
    pathlib.Path(__file__).parent
    / "fixtures"
    / "assessments"
    / "quality"
    / "vesper_multisource.json"
)


@pytest.fixture(scope="module")
def vesper_fixture():
    if not FIXTURE_PATH.exists():
        pytest.skip(f"Multi-source VESPER fixture not found: {FIXTURE_PATH}. Run scripts/build_vesper_fixture.py")
    with open(FIXTURE_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def attack_cluster(vesper_fixture):
    clusters = vesper_fixture["clusters"]
    for c in clusters:
        if c.get("final_verdict") == "VALIDATED_BREACH":
            return c
    pytest.skip("No VALIDATED_BREACH cluster in fixture")


@pytest.fixture(scope="module")
def all_rows(vesper_fixture):
    return vesper_fixture["rows"]


# --- Fixture integrity ---

def test_fixture_has_four_source_types(vesper_fixture):
    """Fixture must contain rows from all 4 VESPER source types."""
    source_types = {r["source_type"] for r in vesper_fixture["rows"]}
    assert "windows_security" in source_types, "Missing Kerberos rows"
    assert "sysmon" in source_types, "Missing LOLBins/Sysmon rows"
    assert "network" in source_types, "Missing network rows"
    assert "cloud_identity" in source_types, "Missing cloud identity rows"


def test_fixture_row_refs_align_with_rows(vesper_fixture, attack_cluster):
    """All row_refs in attack cluster must exist in rows list."""
    row_index_set = {r["row_index"] for r in vesper_fixture["rows"]}
    missing = [ref for ref in attack_cluster["row_refs"] if ref not in row_index_set]
    assert not missing, f"Stale row_refs not in rows: {missing[:5]}"


def test_fixture_evidence_preview_has_source_diversity(attack_cluster):
    """evidence_preview must contain rows from at least 3 different source types."""
    preview = attack_cluster["evidence_preview"]
    assert preview, "evidence_preview is empty"
    source_types = {r.get("_source_type") or r.get("source_type", "") for r in preview}
    assert len(source_types) >= 3, (
        f"evidence_preview only has {len(source_types)} source types: {source_types}. "
        "Expected >= 3 for multi-source VESPER test."
    )


# --- Evidence diagnostics quality ---

def test_evidence_diagnostics_quality_above_threshold(attack_cluster):
    """_compute_evidence_diagnostics should report quality >= 0.80 for the attack cluster."""
    from src.core.ingest.cluster_narrator import _compute_evidence_diagnostics

    preview = attack_cluster["evidence_preview"]
    diag = _compute_evidence_diagnostics(preview)
    assert diag["quality"] >= 0.80, (
        f"Evidence quality {diag['quality']} < 0.80. "
        f"Diagnostics: {diag}"
    )


def test_evidence_diagnostics_has_attack_signals(attack_cluster):
    """Attack cluster must have attack_signal_rows >= 4 in diagnostics."""
    from src.core.ingest.cluster_narrator import _compute_evidence_diagnostics

    diag = _compute_evidence_diagnostics(attack_cluster["evidence_preview"])
    assert diag["attack_signal_rows"] >= 4, (
        f"Only {diag['attack_signal_rows']} attack-signal rows detected. "
        "Expected >= 4 for VESPER (Kerberoasting + WMI + Exfil cluster)."
    )


def test_evidence_diagnostics_source_diversity(attack_cluster):
    """Evidence diagnostics source_mix must cover kerberos and at least 2 other types."""
    from src.core.ingest.cluster_narrator import _compute_evidence_diagnostics

    diag = _compute_evidence_diagnostics(attack_cluster["evidence_preview"])
    mix = diag.get("source_mix", {})
    assert "kerberos" in mix, f"No Kerberos rows in source_mix: {mix}"
    assert len(mix) >= 3, f"source_mix only has {len(mix)} types: {mix}. Expected >= 3."


# --- Row-citation precision: Kerberoasting ---

def test_kerberos_attack_rows_have_rc4_evidence(all_rows):
    """Kerberoasting rows (4769 + RC4 enc) must contain required fields for citation."""
    kerb_attack = [
        r for r in all_rows
        if str(r.get("windows_event_id", "")) == "4769"
        and any(enc in str(r.get("ticket_encryption", "")).lower() for enc in ("0x17", "0x18", "rc4"))
    ]
    assert kerb_attack, "No Kerberoasting rows (4769+RC4) found in fixture"
    for row in kerb_attack[:5]:
        # Must have service_name/SPN for citation
        spn = row.get("service_name") or row.get("spn") or row.get("serviceName") or ""
        assert spn, f"Kerberoasting row missing SPN field: {list(row.keys())}"
        # Must be linkable via account_name or user
        actor = row.get("account_name") or row.get("user") or row.get("user_canonical") or ""
        assert actor, f"Kerberoasting row missing actor field: {list(row.keys())}"


def test_kerberos_snippet_contains_attack_markers(all_rows):
    """_evidence_snippet for a 4769+RC4 row must contain [KERBEROASTING] and SPN."""
    from src.core.ingest.cluster_narrator import _evidence_snippet

    kerb_attack = [
        r for r in all_rows
        if str(r.get("windows_event_id", "")) == "4769"
        and any(enc in str(r.get("ticket_encryption", "")).lower() for enc in ("0x17", "0x18", "rc4"))
    ]
    assert kerb_attack, "No Kerberoasting rows to test snippet generation"
    snippet = _evidence_snippet(kerb_attack[0])
    assert "[KERBEROASTING]" in snippet, f"Missing [KERBEROASTING] marker in snippet: {snippet}"
    # Must include MITRE T-number or encryption type
    assert any(marker in snippet for marker in ("RC4", "T1558.003", "WEAK", "enc=")), (
        f"Snippet missing RC4/technique marker: {snippet}"
    )


# --- Row-citation precision: Sysmon / WMI ---

def test_sysmon_wmi_rows_have_command_line(all_rows):
    """WMI lateral exec rows must carry command_line field for citation."""
    wmi_rows = [
        r for r in all_rows
        if r.get("source_type") == "sysmon"
        and "process call create" in str(r.get("command_line", "")).lower()
    ]
    assert wmi_rows, "No WMI lateral exec rows found in fixture"
    for row in wmi_rows:
        assert row.get("command_line"), f"WMI row missing command_line: {list(row.keys())}"


def test_sysmon_snippet_contains_wmi_marker(all_rows):
    """_evidence_snippet for a WMI row must emit [WMI LATERAL EXEC] marker."""
    from src.core.ingest.cluster_narrator import _evidence_snippet

    wmi_rows = [
        r for r in all_rows
        if r.get("source_type") == "sysmon"
        and "process call create" in str(r.get("command_line", "")).lower()
    ]
    assert wmi_rows, "No WMI rows to test snippet generation"
    snippet = _evidence_snippet(wmi_rows[0])
    assert "[WMI LATERAL EXEC]" in snippet, f"Missing [WMI LATERAL EXEC] in snippet: {snippet}"


# --- Row-citation precision: Network exfil ---

def test_network_large_exfil_rows_score_high(all_rows):
    """Network rows with >10MB exfil must have triage_score >= 0.70."""
    large_exfil = [
        r for r in all_rows
        if r.get("source_type") == "network"
        and int(r.get("bytes_sent", 0) or 0) > 10_000_000
    ]
    assert large_exfil, "No large exfil network rows (>10MB) found in fixture"
    for row in large_exfil:
        assert row["triage_score"] >= 0.70, (
            f"Large exfil row ({row.get('bytes_sent')} bytes) has low score {row['triage_score']}"
        )


def test_network_snippet_contains_exfil_marker(all_rows):
    """_evidence_snippet for large exfil network row must contain [LARGE EXFIL]."""
    from src.core.ingest.cluster_narrator import _evidence_snippet

    large_exfil = [
        r for r in all_rows
        if r.get("source_type") == "network"
        and int(r.get("bytes_sent", 0) or 0) > 10_000_000
    ]
    assert large_exfil, "No large exfil rows to test"
    snippet = _evidence_snippet(large_exfil[0])
    assert "[LARGE EXFIL]" in snippet, f"Missing [LARGE EXFIL] in snippet: {snippet}"


# --- Row-citation precision: Cloud identity ---

def test_cloud_consent_rows_have_event_name(all_rows):
    """Cloud consent-to-application rows must have activityDisplayName or event_name."""
    consent_rows = [
        r for r in all_rows
        if r.get("source_type") == "cloud_identity"
        and "consent" in str(r.get("activityDisplayName", "") or r.get("event_name", "")).lower()
    ]
    assert consent_rows, "No cloud consent rows found in fixture"
    for row in consent_rows:
        label = row.get("activityDisplayName") or row.get("event_name") or ""
        assert label, f"Cloud consent row missing event label: {list(row.keys())}"


def test_cloud_snippet_contains_oauth_marker(all_rows):
    """_evidence_snippet for cloud consent row must emit [OAUTH CONSENT] marker."""
    from src.core.ingest.cluster_narrator import _evidence_snippet

    consent_rows = [
        r for r in all_rows
        if r.get("source_type") == "cloud_identity"
        and "consent" in str(r.get("activityDisplayName", "") or r.get("event_name", "")).lower()
    ]
    assert consent_rows, "No cloud consent rows to test snippet generation"
    snippet = _evidence_snippet(consent_rows[0])
    assert "[OAUTH CONSENT]" in snippet, f"Missing [OAUTH CONSENT] in snippet: {snippet}"


# --- narrate_cluster() integration (no LLM call) ---

def _make_fake_narrative(**overrides) -> dict:
    """Return a fake LLM generate() response dict with 'text' key."""
    base = {
        "verdict": "VALIDATED_BREACH",
        "confidence": 0.95,
        "breach_title": "Test Kerberoasting Breach",
        "breach_subtitle": "Credential theft via Kerberoasting",
        "breach_timeline": "T+0h attacker requested RC4 TGS tickets for multiple SPNs",
        "threat_actor_profile": "APT group targeting AD credentials",
        "blast_radius": "Multiple service accounts compromised",
        "narrative_sections": [],
        "mitre_techniques": ["T1558.003"],
        "recommended_actions": [{"priority": "P1", "tool": "BloodHound", "action": "Audit SPNs"}],
    }
    base.update(overrides)
    return {"text": json.dumps(base), "model": "test-mock", "total_duration": 0}


def test_narrate_cluster_populates_evidence_diagnostics(attack_cluster, all_rows):
    """narrate_cluster() must store _evidence_diagnostics on cluster before LLM call."""
    import unittest.mock as mock
    from src.core.ingest.cluster_narrator import narrate_cluster

    cluster_copy = dict(attack_cluster)
    mock_client = mock.MagicMock()
    mock_client.generate.return_value = _make_fake_narrative()
    with mock.patch("src.integrations.llm_client.DEFAULT_CLIENT", mock_client):
        narrative = narrate_cluster(cluster_copy, all_rows, assessment_id="test-fixture")

    # _evidence_diagnostics is stored on the cluster dict (mutated in place), not in narrative
    assert "_evidence_diagnostics" in cluster_copy, (
        "narrate_cluster() must set cluster['_evidence_diagnostics'] (on cluster dict)"
    )
    diag = cluster_copy["_evidence_diagnostics"]
    assert diag["quality"] >= 0.70, f"Evidence quality too low: {diag}"
    assert "_narrator_tier" in cluster_copy, "narrate_cluster() must set cluster['_narrator_tier']"


def test_narrate_cluster_stores_narrator_model(attack_cluster, all_rows):
    """narrate_cluster() must record _narrator_model in the narrative dict (return value)."""
    import unittest.mock as mock
    from src.core.ingest.cluster_narrator import narrate_cluster

    cluster_copy = dict(attack_cluster)
    mock_client = mock.MagicMock()
    mock_client.generate.return_value = _make_fake_narrative()
    with mock.patch("src.integrations.llm_client.DEFAULT_CLIENT", mock_client):
        narrative = narrate_cluster(cluster_copy, all_rows, assessment_id="test-fixture")

    # narrate_cluster returns the narrative dict directly
    assert "_narrator_model" in narrative, (
        f"narrative dict must contain '_narrator_model' field for provenance. Keys: {list(narrative.keys())}"
    )
