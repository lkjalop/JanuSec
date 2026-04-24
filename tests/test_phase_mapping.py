"""
Unit tests for src/core/correlation/phase_mapping.py

Checks:
  - technique_to_phase handles T-codes, sub-techniques, and unknowns
  - tag_cluster_phases returns safe empty structure on empty input
  - tag_cluster_phases detects single-phase vs multi-phase
  - phase_sequence is in canonical kill-chain order
  - MITRE mappings for the six new factor entries wire correctly
"""
import os
import sys

import pytest

# ── Bootstrap path (minimal; conftest may already do this) ──────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.correlation.phase_mapping import (  # noqa: E402
    PHASE_ORDER,
    tag_cluster_phases,
    technique_to_phase,
)


# ── technique_to_phase ───────────────────────────────────────────────────────

class TestTechniqueToPhase:
    def test_bgp_hijack(self):
        assert technique_to_phase("T1599") == "c2"

    def test_mfa_fatigue(self):
        assert technique_to_phase("T1621") == "credential_access"

    def test_sub_technique_collapses_to_parent(self):
        # T1059.001 (PowerShell) should resolve as T1059 → execution
        assert technique_to_phase("T1059.001") == "execution"

    def test_inbox_rule_creation(self):
        # T1114.003 → collection (parent T1114)
        assert technique_to_phase("T1114.003") == "collection"

    def test_c2_jitter_evasion(self):
        # T1071 = c2 application layer protocol
        assert technique_to_phase("T1071") == "c2"

    def test_unknown_returns_none(self):
        assert technique_to_phase("T9999") is None

    def test_empty_string_returns_none(self):
        assert technique_to_phase("") is None

    def test_lowercase_normalised(self):
        # Should normalise to uppercase T1599
        assert technique_to_phase("t1599") == "c2"

    def test_initial_access_phishing(self):
        assert technique_to_phase("T1566") == "initial_access"

    def test_recon_scan(self):
        assert technique_to_phase("T1595") == "recon"

    def test_lateral_movement(self):
        assert technique_to_phase("T1534") == "lateral_movement"


# ── tag_cluster_phases ───────────────────────────────────────────────────────

class TestTagClusterPhases:
    def test_empty_input_returns_safe_defaults(self):
        result = tag_cluster_phases([])
        assert result["phase_sequence"] == []
        assert result["phase_transitions"] == []
        assert result["phase_entry_ts"] == {}
        assert result["is_multi_phase"] is False
        assert result["dominant_phase"] is None
        assert result["phase_count"] == 0
        assert result["swimlane"] == {}

    def test_single_phase_is_not_multi_phase(self):
        rows = [{"mitre": ["T1566"], "row_index": 0, "timestamp_epoch": 1000}]
        result = tag_cluster_phases(rows)
        assert result["is_multi_phase"] is False
        assert result["phase_count"] == 1
        assert result["phase_sequence"] == ["initial_access"]

    def test_multi_phase_detected(self):
        rows = [
            {"mitre": ["T1566"], "row_index": 0, "timestamp_epoch": 1000},
            {"mitre": ["T1621"], "row_index": 1, "timestamp_epoch": 4600},
            {"mitre": ["T1534"], "row_index": 2, "timestamp_epoch": 7200},
        ]
        result = tag_cluster_phases(rows)
        assert result["is_multi_phase"] is True
        assert result["phase_count"] == 3

    def test_phase_sequence_in_canonical_order(self):
        # Insert out-of-order: lateral_movement then initial_access
        rows = [
            {"mitre": ["T1534"], "row_index": 0, "timestamp_epoch": 2000},
            {"mitre": ["T1566"], "row_index": 1, "timestamp_epoch": 1000},
        ]
        result = tag_cluster_phases(rows)
        seq = result["phase_sequence"]
        # initial_access should appear before lateral_movement in PHASE_ORDER
        assert seq.index("initial_access") < seq.index("lateral_movement")

    def test_all_outputs_present(self):
        rows = [{"mitre": ["T1059"], "row_index": 5}]
        result = tag_cluster_phases(rows)
        for key in ("phase_sequence", "phase_transitions", "phase_entry_ts",
                    "is_multi_phase", "dominant_phase", "phase_count", "swimlane"):
            assert key in result

    def test_swimlane_assigns_row_indices(self):
        rows = [
            {"mitre": ["T1566"], "row_index": 3, "timestamp_epoch": 1000},
            {"mitre": ["T1566"], "row_index": 7, "timestamp_epoch": 1100},
        ]
        result = tag_cluster_phases(rows)
        assert 3 in result["swimlane"]["initial_access"]
        assert 7 in result["swimlane"]["initial_access"]

    def test_dwell_time_computed(self):
        rows = [
            {"mitre": ["T1566"], "row_index": 0, "timestamp_epoch": 1000},
            {"mitre": ["T1621"], "row_index": 1, "timestamp_epoch": 5000},
        ]
        result = tag_cluster_phases(rows)
        # There should be at least one transition; dwell = 5000 - 1000 = 4000s
        transitions = result["phase_transitions"]
        assert len(transitions) >= 1
        # dwell_seconds should be non-negative
        for t in transitions:
            assert t["dwell_seconds"] >= 0

    def test_rows_without_mitre_produce_no_phase(self):
        rows = [
            {"row_index": 0, "timestamp_epoch": 1000},  # no mitre field
            {"mitre": [], "row_index": 1, "timestamp_epoch": 2000},  # empty list
        ]
        result = tag_cluster_phases(rows)
        assert result["phase_count"] == 0

    def test_sub_technique_row_resolves(self):
        rows = [{"mitre": ["T1114.003"], "row_index": 0, "timestamp_epoch": 1000}]
        result = tag_cluster_phases(rows)
        assert "collection" in result["phase_sequence"]

    def test_bec_kill_chain_coverage(self):
        # T1566 (initial_access) + T1114 (collection) + T1534 (lateral_movement)
        rows = [
            {"mitre": ["T1566"], "row_index": 0, "timestamp_epoch": 1000},
            {"mitre": ["T1114.003"], "row_index": 1, "timestamp_epoch": 2000},
            {"mitre": ["T1534"], "row_index": 2, "timestamp_epoch": 3000},
        ]
        result = tag_cluster_phases(rows)
        assert result["is_multi_phase"] is True
        assert {"initial_access", "collection", "lateral_movement"}.issubset(set(result["phase_sequence"]))


# ── factor_to_mitre new entries ──────────────────────────────────────────────

class TestNewMitreMappings:
    """Verify the 6 new factor mappings added in this session wire correctly."""

    def setup_method(self):
        from src.core.mappings.factor_to_mitre import get_all_mappings
        self.get_all_mappings = get_all_mappings

    def test_bgp_route_hijack(self):
        result = self.get_all_mappings(["network:bgp_route_hijack"])
        codes = result.get("mitre", [])
        assert "T1599" in codes

    def test_bec_kill_chain(self):
        result = self.get_all_mappings(["sequence:bec_kill_chain"])
        codes = result.get("mitre", [])
        assert "T1566" in codes
        assert "T1114.003" in codes
        assert "T1534" in codes

    def test_script_kiddie_rate(self):
        result = self.get_all_mappings(["actor:script_kiddie_rate"])
        codes = result.get("mitre", [])
        assert "T1595" in codes

    def test_c2_jitter_evasion(self):
        result = self.get_all_mappings(["network:c2_jitter_evasion"])
        codes = result.get("mitre", [])
        assert "T1071" in codes
        assert "T1571" in codes

    def test_adaptive_ewma_regular_cadence(self):
        result = self.get_all_mappings(["network:adaptive_ewma_regular_cadence"])
        codes = result.get("mitre", [])
        assert "T1071" in codes

    def test_bgp_hijack_alias(self):
        result = self.get_all_mappings(["network:bgp_hijack"])
        codes = result.get("mitre", [])
        assert "T1599" in codes


# ── PHASE_ORDER completeness ─────────────────────────────────────────────────

class TestPhaseOrder:
    def test_has_all_required_phases(self):
        required = {
            "recon", "initial_access", "execution", "persistence", "priv_esc",
            "defense_evasion", "credential_access", "discovery",
            "lateral_movement", "collection", "exfil", "c2", "impact",
        }
        assert required.issubset(set(PHASE_ORDER))

    def test_impact_is_last(self):
        assert PHASE_ORDER[-1] == "impact"

    def test_recon_is_first(self):
        assert PHASE_ORDER[0] == "recon"
