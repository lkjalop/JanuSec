"""Unit tests for src/analysis/expand_checks.py (OPT-1 + OPT-2)."""
from __future__ import annotations

import pytest
from src.analysis.expand_checks import (
    CheckResult,
    extract_entity_fields,
    impossible_travel_check,
    after_hours_check,
    same_ip_cross_account_check,
    temp_privilege_check,
    run_all_checks,
)


# ── CheckResult ───────────────────────────────────────────────────────────────

class TestCheckResult:
    def test_to_dict_keys(self):
        cr = CheckResult("test_id", "Test Label", True, "warning", "some detail", [1, 2])
        d = cr.to_dict()
        assert set(d.keys()) == {"check_id", "label", "triggered", "severity", "detail", "evidence_rows"}

    def test_defaults(self):
        cr = CheckResult("x", "X", False)
        assert cr.severity == "info"
        assert cr.detail == ""
        assert cr.evidence_rows == []

    def test_triggered_true(self):
        cr = CheckResult("x", "X", True, severity="critical")
        assert cr.triggered is True
        assert cr.to_dict()["triggered"] is True


# ── OPT-1: extract_entity_fields ─────────────────────────────────────────────

class TestExtractEntityFields:
    def test_empty_rows(self):
        result = extract_entity_fields([])
        assert result == {"users": [], "ips": [], "hosts": [], "domains": [], "sessions": [], "tokens": [], "policies": []}

    def test_basic_extraction(self):
        rows = [
            {"user": "alice", "src_ip": "10.0.0.1", "host": "WS-01"},
            {"username": "bob", "ip": "10.0.0.2", "hostname": "SRV-02"},
        ]
        result = extract_entity_fields(rows)
        assert "alice" in result["users"]
        assert "bob" in result["users"]
        assert "10.0.0.1" in result["ips"]
        assert "10.0.0.2" in result["ips"]
        assert "WS-01" in result["hosts"]
        assert "SRV-02" in result["hosts"]

    def test_deduplication(self):
        rows = [
            {"user": "alice"},
            {"user": "alice"},
            {"username": "alice"},
        ]
        result = extract_entity_fields(rows)
        assert result["users"].count("alice") == 1

    def test_sessions_and_tokens(self):
        rows = [{"session_id": "sess-abc", "token_id": "tok-xyz"}]
        result = extract_entity_fields(rows)
        assert "sess-abc" in result["sessions"]
        assert "tok-xyz" in result["tokens"]

    def test_policies(self):
        rows = [{"role": "admin", "iam_role": "arn:aws:iam::123:role/admin"}]
        result = extract_entity_fields(rows)
        assert "admin" in result["policies"]

    def test_empty_string_values_excluded(self):
        rows = [{"user": "", "src_ip": "  "}]
        result = extract_entity_fields(rows)
        assert result["users"] == []
        assert result["ips"] == []

    def test_non_string_values_skipped(self):
        rows = [{"user": 42, "src_ip": None}]
        result = extract_entity_fields(rows)
        assert result["users"] == []
        assert result["ips"] == []


# ── OPT-2: impossible_travel_check ──────────────────────────────────────────

class TestImpossibleTravelCheck:
    def _make_row(self, user, ts, lat, lon, idx=None):
        row = {"user": user, "timestamp": ts, "lat": lat, "lon": lon}
        if idx is not None:
            row["row_index"] = idx
        return row

    def test_no_rows(self):
        cr = impossible_travel_check([])
        assert cr.triggered is False
        assert cr.severity == "info"

    def test_single_event_no_trigger(self):
        rows = [self._make_row("alice", "2026-04-17T08:00:00Z", 40.7, -74.0, 0)]
        cr = impossible_travel_check(rows)
        assert cr.triggered is False

    def test_triggered_transatlantic_fast(self):
        # New York (40.7, -74.0) → London (51.5, -0.1) ~5500 km in 10 minutes
        rows = [
            self._make_row("alice", "2026-04-17T08:00:00Z", 40.7, -74.0, 0),
            self._make_row("alice", "2026-04-17T08:10:00Z", 51.5, -0.1, 1),
        ]
        cr = impossible_travel_check(rows)
        assert cr.triggered is True
        assert cr.severity == "critical"
        assert "alice" in cr.detail

    def test_not_triggered_slow_travel(self):
        # Same New York → London but over 10 hours — plausible flight
        rows = [
            self._make_row("alice", "2026-04-17T08:00:00Z", 40.7, -74.0, 0),
            self._make_row("alice", "2026-04-17T18:00:00Z", 51.5, -0.1, 1),
        ]
        cr = impossible_travel_check(rows)
        assert cr.triggered is False

    def test_not_triggered_short_distance(self):
        # Adjacent cities — distance < 200 km threshold
        rows = [
            self._make_row("alice", "2026-04-17T08:00:00Z", 40.7, -74.0, 0),
            self._make_row("alice", "2026-04-17T08:01:00Z", 40.8, -73.9, 1),
        ]
        cr = impossible_travel_check(rows)
        assert cr.triggered is False

    def test_evidence_rows_populated(self):
        rows = [
            self._make_row("bob", "2026-04-17T08:00:00Z", 40.7, -74.0, 5),
            self._make_row("bob", "2026-04-17T08:05:00Z", 51.5, -0.1, 8),
        ]
        cr = impossible_travel_check(rows)
        assert cr.triggered is True
        assert 5 in cr.evidence_rows
        assert 8 in cr.evidence_rows

    def test_different_users_no_cross_contamination(self):
        # Each user only travels locally — no trigger expected
        rows = [
            self._make_row("alice", "2026-04-17T08:00:00Z", 40.7, -74.0, 0),
            self._make_row("bob", "2026-04-17T08:05:00Z", 51.5, -0.1, 1),
            self._make_row("alice", "2026-04-17T08:10:00Z", 40.8, -73.9, 2),
            self._make_row("bob", "2026-04-17T08:15:00Z", 51.6, -0.2, 3),
        ]
        cr = impossible_travel_check(rows)
        assert cr.triggered is False


# ── OPT-2: after_hours_check ─────────────────────────────────────────────────

class TestAfterHoursCheck:
    def test_no_rows(self):
        cr = after_hours_check([])
        assert cr.triggered is False

    def test_business_hours_not_triggered(self):
        # 10 AM UTC on a Wednesday
        rows = [{"user": "alice", "timestamp": "2026-04-15T10:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is False

    def test_late_night_triggered(self):
        # 11 PM UTC
        rows = [{"user": "alice", "timestamp": "2026-04-15T23:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is True
        assert cr.severity == "warning"

    def test_early_morning_triggered(self):
        # 3 AM UTC
        rows = [{"user": "alice", "timestamp": "2026-04-15T03:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is True

    def test_weekend_triggered(self):
        # Saturday 2026-04-18
        rows = [{"user": "alice", "timestamp": "2026-04-18T14:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is True

    def test_sunday_triggered(self):
        # Sunday 2026-04-19
        rows = [{"user": "alice", "timestamp": "2026-04-19T10:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is True

    def test_boundary_22h_is_after_hours(self):
        rows = [{"user": "alice", "timestamp": "2026-04-15T22:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is True

    def test_boundary_6h_is_business_hours(self):
        # 06:00 UTC is NOT after-hours (condition is hour < 6)
        rows = [{"user": "alice", "timestamp": "2026-04-15T06:00:00Z", "event_type": "login", "row_index": 0}]
        cr = after_hours_check(rows)
        assert cr.triggered is False

    def test_multiple_events_detail(self):
        rows = [
            {"user": "alice", "timestamp": "2026-04-15T23:00:00Z", "event_type": "login", "row_index": 0},
            {"user": "bob", "timestamp": "2026-04-15T02:00:00Z", "event_type": "exec", "row_index": 1},
        ]
        cr = after_hours_check(rows)
        assert cr.triggered is True
        assert "2" in cr.detail or len(cr.evidence_rows) == 2

    def test_no_timestamp_skipped(self):
        rows = [{"user": "alice", "event_type": "login"}]
        cr = after_hours_check(rows)
        assert cr.triggered is False


# ── OPT-2: same_ip_cross_account_check ──────────────────────────────────────

class TestSameIpCrossAccountCheck:
    def test_no_rows(self):
        cr = same_ip_cross_account_check([])
        assert cr.triggered is False

    def test_single_user_single_ip(self):
        rows = [
            {"user": "alice", "src_ip": "10.0.0.1", "row_index": 0},
            {"user": "alice", "src_ip": "10.0.0.1", "row_index": 1},
        ]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is False

    def test_two_users_same_ip_triggered(self):
        rows = [
            {"user": "alice", "src_ip": "10.0.0.1", "row_index": 0},
            {"user": "bob", "src_ip": "10.0.0.1", "row_index": 1},
        ]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is True
        assert cr.severity == "critical"
        assert "10.0.0.1" in cr.detail

    def test_three_users_same_ip(self):
        rows = [
            {"user": "alice", "src_ip": "192.168.1.1", "row_index": 0},
            {"user": "bob", "src_ip": "192.168.1.1", "row_index": 1},
            {"user": "charlie", "src_ip": "192.168.1.1", "row_index": 2},
        ]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is True
        assert "3" in cr.detail

    def test_different_ips_no_trigger(self):
        rows = [
            {"user": "alice", "src_ip": "10.0.0.1", "row_index": 0},
            {"user": "bob", "src_ip": "10.0.0.2", "row_index": 1},
        ]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is False

    def test_evidence_rows_collected(self):
        rows = [
            {"user": "alice", "src_ip": "10.0.0.1", "row_index": 3},
            {"user": "bob", "src_ip": "10.0.0.1", "row_index": 7},
        ]
        cr = same_ip_cross_account_check(rows)
        assert 3 in cr.evidence_rows
        assert 7 in cr.evidence_rows

    def test_no_ip_field_skipped(self):
        rows = [{"user": "alice"}, {"user": "bob"}]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is False

    def test_ip_key_variants(self):
        rows = [
            {"user": "alice", "source_ip": "172.16.0.1", "row_index": 0},
            {"user": "bob", "client_ip": "172.16.0.1", "row_index": 1},
        ]
        cr = same_ip_cross_account_check(rows)
        assert cr.triggered is True


# ── OPT-2: temp_privilege_check ──────────────────────────────────────────────

class TestTempPrivilegeCheck:
    def test_no_rows(self):
        cr = temp_privilege_check([])
        assert cr.triggered is False

    def test_admin_role_triggered(self):
        rows = [{"user": "alice", "role": "global.admin", "event_type": "role_assignment", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True
        assert cr.severity == "critical"

    def test_sudo_command_triggered(self):
        rows = [{"user": "bob", "command_line": "sudo su -", "event_type": "process", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_assume_role_triggered(self):
        rows = [{"user": "charlie", "event_type": "sts:assumeRole", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_breakglass_triggered(self):
        rows = [{"user": "svc-bot", "role": "breakglass", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_escalation_keyword_triggered(self):
        rows = [{"user": "alice", "event_type": "privilege_escalation", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_normal_event_not_triggered(self):
        rows = [{"user": "alice", "event_type": "file_read", "command_line": "cat /etc/hosts", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is False

    def test_mitre_technique_field_checked(self):
        rows = [{"user": "alice", "mitre_technique": "T1078 - Domain Admin", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_multiple_events_counted(self):
        rows = [
            {"user": "alice", "role": "admin", "row_index": 0},
            {"user": "bob", "role": "admin", "row_index": 1},
            {"user": "charlie", "event_type": "file_read", "row_index": 2},
        ]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True
        assert len(cr.evidence_rows) == 2
        assert "2" in cr.detail

    def test_case_insensitive_match(self):
        rows = [{"user": "alice", "role": "SYSADMIN", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True

    def test_iam_passrole_triggered(self):
        rows = [{"user": "svc", "event_type": "iam.passrole", "row_index": 0}]
        cr = temp_privilege_check(rows)
        assert cr.triggered is True


# ── run_all_checks ───────────────────────────────────────────────────────────

class TestRunAllChecks:
    def test_returns_eight_results(self):
        results = run_all_checks([])
        assert len(results) == 8

    def test_result_ids(self):
        results = run_all_checks([])
        ids = {r.check_id for r in results}
        # 4 original + 4 Phase A checks
        assert {"impossible_travel", "after_hours", "same_ip_cross_account", "temp_privilege"}.issubset(ids)
        assert {"brute_force_rate", "beacon_ewma", "dns_entropy", "bgp_hijack"}.issubset(ids)

    def test_all_results_are_check_result(self):
        results = run_all_checks([])
        for r in results:
            assert isinstance(r, CheckResult)

    def test_mixed_dataset_fires_subset(self):
        """A dataset with after-hours + cross-account should trigger those two only."""
        rows = [
            # after-hours (Saturday)
            {"user": "alice", "src_ip": "10.0.0.1", "timestamp": "2026-04-18T14:00:00Z", "row_index": 0},
            # cross-account same IP
            {"user": "bob", "src_ip": "10.0.0.1", "timestamp": "2026-04-18T14:01:00Z", "row_index": 1},
        ]
        results = run_all_checks(rows)
        result_map = {r.check_id: r for r in results}

        assert result_map["after_hours"].triggered is True
        assert result_map["same_ip_cross_account"].triggered is True
        assert result_map["impossible_travel"].triggered is False
        assert result_map["temp_privilege"].triggered is False
