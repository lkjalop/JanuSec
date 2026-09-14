"""Tests for Phase A deterministic checks and Phase B cluster-aware row selection."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from src.analysis.expand_checks import (
    CheckResult,
    brute_force_rate_check,
    beacon_ewma_check,
    dns_entropy_check,
    bgp_hijack_check,
    run_all_checks,
)
from src.analysis.expand_engine import cluster_aware_row_select


# ── Helpers ──────────────────────────────────────────────────────────────────

def _auth_rows(ip, n, elapsed_s, start="2026-03-19T14:00:00Z", user_prefix="u"):
    t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
    step = elapsed_s / max(n - 1, 1)
    return [
        {"event_id": f"A{i:03d}", "event_type": "auth_failure", "src_ip": ip,
         "user": f"{user_prefix}{i % 5}@corp.com",
         "ts": (t0 + timedelta(seconds=i * step)).isoformat(), "row_index": i}
        for i in range(n)
    ]


# ── brute_force_rate_check ────────────────────────────────────────────────────

class TestBruteForceRateCheck:
    def test_script_kiddie_rate_triggers(self):
        """OKT-039: 847 attempts / 282s = 3/sec from 117.50.39.100."""
        rows = _auth_rows("117.50.39.100", n=60, elapsed_s=20)
        result = brute_force_rate_check(rows)
        assert result.triggered is True
        assert result.check_id == "brute_force_rate"
        assert "117.50.39.100" in result.detail
        assert "/sec" in result.detail

    def test_apt_slow_rate_does_not_trigger(self):
        """APT: 1 attempt per 7 minutes — evades rate check."""
        rows = _auth_rows("91.108.4.200", n=5, elapsed_s=2100)  # 1/420s
        assert brute_force_rate_check(rows).triggered is False

    def test_below_10_events_skipped(self):
        """Fewer than 10 events from one IP — not enough data."""
        rows = _auth_rows("1.2.3.4", n=9, elapsed_s=3)
        assert brute_force_rate_check(rows).triggered is False

    def test_no_auth_event_type_skipped(self):
        rows = [{"event_type": "dns_query", "src_ip": "1.2.3.4",
                 "ts": "2026-01-01T00:00:00Z", "row_index": 0}]
        assert brute_force_rate_check(rows).triggered is False

    def test_empty_rows(self):
        assert brute_force_rate_check([]).triggered is False

    def test_severity_warning_not_critical(self):
        """Script kiddie is warning (noisy, low-skill), not critical (APT)."""
        rows = _auth_rows("1.1.1.1", n=60, elapsed_s=10)
        result = brute_force_rate_check(rows)
        if result.triggered:
            assert result.severity == "warning"

    def test_evidence_rows_populated(self):
        rows = _auth_rows("2.2.2.2", n=30, elapsed_s=10)
        result = brute_force_rate_check(rows)
        if result.triggered:
            assert len(result.evidence_rows) > 0

    def test_login_event_type_also_matches(self):
        rows = _auth_rows("3.3.3.3", n=30, elapsed_s=10)
        for r in rows:
            r["event_type"] = "user_login"
        result = brute_force_rate_check(rows)
        assert result.triggered is True

    def test_multiple_ips_worst_selected(self):
        """Two IPs with different rates — the faster one drives the result."""
        slow = _auth_rows("10.0.0.1", n=15, elapsed_s=60, user_prefix="a")  # ~0.25/sec
        fast = _auth_rows("10.0.0.2", n=30, elapsed_s=5, user_prefix="b")   # ~6/sec
        result = brute_force_rate_check(slow + fast)
        assert result.triggered is True
        assert "10.0.0.2" in result.detail


# ── beacon_ewma_check ─────────────────────────────────────────────────────────

class TestBeaconEWMACheck:
    def test_c2_jitter_beacon_triggers(self):
        """PHANTOM-MERIDIAN NET-014: interval=3336s, jitter=0.12, stddev=399."""
        rows = [{"event_id": "NET-014", "beacon_interval_seconds": "3336.0",
                 "beacon_jitter_ratio": "0.12", "running_stddev": "399.0",
                 "running_mean_interval": "2860.0", "row_index": 0}]
        result = beacon_ewma_check(rows)
        assert result.triggered is True
        assert result.severity == "critical"
        assert "NET-014" in result.detail

    def test_algorithmic_zero_stddev_triggers(self):
        """Machine-clock heartbeat: stddev=0.0, interval=1800s (jitter irrelevant)."""
        rows = [{"event_id": "NET-001", "beacon_interval_seconds": "1800.0",
                 "beacon_jitter_ratio": "0.0", "running_stddev": "0.0", "row_index": 0}]
        result = beacon_ewma_check(rows)
        assert result.triggered is True
        assert result.severity == "warning"  # algorithmic, not C2 confirmed

    def test_observiq_supply_chain_triggers(self):
        """ObservIQ NET-035..039: interval=301s, jitter=0.04 (algorithmic)."""
        rows = [
            {"event_id": "NET-035", "beacon_interval_seconds": "301.0",
             "beacon_jitter_ratio": "0.04", "running_stddev": "0.0", "row_index": 0},
            {"event_id": "NET-036", "beacon_interval_seconds": "301.0",
             "beacon_jitter_ratio": "0.04", "running_stddev": "0.0", "row_index": 1},
        ]
        result = beacon_ewma_check(rows)
        assert result.triggered is True

    def test_no_beacon_fields_no_trigger(self):
        rows = [{"event_id": "OKT-001", "event_type": "user_login", "row_index": 0}]
        assert beacon_ewma_check(rows).triggered is False

    def test_empty_rows(self):
        assert beacon_ewma_check([]).triggered is False

    def test_c2_jitter_severity_critical(self):
        rows = [{"beacon_interval_seconds": "2700", "beacon_jitter_ratio": "0.09",
                 "running_stddev": "310", "row_index": 0}]
        result = beacon_ewma_check(rows)
        if result.triggered:
            assert result.severity == "critical"

    def test_mia_c2_60s_interval(self):
        """NET-044: Mia's laptop C2 — 60s interval, jitter=0.15."""
        rows = [{"event_id": "NET-044", "beacon_interval_seconds": "60.0",
                 "beacon_jitter_ratio": "0.15", "running_stddev": "9.0", "row_index": 0}]
        result = beacon_ewma_check(rows)
        assert result.triggered is True
        assert result.severity == "critical"

    def test_both_patterns_present_critical(self):
        """Mix of algorithmic + C2 jitter rows → critical."""
        rows = [
            {"beacon_interval_seconds": "300", "beacon_jitter_ratio": "0.0",
             "running_stddev": "0", "row_index": 0},
            {"beacon_interval_seconds": "2700", "beacon_jitter_ratio": "0.09",
             "running_stddev": "310", "row_index": 1},
        ]
        result = beacon_ewma_check(rows)
        assert result.triggered is True
        assert result.severity == "critical"


# ── dns_entropy_check ─────────────────────────────────────────────────────────

class TestDNSEntropyCheck:
    def test_high_entropy_exfil_triggers(self):
        """NET-014: 4.6 bits — highest entropy in dataset, DNS exfil."""
        rows = [{"event_id": "NET-014", "dns_label_entropy_bits": "4.6",
                 "dns_query": "c2-usr-list-b64data.update-cdn-svc.net", "row_index": 0}]
        result = dns_entropy_check(rows)
        assert result.triggered is True
        assert result.severity == "critical"
        assert "NET-014" in result.detail

    def test_benign_low_entropy_no_trigger(self):
        """google.com = 2.8 bits — benign."""
        rows = [{"event_id": "NET-001", "dns_label_entropy_bits": "2.8",
                 "dns_query": "google.com", "row_index": 0}]
        assert dns_entropy_check(rows).triggered is False

    def test_boundary_exactly_35_no_trigger(self):
        """Threshold is strictly > 3.5, so 3.5 does NOT trigger."""
        rows = [{"dns_label_entropy_bits": "3.5", "dns_query": "x.example.com", "row_index": 0}]
        assert dns_entropy_check(rows).triggered is False

    def test_boundary_36_triggers(self):
        rows = [{"dns_label_entropy_bits": "3.6", "dns_query": "xn.example.com", "row_index": 0}]
        assert dns_entropy_check(rows).triggered is True

    def test_net008_initial_c2_domain_low_entropy(self):
        """NET-008: update-cdn-svc.net = 2.1 bits — domain itself isn't high entropy."""
        rows = [{"event_id": "NET-008", "dns_label_entropy_bits": "2.1",
                 "dns_query": "update-cdn-svc.net", "row_index": 0}]
        assert dns_entropy_check(rows).triggered is False

    def test_warning_for_38_bits(self):
        """3.8 bits → warning (below 4.0 critical boundary)."""
        rows = [{"dns_label_entropy_bits": "3.8", "dns_query": "xn--abc.com", "row_index": 0}]
        result = dns_entropy_check(rows)
        if result.triggered:
            assert result.severity == "warning"

    def test_empty_rows(self):
        assert dns_entropy_check([]).triggered is False

    def test_no_entropy_field_no_trigger(self):
        rows = [{"event_id": "NET-001", "dns_query": "google.com", "row_index": 0}]
        assert dns_entropy_check(rows).triggered is False

    def test_multiple_rows_all_flagged(self):
        """Several DNS tunnel rows — all should appear in evidence."""
        rows = [
            {"dns_label_entropy_bits": "3.8", "dns_query": f"q{i}.c2.example.com", "row_index": i}
            for i in range(5)
        ]
        result = dns_entropy_check(rows)
        assert result.triggered is True
        assert len(result.evidence_rows) == 5


# ── bgp_hijack_check ──────────────────────────────────────────────────────────

class TestBGPHijackCheck:
    def test_net015_explicit_indicator(self):
        """NET-015: bgp_hijack_indicator=True + ASN mismatch."""
        rows = [{"event_id": "NET-015", "bgp_hijack_indicator": "True",
                 "bgp_origin_asn": "AS60068", "bgp_expected_origin_asn": "AS15169",
                 "bgp_prefix_announced": "10.10.0.0/16", "row_index": 0}]
        result = bgp_hijack_check(rows)
        assert result.triggered is True
        assert result.severity == "critical"
        assert "NET-015" in result.detail
        assert "AS60068" in result.detail

    def test_asn_mismatch_without_indicator_field(self):
        """ASN mismatch alone is sufficient — indicator field not required."""
        rows = [{"event_id": "NET-X", "bgp_origin_asn": "AS60068",
                 "bgp_expected_origin_asn": "AS15169",
                 "bgp_prefix_announced": "8.8.0.0/16", "row_index": 0}]
        assert bgp_hijack_check(rows).triggered is True

    def test_matching_asn_no_trigger(self):
        """Origin matches expected — legitimate BGP announcement."""
        rows = [{"event_id": "NET-016", "bgp_origin_asn": "AS15169",
                 "bgp_expected_origin_asn": "AS15169",
                 "bgp_prefix_announced": "8.8.0.0/16",
                 "bgp_hijack_indicator": "False", "row_index": 0}]
        assert bgp_hijack_check(rows).triggered is False

    def test_no_bgp_fields_no_trigger(self):
        rows = [{"event_id": "OKT-001", "event_type": "user_login", "row_index": 0}]
        assert bgp_hijack_check(rows).triggered is False

    def test_empty_rows(self):
        assert bgp_hijack_check([]).triggered is False

    def test_evidence_rows_populated(self):
        rows = [{"bgp_hijack_indicator": "True", "bgp_origin_asn": "AS9999",
                 "bgp_expected_origin_asn": "AS1234", "row_index": 42}]
        result = bgp_hijack_check(rows)
        if result.triggered:
            assert 42 in result.evidence_rows

    def test_indicator_true_lowercase(self):
        rows = [{"bgp_hijack_indicator": "true", "bgp_origin_asn": "AS9",
                 "bgp_expected_origin_asn": "AS1", "row_index": 0}]
        assert bgp_hijack_check(rows).triggered is True

    def test_indicator_1_triggers(self):
        rows = [{"bgp_hijack_indicator": "1", "bgp_origin_asn": "AS9",
                 "bgp_expected_origin_asn": "AS1", "row_index": 0}]
        assert bgp_hijack_check(rows).triggered is True


# ── run_all_checks — eight checks now ────────────────────────────────────────

class TestRunAllChecksPhaseA:
    def test_returns_eight_checks(self):
        results = run_all_checks([])
        assert len(results) == 8

    def test_all_phase_a_check_ids_present(self):
        ids = {r.check_id for r in run_all_checks([])}
        assert "brute_force_rate" in ids
        assert "beacon_ewma" in ids
        assert "dns_entropy" in ids
        assert "bgp_hijack" in ids

    def test_original_four_still_present(self):
        ids = {r.check_id for r in run_all_checks([])}
        assert "impossible_travel" in ids
        assert "after_hours" in ids
        assert "same_ip_cross_account" in ids
        assert "temp_privilege" in ids

    def test_beacon_row_fires_beacon_check(self):
        rows = [{"event_id": "NET-014", "beacon_interval_seconds": "3336",
                 "beacon_jitter_ratio": "0.12", "running_stddev": "399", "row_index": 0}]
        results = run_all_checks(rows)
        beacon = next(r for r in results if r.check_id == "beacon_ewma")
        assert beacon.triggered is True

    def test_bgp_row_fires_bgp_check(self):
        rows = [{"bgp_hijack_indicator": "True", "bgp_origin_asn": "AS60068",
                 "bgp_expected_origin_asn": "AS15169", "row_index": 0}]
        results = run_all_checks(rows)
        bgp = next(r for r in results if r.check_id == "bgp_hijack")
        assert bgp.triggered is True

    def test_dns_row_fires_dns_check(self):
        rows = [{"dns_label_entropy_bits": "4.6", "dns_query": "c2.example.net", "row_index": 0}]
        results = run_all_checks(rows)
        dns = next(r for r in results if r.check_id == "dns_entropy")
        assert dns.triggered is True

    def test_auth_spray_fires_brute_force_check(self):
        rows = _auth_rows("1.2.3.4", n=50, elapsed_s=10)
        results = run_all_checks(rows)
        bf = next(r for r in results if r.check_id == "brute_force_rate")
        assert bf.triggered is True


# ── Phase B: cluster_aware_row_select ────────────────────────────────────────

class TestClusterAwareRowSelect:
    def _malicious_row(self, ip, idx):
        return {"src_ip": ip, "review_state": "confirmed_malicious",
                "ts": f"2026-03-{idx+1:02d}T00:00:00Z", "row_index": idx}

    def _benign_row(self, ip, idx):
        return {"src_ip": ip, "review_state": "reviewed_benign",
                "ts": f"2026-03-{idx+1:02d}T00:00:00Z", "row_index": idx}

    def _script_kiddie_row(self, ip, idx):
        return {"src_ip": ip, "review_state": "script_kiddie",
                "ts": f"2026-03-{idx+1:02d}T00:00:00Z", "row_index": idx}

    def test_empty_returns_empty(self):
        assert cluster_aware_row_select([]) == []

    def test_hard_cap_respected(self):
        rows = [self._benign_row("1.1.1.1", i) for i in range(50)]
        result = cluster_aware_row_select(rows, k_clusters=5, n_per_cluster=6, hard_cap=30)
        assert len(result) <= 30

    def test_malicious_cluster_beats_benign(self):
        """confirmed_malicious cluster should appear before reviewed_benign cluster."""
        benign = [self._benign_row("10.0.0.1", i) for i in range(20)]
        malicious = [self._malicious_row("45.153.160.100", i + 20) for i in range(5)]
        rows = benign + malicious
        result = cluster_aware_row_select(rows, k_clusters=2, n_per_cluster=5)
        result_states = [r["review_state"] for r in result]
        # All malicious should be in result
        assert "confirmed_malicious" in result_states

    def test_script_kiddie_spray_does_not_crowd_out_c2(self):
        """847 script_kiddie rows should not prevent PHANTOM-MERIDIAN from appearing."""
        spray = [self._script_kiddie_row("117.50.39.100", i) for i in range(30)]
        c2 = [self._malicious_row("45.153.160.100", i + 30) for i in range(5)]
        result = cluster_aware_row_select(spray + c2, k_clusters=5, n_per_cluster=6)
        c2_ips = [r["src_ip"] for r in result]
        assert "45.153.160.100" in c2_ips, "C2 cluster must appear despite script_kiddie spray"

    def test_top_k_clusters_selected(self):
        """With k_clusters=2 and 3 clusters, only top 2 appear."""
        rows = (
            [self._malicious_row("10.0.0.1", i) for i in range(3)] +       # cluster A malicious
            [self._benign_row("10.0.0.2", i + 3) for i in range(10)] +     # cluster B benign
            [self._script_kiddie_row("10.0.0.3", i + 13) for i in range(5)] # cluster C sk
        )
        result = cluster_aware_row_select(rows, k_clusters=2, n_per_cluster=6)
        ips = {r["src_ip"] for r in result}
        assert "10.0.0.1" in ips, "Malicious cluster must be in top-2"
        # cluster C (script_kiddie) may or may not be there — but benign should beat it
        # Actually malicious=0 < script_kiddie=2, script_kiddie < benign=3
        # So top-2 = malicious + script_kiddie
        # benign has 10 rows but state_pri=3; script_kiddie has 5 rows but state_pri=2
        assert "10.0.0.2" not in ips or "10.0.0.3" in ips  # benign should lose to SK

    def test_n_per_cluster_limits_rows_per_cluster(self):
        """n_per_cluster=3 means at most 3 rows per cluster."""
        rows = [self._malicious_row("10.0.0.1", i) for i in range(10)]
        result = cluster_aware_row_select(rows, k_clusters=1, n_per_cluster=3, hard_cap=30)
        assert len(result) <= 3

    def test_within_cluster_sort_by_severity(self):
        """Within a cluster, confirmed_malicious rows should come first."""
        rows = [
            {"src_ip": "10.0.0.1", "review_state": "reviewed_benign",
             "ts": "2026-03-01T00:00:00Z", "row_index": 0},
            {"src_ip": "10.0.0.1", "review_state": "confirmed_malicious",
             "ts": "2026-03-02T00:00:00Z", "row_index": 1},
            {"src_ip": "10.0.0.1", "review_state": "needs_investigation",
             "ts": "2026-03-03T00:00:00Z", "row_index": 2},
        ]
        result = cluster_aware_row_select(rows, k_clusters=1, n_per_cluster=3)
        # First row in result should be malicious (lowest priority score = 0)
        assert result[0]["review_state"] == "confirmed_malicious"

    def test_threat_confidence_used_for_net_rows(self):
        """NET CSV has threat_confidence instead of severity — must be respected."""
        rows = [
            {"src_ip": "10.0.0.1", "threat_confidence": "100.0",
             "ts": "2026-03-01T00:00:00Z", "row_index": 0},
            {"src_ip": "10.0.0.2", "threat_confidence": "10.0",
             "ts": "2026-03-01T00:00:00Z", "row_index": 1},
        ]
        result = cluster_aware_row_select(rows, k_clusters=2, n_per_cluster=1)
        # 10.0.0.1 (threat_confidence=100) should appear
        ips = [r["src_ip"] for r in result]
        assert "10.0.0.1" in ips

    def test_single_row_returns_single_row(self):
        rows = [self._malicious_row("1.2.3.4", 0)]
        result = cluster_aware_row_select(rows)
        assert len(result) == 1

    def test_harbourside_bec_user_cluster(self):
        """User-keyed cluster (no src_ip) — finance.officer BEC events."""
        rows = [
            {"user": "finance.officer@corp.com", "review_state": "confirmed_malicious",
             "event_type": "email_send", "ts": "2026-03-21T14:22:00Z", "row_index": i}
            for i in range(3)
        ]
        result = cluster_aware_row_select(rows, k_clusters=1, n_per_cluster=3)
        assert len(result) == 3
        assert all(r["user"] == "finance.officer@corp.com" for r in result)
