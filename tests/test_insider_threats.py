"""
Unit tests for detect_insider_threats() in advanced_endpoint_threats.py

Covers all four detection pillars:
  identity:stale_account_active
  insider:bulk_cloud_download
  insider:personal_cloud_sync_process
  dlp:purview_policy_match
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.detectors.advanced_endpoint_threats import detect_insider_threats  # noqa: E402


# ── helpers -----------------------------------------------------------------

def _factor_names(results):
    return {r["factor"] for r in results}


def _get(results, factor):
    return next((r for r in results if r["factor"] == factor), None)


_TERM_TS = time.time() - 7 * 86400  # terminated 7 days ago
_RECENT_LOGIN_TS = time.time() - 1 * 86400  # logged in 1 day ago (after termination)
_MB500 = 500 * 1024 * 1024  # 500 MB


# ── identity:stale_account_active -------------------------------------------

class TestStaleAccount:
    def test_enabled_after_termination_fires(self):
        ev = {
            "user": "jsmith",
            "account_status": "enabled",
            "termination_date": _TERM_TS,
            "last_login_epoch": _RECENT_LOGIN_TS,
            "hostname": "CORP-PC-01",
        }
        results = detect_insider_threats([ev])
        assert "identity:stale_account_active" in _factor_names(results)

    def test_login_after_termination_fires_even_without_status(self):
        ev = {
            "user": "jsmith",
            "termination_date": _TERM_TS,
            "timestamp_epoch": _RECENT_LOGIN_TS,   # event itself is post-termination
        }
        results = detect_insider_threats([ev])
        assert "identity:stale_account_active" in _factor_names(results)

    def test_no_termination_date_does_not_fire(self):
        ev = {"user": "jsmith", "account_status": "enabled"}
        results = detect_insider_threats([ev])
        assert "identity:stale_account_active" not in _factor_names(results)

    def test_disabled_account_after_termination_does_not_fire(self):
        ev = {
            "user": "jsmith",
            "account_status": "disabled",
            "termination_date": _TERM_TS,
            "last_login_epoch": _TERM_TS - 86400,  # last login BEFORE termination
        }
        results = detect_insider_threats([ev])
        assert "identity:stale_account_active" not in _factor_names(results)

    def test_score_scales_with_days_stale(self):
        ev_short = {
            "user": "user1",
            "account_status": "active",
            "termination_date": time.time() - 1 * 86400,
            "last_login_epoch": time.time() - 0.5 * 86400,
        }
        ev_long = {
            "user": "user2",
            "account_status": "active",
            "termination_date": time.time() - 30 * 86400,
            "last_login_epoch": time.time() - 0.5 * 86400,
        }
        r1 = _get(detect_insider_threats([ev_short]), "identity:stale_account_active")
        r2 = _get(detect_insider_threats([ev_long]), "identity:stale_account_active")
        assert r1 is not None and r2 is not None
        assert r2["score"] > r1["score"]

    def test_has_required_tags(self):
        ev = {
            "user": "jsmith",
            "account_status": "enabled",
            "termination_date": _TERM_TS,
            "last_login_epoch": _RECENT_LOGIN_TS,
        }
        result = _get(detect_insider_threats([ev]), "identity:stale_account_active")
        assert result is not None
        tags = result["tags"]
        assert "ATTACK:T1078" in tags
        assert "INSIDER:TRUE" in tags


# ── insider:bulk_cloud_download ---------------------------------------------

class TestBulkCloudDownload:
    def _make_download_events(self, user, n_files, bytes_each=0):
        return [
            {
                "user": user,
                "operation": "FileDownloaded",
                "byte_count": bytes_each,
                "timestamp_epoch": time.time() - i * 60,
            }
            for i in range(n_files)
        ]

    def test_fires_on_file_count_threshold(self):
        events = self._make_download_events("alice", n_files=210)
        results = detect_insider_threats(events)
        assert "insider:bulk_cloud_download" in _factor_names(results)

    def test_fires_on_byte_threshold(self):
        # 10 files × 60 MB = 600 MB > 500 MB threshold
        events = self._make_download_events("bob", n_files=10, bytes_each=60 * 1024 * 1024)
        results = detect_insider_threats(events)
        assert "insider:bulk_cloud_download" in _factor_names(results)

    def test_does_not_fire_below_threshold(self):
        # 10 files, 0 bytes — well below both thresholds
        events = self._make_download_events("carol", n_files=10)
        results = detect_insider_threats(events)
        assert "insider:bulk_cloud_download" not in _factor_names(results)

    def test_purview_hit_boosts_score(self):
        base_events = self._make_download_events("dave", n_files=210)
        # Same but with a Purview DLP match on the same user
        with_purview = base_events + [{
            "user": "dave",
            "operation": "DlpPolicyMatched",
            "timestamp_epoch": time.time(),
        }]
        r_base = _get(detect_insider_threats(base_events), "insider:bulk_cloud_download")
        r_purview = _get(detect_insider_threats(with_purview), "insider:bulk_cloud_download")
        assert r_base is not None and r_purview is not None
        assert r_purview["score"] > r_base["score"]

    def test_departure_window_boosts_score(self):
        # Departed 3 days ago; downloads within window
        dep_ts = time.time() - 3 * 86400
        base_events = self._make_download_events("eve", n_files=210)
        departure_events = base_events + [{
            "user": "eve",
            "termination_date": dep_ts,
            "timestamp_epoch": time.time() - 2 * 86400,
        }]
        r_base    = _get(detect_insider_threats(base_events), "insider:bulk_cloud_download")
        r_depart  = _get(detect_insider_threats(departure_events), "insider:bulk_cloud_download")
        assert r_base is not None and r_depart is not None
        assert r_depart["score"] > r_base["score"]

    def test_m365_filesync_operation_counts(self):
        events = [
            {"user": "frank", "operation": "FileSyncDownloadedFull", "byte_count": 1024}
            for _ in range(210)
        ]
        results = detect_insider_threats(events)
        assert "insider:bulk_cloud_download" in _factor_names(results)

    def test_tags_present(self):
        events = self._make_download_events("grace", n_files=210)
        result = _get(detect_insider_threats(events), "insider:bulk_cloud_download")
        assert result is not None
        assert "ATTACK:T1213" in result["tags"]
        assert "INSIDER:TRUE" in result["tags"]


# ── dlp:purview_policy_match ------------------------------------------------

class TestPurviewDLP:
    def test_fires_on_purview_event(self):
        ev = {"user": "hank", "operation": "DlpPolicyMatched", "timestamp_epoch": time.time()}
        assert "dlp:purview_policy_match" in _factor_names(detect_insider_threats([ev]))

    def test_fires_on_sensitivity_label_changed(self):
        ev = {"user": "ira", "operation": "SensitivityLabelChanged"}
        assert "dlp:purview_policy_match" in _factor_names(detect_insider_threats([ev]))

    def test_does_not_fire_for_unrelated_op(self):
        ev = {"user": "jane", "operation": "UserLoggedIn"}
        assert "dlp:purview_policy_match" not in _factor_names(detect_insider_threats([ev]))

    def test_hit_count_in_result(self):
        events = [
            {"user": "karl", "operation": "DlpRuleMatch"},
            {"user": "karl", "operation": "DlpPolicyTip"},
        ]
        result = _get(detect_insider_threats(events), "dlp:purview_policy_match")
        assert result is not None
        assert result["dlp_hit_count"] == 2

    def test_dlp_endpoint_match_op(self):
        ev = {"user": "leo", "operation": "DlpEndpointMatch"}
        assert "dlp:purview_policy_match" in _factor_names(detect_insider_threats([ev]))


# ── insider:personal_cloud_sync_process -------------------------------------

class TestPersonalCloudSync:
    def test_dropbox_on_corp_endpoint_fires(self):
        ev = {
            "process": "Dropbox.exe",
            "source": "sysmon",
            "hostname": "CORP-WS-42",
            "user": "mike",
        }
        assert "insider:personal_cloud_sync_process" in _factor_names(detect_insider_threats([ev]))

    def test_googledrivesync_fires(self):
        ev = {
            "process": "googledrivesync.exe",
            "source_platform": "windows",
            "hostname": "PC-001",
        }
        assert "insider:personal_cloud_sync_process" in _factor_names(detect_insider_threats([ev]))

    def test_megasync_fires(self):
        ev = {"process": "megasync.exe", "source": "edr", "hostname": "CORP-PC"}
        assert "insider:personal_cloud_sync_process" in _factor_names(detect_insider_threats([ev]))

    def test_legitimate_process_does_not_fire(self):
        ev = {"process": "chrome.exe", "source": "sysmon", "hostname": "CORP-PC"}
        assert "insider:personal_cloud_sync_process" not in _factor_names(detect_insider_threats([ev]))

    def test_unknown_source_no_hostname_skipped(self):
        # BYOD or unclassified source with no hostname = skip
        ev = {"process": "dropbox.exe", "source": "", "hostname": ""}
        assert "insider:personal_cloud_sync_process" not in _factor_names(detect_insider_threats([ev]))

    def test_tags_present(self):
        ev = {"process": "box.exe", "source": "sysmon", "hostname": "CORP-PC"}
        result = _get(detect_insider_threats([ev]), "insider:personal_cloud_sync_process")
        assert result is not None
        assert "ATTACK:T1567" in result["tags"]
        assert "INSIDER:TRUE" in result["tags"]


# ── Empty input --------------------------------------------------------------

class TestEdgeCases:
    def test_empty_events_returns_empty(self):
        assert detect_insider_threats([]) == []

    def test_events_with_no_relevant_fields(self):
        results = detect_insider_threats([{"foo": "bar"}, {}, {"x": 1}])
        assert results == []

    def test_combined_signals_all_fire(self):
        """Multiple independent signals for the same user all produce factors."""
        dep_ts = time.time() - 3 * 86400
        events = [
            # stale account
            {
                "user": "nancy",
                "account_status": "active",
                "termination_date": dep_ts,
                "last_login_epoch": time.time() - 1 * 86400,
            },
            # bulk download
            *[{"user": "nancy", "operation": "FileDownloaded", "byte_count": 1024}
              for _ in range(210)],
            # Purview DLP
            {"user": "nancy", "operation": "DlpRuleMatch"},
            # personal sync
            {"process": "dropbox.exe", "source": "sysmon", "hostname": "CORP-PC", "user": "nancy"},
        ]
        names = _factor_names(detect_insider_threats(events))
        assert "identity:stale_account_active" in names
        assert "insider:bulk_cloud_download" in names
        assert "dlp:purview_policy_match" in names
        assert "insider:personal_cloud_sync_process" in names
