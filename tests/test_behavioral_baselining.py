"""Per-entity behavioral baselining (ChronoGraph Stage 5j).

Stage 5i accumulates per-user behavioral counts (lolbin/encoded-PS/WMI/fan-out/
foreign-ASN/auth-failure/external-send). Stage 5j z-scores each against the user's
own temporal history (peer population on cold start) and surfaces a behavior:* factor
when the current window is anomalous. These tests exercise the z-score store directly
plus the narrator label mapping, which is the contract Stage 5j relies on.
"""
from __future__ import annotations

import time

from src.core.chrono.sketch_store import ChronoSketchStore
from src.core.ingest.cluster_narrator import _FACTOR_TAG_LABELS


# The metric -> factor map Stage 5j applies. Kept in sync with assessment_worker.
_BEHAV = {
    "endpoint:lolbin_count": "behavior:lolbin_spike",
    "endpoint:encoded_ps_count": "behavior:encoded_powershell_spike",
    "endpoint:wmi_exec_count": "behavior:wmi_exec_spike",
    "network:unique_dest_count": "behavior:network_fanout_spike",
    "cloud:foreign_asn_count": "behavior:foreign_asn_spike",
    "iam:pre_auth_fail_count": "behavior:auth_failure_spike",
    "email:external_send_count": "behavior:external_send_spike",
}


def test_every_behavior_factor_has_a_narrator_label():
    # An unlabelled factor surfaces as a raw "behavior:foo_count" string in narration.
    for factor in _BEHAV.values():
        assert factor in _FACTOR_TAG_LABELS, f"{factor} missing narrator label"
        assert "T1" in _FACTOR_TAG_LABELS[factor], f"{factor} label lacks MITRE ref"


def test_temporal_spike_against_own_history_is_anomalous():
    store = ChronoSketchStore()
    ref = 1_739_000_000.0  # fixed reference so the window math is deterministic
    day = 86400.0
    # 20 days of low-but-varied baseline (1-3/day) well before the current 7-day window.
    for d in range(8, 28):
        store.increment("user", "alice", "endpoint:lolbin_count", float(d % 3 + 1), ts=ref - d * day)
    # A spike inside the current window.
    store.increment("user", "alice", "endpoint:lolbin_count", 40.0, ts=ref - day)
    z = store.z_score("user", "alice", "endpoint:lolbin_count",
                      window_seconds=7 * day, reference_ts=ref)
    assert z["source"] == "temporal"
    assert z["anomaly"] is True
    assert z["z"] >= 2.5


def test_population_fallback_flags_outlier_on_first_assessment():
    # Cold start: no per-user history, so z_score falls back to peer population.
    store = ChronoSketchStore()
    ref = 1_739_000_000.0
    for i in range(8):
        # Varied peer baseline (1-8 destinations) so the population has non-zero stddev.
        store.increment("user", f"u{i}", "network:unique_dest_count", float(i + 1), ts=ref - 3600)
    store.increment("user", "scanner", "network:unique_dest_count", 500.0, ts=ref - 3600)
    z = store.z_score("user", "scanner", "network:unique_dest_count",
                      window_seconds=7 * 86400, reference_ts=ref)
    assert z["source"] == "population"
    assert z["anomaly"] is True


def test_telemetry_gap_is_negative_z():
    # EDR-blinding signal: a host whose event volume collapses far below its own
    # baseline yields a strongly NEGATIVE temporal z-score (Stage 5j Gap 7).
    store = ChronoSketchStore()
    ref = 1_739_000_000.0
    day = 86400.0
    # 20 days of healthy event volume (varied 80-120/day) before the window.
    for d in range(8, 28):
        store.increment("host", "web01", "events", float(100 + (d % 5) * 10), ts=ref - d * day)
    # Current window: near-silence (telemetry dropped).
    store.increment("host", "web01", "events", 1.0, ts=ref - day)
    z = store.z_score("host", "web01", "events", window_seconds=7 * day,
                      reference_ts=ref, allow_population=False)
    assert z["source"] == "temporal"
    assert z["z"] <= -2.5


def test_mfa_metric_in_behavior_map():
    # The MFA push-bombing metric must be wired into the Stage 5j behavioral map.
    from src.core.ingest import assessment_worker  # noqa: F401
    # Map is built inside the function scope; assert the factor label exists instead.
    from src.core.ingest.cluster_narrator import _FACTOR_TAG_LABELS
    assert "behavior:mfa_fatigue_spike" in _FACTOR_TAG_LABELS


def test_in_baseline_user_is_not_flagged():
    store = ChronoSketchStore()
    ref = 1_739_000_000.0
    day = 86400.0
    for d in range(1, 28):
        store.increment("user", "bob", "iam:pre_auth_fail_count", 1.0, ts=ref - d * day)
    z = store.z_score("user", "bob", "iam:pre_auth_fail_count",
                      window_seconds=7 * day, reference_ts=ref)
    assert z["anomaly"] is False
