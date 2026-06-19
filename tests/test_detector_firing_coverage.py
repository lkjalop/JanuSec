"""Detector-firing coverage — the net for "a detector went silent".

The Kerberos + DCSync detectors silently never fired for an unknown period because a
generic `event_id` hash shadowed the real `windows_event_id` (a Mode-B failure: wrong
answer, NO exception — counters can't catch it, only firing assertions can). This locks
that class:

  1. The VESPER kill-chain detectors MUST fire on the live dataset (regression net for
     the exact bug we hit).
  2. Field-based Windows detectors MUST fire on the NDJSON shape (hash event_id +
     windows_event_id) — the precise shape that caused the shadowing bug.
  3. The svc_jenkins self-service red herring MUST stay suppressed.
"""
from __future__ import annotations

import glob
import os

import pytest

from src.core.ingest.cluster_merge import detect_row_phase_tags, PHASE_DETECTORS

_VESPER = os.path.join("dump", "test files", "Vesper")

# Detectors that MUST fire somewhere in VESPER's telemetry — the documented kill chain.
# If any of these stops firing (e.g. a refactor reintroduces field shadowing), this fails.
_VESPER_REQUIRED = {
    "oauth_device_code",
    "ad_recon_discovery",
    "kerberoasting",
    "wmi_dcom_lateral",
    "powershell_staged_payload",
    "bastion_rdp_lateral",
}


def _vesper_present() -> bool:
    return os.path.isdir(_VESPER) and any(
        not p.lower().endswith(".md") for p in glob.glob(os.path.join(_VESPER, "*"))
    )


@pytest.fixture(scope="module")
def vesper_fired() -> set[str]:
    """The set of phase_ids that fire across all VESPER rows (computed once)."""
    from src.core.ingest.file_parser import parse_file
    from src.pipeline.streaming_ingest import normalize_row

    fired: set[str] = set()
    for path in sorted(glob.glob(os.path.join(_VESPER, "*"))):
        if path.lower().endswith(".md") or os.path.isdir(path):
            continue
        for raw in parse_file(path, filename=os.path.basename(path)):
            fired |= detect_row_phase_tags(normalize_row(raw))
    return fired


@pytest.mark.skipif(not _vesper_present(), reason="VESPER dataset not present")
def test_vesper_killchain_detectors_fire(vesper_fired):
    missing = _VESPER_REQUIRED - vesper_fired
    assert not missing, (
        f"kill-chain detector(s) went SILENT on VESPER: {sorted(missing)} — likely a "
        f"field-shadowing / normalization regression. Fired: {sorted(vesper_fired)}")


@pytest.mark.skipif(not _vesper_present(), reason="VESPER dataset not present")
def test_no_mass_detector_silence(vesper_fired):
    # A floor: if a refactor breaks detect_row_phase_tags wholesale, the fired set
    # collapses. VESPER legitimately trips at least the kill chain.
    assert len(vesper_fired) >= len(_VESPER_REQUIRED)


# ── Synthetic positives in the exact NDJSON shape that caused the shadowing bug ──
# Each row carries a HASH `event_id` alongside the real `windows_event_id`; the detector
# must read the Windows code, not the hash.
_SHADOW_SHAPE_CASES = [
    ("kerberoasting", {"windows_event_id": "4769", "ticket_encryption": "0x17",
                       "account_name": "attacker", "service_name": "ldap/DC-X",
                       "event_id": "deadbeefhash01"}),
    ("kerberoasting", {"windows_event_id": "4769", "ticket_options": "0x60a10000",
                       "account_name": "martin", "event_id": "deadbeefhash02"}),
    ("kerberoasting", {"windows_event_id": "4768", "pre_auth_type": "0",
                       "account_name": "svc_x", "event_id": "deadbeefhash03"}),
    ("dcsync_replication", {"windows_event_id": "4662", "Properties": "1131f6aa",
                            "event_id": "deadbeefhash04"}),
    ("ad_recon_discovery", {"command_line": 'net group "Domain Admins" /domain',
                            "process_name": "net.exe"}),
]


@pytest.mark.parametrize("expected_phase,row", _SHADOW_SHAPE_CASES)
def test_windows_event_detectors_fire_on_ndjson_shape(expected_phase, row):
    tags = detect_row_phase_tags(row)
    assert expected_phase in tags, (
        f"{expected_phase} did not fire on NDJSON-shape row (hash event_id shadowing "
        f"regression?). Got: {sorted(tags)}")


def test_kerberoast_self_service_red_herring_suppressed():
    # svc_jenkins requesting a ticket for its OWN host service = benign legacy RC4.
    row = {"windows_event_id": "4769", "ticket_encryption": "0x17",
           "account_name": "svc_jenkins", "service_name": "host/SVR-JENKINS-01",
           "event_id": "hash"}
    assert "kerberoasting" not in detect_row_phase_tags(row)


def test_every_registered_detector_has_unique_phase_id():
    # A duplicate phase_id silently hides one detector behind another in the registry.
    ids = [d.phase_id for d in PHASE_DETECTORS]
    dupes = {p for p in ids if ids.count(p) > 1}
    assert not dupes, f"duplicate PhaseDetector phase_id(s): {sorted(dupes)}"


def test_detector_errors_are_counted_not_swallowed():
    # A2 observability: a detector that RAISES must be counted, not vanish into a debug
    # log. Guards the Mode-A failure on the detection path.
    import src.core.ingest.cluster_merge as cm
    det = cm.PHASE_DETECTORS[0]
    original = det.matcher
    cm.reset_detector_error_counts()
    try:
        def _boom(row, text):
            raise ValueError("synthetic detector crash")
        det.matcher = _boom
        cm.detect_row_phase_tags({"message": "anything"})
        counts = cm.get_detector_error_counts()
        assert counts.get(det.phase_id, 0) >= 1, "raising detector was swallowed silently"
    finally:
        det.matcher = original
        cm.reset_detector_error_counts()


def test_clustering_diagnostics_surface_detector_errors():
    import src.core.ingest.cluster_merge as cm
    diag: dict = {}
    cm.transitive_merge_clusters(
        None,
        [{"row_index": 0, "user_canonical": "u", "timestamp": "2026-01-01T00:00:00Z",
          "message": "x"}],
        diagnostics_out=diag,
    )
    assert "detector_errors" in diag  # healthy run -> {} ; any entry -> a detector is throwing
