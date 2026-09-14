import pytest

from src.core.evidence_contract.signed_snapshots import verify_snapshot
from src.core.grc.verification_adapters import build_verification_payload, sign_provider_verification


@pytest.mark.parametrize("provider,before,after,expected", [
    ("entra_m365", {"id":"b1","createdDateTime":"2026-08-22T00:00:00Z","status":"active"}, {"id":"a1","createdDateTime":"2026-08-22T00:01:00Z","status":"revoked"}, {"status":"revoked"}),
    ("aws", {"eventID":"b1","eventTime":"2026-08-22T00:00:00Z","result":"attached"}, {"eventID":"a1","eventTime":"2026-08-22T00:01:00Z","result":"detached"}, {"result":"detached"}),
    ("gcp", {"insertId":"b1","timestamp":"2026-08-22T00:00:00Z","result":"enabled"}, {"insertId":"a1","timestamp":"2026-08-22T00:01:00Z","result":"disabled"}, {"result":"disabled"}),
    ("alibaba", {"eventId":"b1","eventTime":"2026-08-22T00:00:00Z","result":"enabled"}, {"eventId":"a1","eventTime":"2026-08-22T00:01:00Z","result":"disabled"}, {"result":"disabled"}),
    ("edr", {"event_id":"b1","timestamp":"2026-08-22T00:00:00Z","status":"online"}, {"event_id":"a1","timestamp":"2026-08-22T00:01:00Z","status":"isolated"}, {"status":"isolated"}),
    ("firewall", {"event_id":"b1","timestamp":"2026-08-22T00:00:00Z","disposition":"allow"}, {"event_id":"a1","timestamp":"2026-08-22T00:01:00Z","disposition":"deny"}, {"disposition":"deny"}),
    ("veeam", {"job_id":"b1","collected_at":"2026-08-22T00:00:00Z","result":"not_tested"}, {"job_id":"a1","collected_at":"2026-08-22T00:01:00Z","result":"passed"}, {"result":"passed"}),
])
def test_provider_verification_is_exact_read_only_and_signable(provider, before, after, expected):
    payload = build_verification_payload(
        provider=provider, action_id="action-1", before_native=before, after_native=after,
        expected_after=expected, collector_identity="workload:test",
    )
    assert payload["verification_status"] == "verified"
    assert payload["collection_mode"] == "read_only"
    signed = sign_provider_verification(
        tenant_id="tenant-a", payload=payload, version="1",
        valid_from="2026-08-22T00:00:00Z", key="test-key",
    )
    assert verify_snapshot(
        signed, expected_kind="control_verification", tenant_id="tenant-a", key="test-key",
    ) == (True, "verified")


def test_verification_fails_closed_on_mismatch_or_missing_native_id():
    payload = build_verification_payload(
        provider="firewall", action_id="a", collector_identity="collector",
        before_native={"event_id":"b","timestamp":"2026-08-22T00:00:00Z"},
        after_native={"event_id":"c","timestamp":"2026-08-22T00:01:00Z","disposition":"allow"},
        expected_after={"disposition":"deny"},
    )
    assert payload["verification_status"] == "failed"
    with pytest.raises(ValueError, match="stable_ids"):
        build_verification_payload(
            provider="aws", action_id="a", collector_identity="collector",
            before_native={"eventTime":"2026-08-22T00:00:00Z"},
            after_native={"eventTime":"2026-08-22T00:01:00Z"}, expected_after={"result":"ok"},
        )


@pytest.mark.parametrize("timestamp", [None, "not-a-time"])
def test_missing_or_invalid_time_cannot_verify_correction(timestamp):
    payload = build_verification_payload(
        provider="edr", action_id="a", collector_identity="collector",
        before_native={"event_id": "before", "timestamp": timestamp},
        after_native={"event_id": "after", "timestamp": timestamp, "status": "isolated"},
        expected_after={"status": "isolated"},
    )
    assert payload["verification_status"] == "unverified"


def test_missing_field_is_not_an_explicit_null_provider_result():
    payload = build_verification_payload(
        provider="edr", action_id="a", collector_identity="collector",
        before_native={"event_id": "before", "timestamp": "2026-01-01T00:00:00Z"},
        after_native={"event_id": "after", "timestamp": "2026-01-01T00:01:00Z"},
        expected_after={"status": None},
    )
    assert payload["verification_status"] == "failed"
