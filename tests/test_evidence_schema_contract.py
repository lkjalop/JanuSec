"""Canonical evidence-schema contract.

Guarantees every normalized row is attribution-grade: baseline fields on EVERY row,
and attribution (5-W) fields populated when the source carries them. A new source
that forgets to fill these fails here instead of silently producing weak evidence
that degrades clustering / attribution / grounded narration downstream.
"""
from __future__ import annotations

from src.pipeline.streaming_ingest import (
    normalize_row, CANONICAL_BASELINE_FIELDS, CANONICAL_ATTRIBUTION_FIELDS,
)


def test_baseline_fields_present_on_every_row():
    for row in (
        {"_source": "okta", "user": "alice", "src_ip": "1.2.3.4"},
        {"_source": "zeek", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"},
        {"_source": "sysmon", "process_name": "powershell.exe", "command_line": "-enc xxxx"},
        {"_source": "totally-unknown-source", "blob": "x"},   # even UNKNOWN gets baseline
    ):
        r = normalize_row(row)
        missing = [f for f in CANONICAL_BASELINE_FIELDS if f not in r]
        assert not missing, f"baseline fields missing for {row.get('_source')}: {missing}"


def test_identity_row_fills_actor_attribution():
    r = normalize_row({"_source": "okta", "user": "martin.chen@acme.io", "src_ip": "203.0.113.7"})
    assert r.get("user") and r.get("user_canonical")
    assert r.get("src_ip") == "203.0.113.7"


def test_ocsf_row_fills_attribution_and_provenance():
    r = normalize_row({
        "class_uid": 3002, "category_uid": 3, "severity_id": 4, "activity_name": "Logon",
        "actor": {"user": {"name": "alice"}}, "src_endpoint": {"ip": "9.9.9.9"},
        "metadata": {"version": "1.1.0", "product": {"name": "Okta"}},
    })
    # actor + action + endpoint + provenance all present.
    assert r["user"] == "alice" and r["src_ip"] == "9.9.9.9" and r["event_name"] == "Logon"
    assert r["_origin"]["source_type"] == r["_source_type"]


def test_attribution_fields_are_documented():
    # The contract list must stay non-empty and cover the identity-pivot keys that
    # clustering depends on (regression guard against silently dropping them).
    for key in ("user", "src_ip", "session_id", "device_id", "oauth_token_id", "event_name"):
        assert key in CANONICAL_ATTRIBUTION_FIELDS
