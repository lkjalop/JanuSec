"""Declarative field-map registry, per-row provenance, and ingest accounting.

These reduce ingest-path debt: a new source becomes a DATA edit (one field map),
every row carries provenance for attribution/grounding, and silent row drops become
observable counters instead of `except: pass`.
"""
from __future__ import annotations

import src.pipeline.streaming_ingest as si
from src.pipeline.streaming_ingest import (
    normalize_row, FIELD_MAPS, get_ingest_stats, reset_ingest_stats, record_dropped_row,
)


def test_field_map_adds_vendor_fidelity():
    # Register a throwaway vendor map; a row tagged with that vendor gets canonical
    # fields filled from its raw keys WITHOUT a new _normalize_X branch.
    FIELD_MAPS["acmewaf"] = {"src_ip": "ClientIP", "geo_country": "ClientCountry", "action": "WAFAction"}
    try:
        row = {"_source": "acmewaf", "ClientIP": "203.0.113.9", "ClientCountry": "RU", "WAFAction": "block"}
        r = normalize_row(row)
        assert r["src_ip"] == "203.0.113.9"
        assert r["geo_country"] == "RU"
        assert r["action"] == "block"
        assert r.get("_vendor") == "acmewaf"
    finally:
        FIELD_MAPS.pop("acmewaf", None)


def test_field_map_does_not_override_existing_canonical():
    FIELD_MAPS["acmewaf2"] = {"src_ip": "ClientIP"}
    try:
        # Network normalizer already set src_ip; the map must not clobber it.
        row = {"_source": "acmewaf2 zeek", "src_ip": "10.0.0.1", "ClientIP": "203.0.113.9"}
        r = normalize_row(row)
        assert r["src_ip"] == "10.0.0.1"
    finally:
        FIELD_MAPS.pop("acmewaf2", None)


def test_every_row_has_provenance():
    r = normalize_row({"_source": "okta", "user": "alice", "src_ip": "1.2.3.4"})
    origin = r.get("_origin")
    assert isinstance(origin, dict)
    assert origin["source_type"] == r["_source_type"]
    assert "normalizer_version" in origin


def test_ingest_accounting_counts_and_drops():
    reset_ingest_stats()
    normalize_row({"_source": "okta", "user": "a"})
    normalize_row({"_source": "zeek", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"})
    record_dropped_row("json_decode_error")
    stats = get_ingest_stats()
    assert stats["normalized"] == 2
    assert stats["dropped_total"] == 1
    assert stats["dropped"]["json_decode_error"] == 1
    assert sum(stats["by_source_type"].values()) == 2
