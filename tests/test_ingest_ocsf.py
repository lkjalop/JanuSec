"""OCSF (Open Cybersecurity Schema Framework) ingestion.

One normalizer ingests the whole multi-cloud estate behind AWS Security Lake
(AWS + Azure + GCP + GuardDuty + custom -> OCSF). Routed by class_uid to the
right Janusec source-type; nested OCSF objects flattened to canonical fields.
"""
from __future__ import annotations

from src.pipeline.streaming_ingest import (
    normalize_row, _is_ocsf_row, SOURCE_IAM, SOURCE_NETWORK, SOURCE_CLOUD,
)


def test_ocsf_authentication_event_routes_to_iam():
    row = {
        "class_uid": 3002, "category_uid": 3, "severity_id": 4,
        "activity_name": "Logon",
        "actor": {"user": {"name": "martin.chen@acme.io"}},
        "src_endpoint": {"ip": "203.0.113.7", "location": {"country": "RU"},
                         "autonomous_system": {"number": 64500}},
        "device": {"hostname": "DC01"},
        "time": 1739000000000,
        "metadata": {"version": "1.1.0", "product": {"name": "Okta"}},
    }
    assert _is_ocsf_row(row)
    r = normalize_row(row)
    assert r["_source_type"] == SOURCE_IAM
    assert r["user"] == "martin.chen@acme.io"
    assert r["src_ip"] == "203.0.113.7"
    assert r["hostname"] == "DC01"
    assert r["severity"] == "high"           # severity_id 4 -> high
    assert r["geo_country"] == "RU"
    assert str(r["asn"]) == "64500"
    assert r["_ocsf_product"] == "Okta"


def test_ocsf_detection_finding_routes_to_cloud():
    row = {
        "class_uid": 2004, "category_uid": 2, "severity_id": 5,
        "finding_info": {"title": "CryptoCurrency:EC2/BitcoinTool.B"},
        "metadata": {"version": "1.1.0", "product": {"name": "Amazon GuardDuty"}},
        "time": 1739000000000,
    }
    r = normalize_row(row)
    assert r["_source_type"] == SOURCE_CLOUD
    assert "BitcoinTool" in r["event_name"]
    assert r["severity"] == "critical"


def test_ocsf_http_activity_routes_to_network():
    row = {
        "class_uid": 4002, "category_uid": 4, "severity_id": 3,
        "activity_name": "GET",
        "src_endpoint": {"ip": "198.51.100.9"},
        "dst_endpoint": {"ip": "10.0.0.5", "hostname": "web01"},
        "metadata": {"version": "1.1.0", "product": {"name": "Cloudflare"}},
    }
    r = normalize_row(row)
    assert r["_source_type"] == SOURCE_NETWORK
    assert r["src_ip"] == "198.51.100.9"
    assert r["dst_ip"] == "10.0.0.5"


def test_non_ocsf_row_unaffected():
    # A plain row without OCSF markers must NOT be treated as OCSF.
    assert not _is_ocsf_row({"user": "alice", "src_ip": "1.2.3.4"})
