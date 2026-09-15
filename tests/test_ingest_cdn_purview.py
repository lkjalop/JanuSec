"""CDN (Cloudflare) + M365 Unified Audit Log + Microsoft Purview ingestion.

Added declaratively via FIELD_MAPS (no new _normalize_X). Cloudflare WAF/Access →
network+identity, M365 UAL → activity, Purview DLP → data-aware exfil (a detector
that clusters DLP hits into the intrusion + the exfil-first arc).
"""
from __future__ import annotations

from src.pipeline.streaming_ingest import normalize_row, classify_source, SOURCE_NETWORK, SOURCE_IAM
from src.core.ingest.cluster_merge import detect_row_phase_tags, PHASE_DETECTORS
from src.core.mappings.factor_to_mitre import get_all_mappings
from src.core.ingest.cluster_narrator import _FACTOR_TAG_LABELS


def test_cloudflare_classifies_and_maps():
    assert classify_source("cloudflare") == SOURCE_NETWORK
    row = {"_source": "cloudflare", "ClientIP": "203.0.113.9", "ClientRequestHost": "app.acme.io",
           "ClientCountry": "RU", "ClientASN": "64500", "Action": "block", "RuleID": "100015",
           "Email": "martin.chen@acme.io"}
    r = normalize_row(row)
    assert r["src_ip"] == "203.0.113.9"
    assert r["hostname"] == "app.acme.io"
    assert r["geo_country"] == "RU"
    assert r["action"] == "block"
    assert r["user"] == "martin.chen@acme.io"   # Cloudflare Access (Zero Trust) identity
    assert r["_vendor"] == "cloudflare"


def test_m365_ual_maps_operation_and_actor():
    row = {"_source": "m365_ual", "UserId": "alice@acme.io", "ClientIP": "1.2.3.4",
           "Operation": "New-InboxRule", "ObjectId": "mbx/alice"}
    r = normalize_row(row)
    assert r["user"] == "alice@acme.io"
    assert r["event_name"] == "New-InboxRule"
    assert r["target"] == "mbx/alice"


def test_purview_dlp_maps_and_detects_exfil():
    row = {"_source": "purview", "UserPrincipalName": "bob@acme.io", "Operation": "DLPRuleMatch",
           "SensitiveInfoType": "Credit Card Number", "PolicyName": "Block-PII-Exfil",
           "PolicyAction": "Block", "ObjectId": "file/secret.xlsx"}
    r = normalize_row(row)
    assert r["user"] == "bob@acme.io"
    assert r["data_class"] == "Credit Card Number"
    assert r["outcome"] == "Block"
    # DLP detector fires -> exfiltration phase, ties Purview into the intrusion arc.
    r["row_index"] = 1
    assert "dlp_exfil" in detect_row_phase_tags(r)
    det = next(d for d in PHASE_DETECTORS if d.phase_id == "dlp_exfil")
    assert det.case_role == "data_exfiltration"


def test_new_source_factors_map_and_narrate():
    for factor, code in {"data:dlp_violation": "T1567", "insider:risk_elevated": "T1078",
                         "network:waf_block": "T1190", "network:edge_recon_scan": "T1595"}.items():
        assert code in get_all_mappings([factor]).get("mitre", [])
        assert factor in _FACTOR_TAG_LABELS
