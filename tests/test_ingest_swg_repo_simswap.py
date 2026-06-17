"""Zscaler/Netskope SWG + GitHub repo-audit ingestion + SIM-swap detector.

Each is a declarative vertical slice (no new _normalize_X):
  * Zscaler/Netskope secure web gateway -> NETWORK lane, user-attributed web egress.
  * GitHub/GitLab audit -> IAM lane, actor-attributed repo/secret access.
  * SIM-swap is a per-row PhaseDetector (initial_access) + factor surface (T1451).
"""
from __future__ import annotations

from src.pipeline.streaming_ingest import normalize_row, classify_source, SOURCE_NETWORK, SOURCE_IAM
from src.core.ingest.cluster_merge import detect_row_phase_tags, PHASE_DETECTORS
from src.core.mappings.factor_to_mitre import get_all_mappings
from src.core.ingest.cluster_narrator import _FACTOR_TAG_LABELS


def _phases(row):
    return detect_row_phase_tags(row)


def test_zscaler_classifies_network_and_maps():
    assert classify_source("zscaler") == SOURCE_NETWORK
    row = {"_source": "zscaler", "user": "martin.chen@acme.io", "url": "martin-chen.sharepoint.com",
           "action": "allowed", "urlcategory": "File Sharing", "clientpublicIP": "203.0.113.5",
           "location": "RU", "reason": "policy-allow"}
    r = normalize_row(row)
    assert r["user"] == "martin.chen@acme.io"
    assert r["target"] == "martin-chen.sharepoint.com"
    assert r["action"] == "allowed"
    assert r["category"] == "File Sharing"
    assert r["_vendor"] == "zscaler"


def test_netskope_classifies_network_and_maps_dlp():
    assert classify_source("netskope") == SOURCE_NETWORK
    row = {"_source": "netskope", "user": "bob@acme.io", "url": "drive.google.com/upload",
           "action": "block", "dlp_profile": "PII-Strict", "policy": "Block-Exfil"}
    r = normalize_row(row)
    assert r["user"] == "bob@acme.io"
    assert r["target"] == "drive.google.com/upload"
    assert r["data_class"] == "PII-Strict"
    assert r["_vendor"] == "netskope"


def test_github_audit_classifies_iam_and_maps_actor():
    assert classify_source("github") == SOURCE_IAM
    assert classify_source("github_audit") == SOURCE_IAM
    row = {"_source": "github_audit", "actor": "martin.chen", "action": "repo.download_zip",
           "repo": "acme/payments-core", "actor_ip": "203.0.113.5", "result": "success"}
    r = normalize_row(row)
    assert r["user"] == "martin.chen"
    assert r["event_name"] == "repo.download_zip"
    assert r["target"] == "acme/payments-core"
    assert r["_vendor"] == "github"


def test_gcp_audit_extracts_nested_principal_and_caller_ip():
    from src.pipeline.streaming_ingest import SOURCE_CLOUD
    assert classify_source("gcp") == SOURCE_CLOUD
    row = {
        "_source": "gcp",
        "protoPayload": {
            "authenticationInfo": {"principalEmail": "martin.chen@acme.io"},
            "requestMetadata": {"callerIp": "203.0.113.5"},
            "methodName": "storage.objects.get",
        },
        "resource": "acme-secrets-bucket",
    }
    r = normalize_row(row)
    assert r["user"] == "martin.chen@acme.io"   # nested principal -> actor
    assert r["src_ip"] == "203.0.113.5"          # nested callerIp -> src_ip
    assert r["event_name"] == "storage.objects.get"


def test_sim_swap_detector_fires_on_op_and_text():
    assert "sim_swap" in _phases({"row_index": 1, "Operation": "Update phone number"})
    assert "sim_swap" in _phases({"row_index": 2, "message": "SIM swap detected; number ported to new carrier"})
    assert "sim_swap" not in _phases({"row_index": 3, "Operation": "UserLoggedIn"})
    det = next(d for d in PHASE_DETECTORS if d.phase_id == "sim_swap")
    assert det.case_role == "initial_access" and det.severity == "high"


def test_new_feed_factors_map_to_mitre_and_have_labels():
    cases = {
        "iam:sim_swap_indicator": "T1451",
        "cloud:gcp_audit_anomaly": "T1078.004",
        "identity:repo_audit_anomaly": "T1078",
    }
    for factor, code in cases.items():
        assert code in get_all_mappings([factor]).get("mitre", []), f"{factor} -> {code} missing"
        assert factor in _FACTOR_TAG_LABELS and "T1" in _FACTOR_TAG_LABELS[factor]
