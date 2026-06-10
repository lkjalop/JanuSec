"""Regression tests for AWS CloudTrail IAM normalization.

Root cause of the Santos `analysis-0` over-merge: CloudTrail rows (source_type=iam)
carry their principal nested in userIdentity.arn / .userName and the IP in
sourceIPAddress. `_normalize_iam` previously only handled Okta/Entra/SailPoint, so
CloudTrail rows arrived entity-less — every actor's API calls fused into one
mega-component via the generic iam_op pivot, and shared_* came out empty.

These tests pin the fix so the over-merge cannot silently return.
"""
from __future__ import annotations

import os
os.environ.setdefault("PLATFORM_LITE_INIT", "1")

from src.pipeline.streaming_ingest import _normalize_iam, _principal_from_arn


class TestArnParsing:
    def test_user_arn(self):
        assert _principal_from_arn("arn:aws:iam::412309876501:user/sophie.reid") == "sophie.reid"

    def test_assumed_role_arn_returns_role(self):
        assert _principal_from_arn("arn:aws:sts::123:assumed-role/AdminRole/session-x") == "AdminRole"

    def test_role_arn(self):
        assert _principal_from_arn("arn:aws:iam::123:role/eks-integration-probe") == "eks-integration-probe"

    def test_empty_and_garbage(self):
        assert _principal_from_arn("") == ""
        assert _principal_from_arn("not-an-arn") == ""


class TestCloudTrailNormalization:
    def test_username_extracted(self):
        row = {
            "eventName": "GetObject", "sourceIPAddress": "10.11.171.153", "source_type": "iam",
            "userIdentity": {"type": "IAMUser",
                              "arn": "arn:aws:iam::412309876502:user/sophie.reid",
                              "userName": "sophie.reid", "accountId": "412309876502"},
        }
        n = _normalize_iam(row)
        assert n["user"] == "sophie.reid"
        assert n["src_ip"] == "10.11.171.153"
        assert n["event_name"] == "GetObject"
        assert n["user_type"] == "IAMUser"
        assert n["account_id"] == "412309876502"

    def test_arn_only_falls_back_to_arn_parse(self):
        row = {"sourceIPAddress": "10.0.0.5",
               "userIdentity": {"type": "AssumedRole",
                                "arn": "arn:aws:sts::1:assumed-role/pentest-readonly-feb2026/s"}}
        n = _normalize_iam(row)
        assert n["user"] == "pentest-readonly-feb2026"
        assert n["src_ip"] == "10.0.0.5"

    def test_okta_path_still_works(self):
        # Ensure the CloudTrail addition didn't break the existing Okta path.
        row = {"actor": {"alternateId": "jane@corp.com"}, "client": {"ipAddress": "1.2.3.4"},
               "eventType": "user.session.start", "source_type": "iam"}
        n = _normalize_iam(row)
        assert n["user"] == "jane@corp.com"
        assert n["src_ip"] == "1.2.3.4"

    def test_distinct_principals_do_not_collapse(self):
        # The over-merge signature: different ARNs must yield different users so
        # per-user clustering separates them instead of fusing via iam_op.
        users = set()
        for name in ("sophie.reid", "aaron.blackwood", "kenji.watanabe"):
            n = _normalize_iam({"userIdentity": {"arn": f"arn:aws:iam::1:user/{name}"},
                                "sourceIPAddress": "10.0.0.1"})
            users.add(n["user"])
        assert users == {"sophie.reid", "aaron.blackwood", "kenji.watanabe"}
