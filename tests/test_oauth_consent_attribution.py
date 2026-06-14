"""Regression: OAuth consent-grant entry-point attribution (VESPER).

The intrusion entry point — martin.chen consenting to a foreign-tenant app with excessive
scopes — was invisible: scopes were nested in targetResources, the event was low-triage
(filtered before clustering), and the cloud UPN didn't canonicalize to match endpoint
events. This pins the fix.
"""
from __future__ import annotations
import os
os.environ.setdefault("PLATFORM_LITE_INIT", "1")

from src.pipeline.streaming_ingest import _normalize_iam, _normalize_cloud, _extract_oauth_consent

_CONSENT = {
    "activityDisplayName": "Consent to application",
    "userPrincipalName": "martin.chen@acme-vesper.io",
    "targetResources": [{
        "displayName": "System Health Monitor", "id": "f8a7c2e1",
        "modifiedProperties": [{"displayName": "ConsentAction.Permissions",
                                "newValue": "[Mail.Read, Files.Read.All, User.Read.All, offline_access]"}],
    }],
}


class TestConsentExtraction:
    def test_scopes_and_excessive_flag(self):
        r = {}
        _extract_oauth_consent(_CONSENT, r)
        assert r["oauth_consent_excessive"] is True
        assert "offline_access" in r["oauth_scopes"] and "Mail.Read" in r["oauth_scopes"]
        assert r["oauth_app_name"] == "System Health Monitor"

    def test_benign_single_scope_not_excessive(self):
        r = {}
        _extract_oauth_consent({"activityDisplayName": "Consent to application",
                                "targetResources": [{"modifiedProperties": [
                                    {"displayName": "ConsentAction.Permissions", "newValue": "[User.Read]"}]}]}, r)
        assert not r.get("oauth_consent_excessive")

    def test_both_normalizers_extract(self):
        # routing-robust: consent handled whether classified iam or cloud
        assert _normalize_iam(dict(_CONSENT)).get("oauth_consent_excessive") is True
        assert _normalize_cloud(dict(_CONSENT)).get("oauth_consent_excessive") is True

    def test_upn_canonicalizes_to_short_name(self):
        # cloud UPN must unify with endpoint short-name so entry point clusters with activity
        from src.pipeline.streaming_ingest import _canonical_user
        assert _canonical_user({"user": "martin.chen@acme-vesper.io"}) == "martin.chen"
        assert _canonical_user({"user": "martin.chen"}) == "martin.chen"


class TestDetectorFires:
    def test_excessive_flag_triggers_detector(self):
        from src.core.ingest.cluster_merge import _det_oauth_device_code
        assert _det_oauth_device_code({"oauth_consent_excessive": True}, "")
