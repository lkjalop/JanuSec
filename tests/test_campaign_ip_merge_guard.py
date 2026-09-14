"""Clustering hardening: a public IP shared by MANY breach clusters is shared egress
(NAT/VPN/CDN), not a campaign link — merging on it would collapse unrelated breaches."""
import pytest

from src.core.ingest.cluster_merge import _campaign_rollup

pytestmark = pytest.mark.acceptance


def _clusters(n, ip):
    return [{"verdict": "VALIDATED_BREACH", "cluster_id": f"c{i}",
             "shared_users": [f"user{i}"], "shared_ips": [ip],
             "row_refs": [i], "factor_tags": ["kerberoasting"]} for i in range(n)]


def test_shared_egress_ip_does_not_collapse_unrelated_breaches():
    # 6 distinct-actor breaches sharing one public IP must NOT become one campaign.
    out = _campaign_rollup(_clusters(6, "203.0.113.9"))
    assert len(out) == 6


def test_small_ip_link_still_merges_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("JANUSEC_ENABLE_IP_CAMPAIGN_UNION", "1")
    # Two breaches sharing a public IP is plausible campaign infrastructure — merge.
    out = _campaign_rollup(_clusters(2, "203.0.113.9"))
    assert len(out) == 1


def test_shared_actor_always_merges_regardless_of_ip_count():
    # Same identity across many clusters is strong evidence — always one campaign.
    cl = [{"verdict": "VALIDATED_BREACH", "cluster_id": f"c{i}",
           "shared_users": ["martin.chen"], "shared_ips": [f"203.0.113.{i}"],
           "row_refs": [i], "factor_tags": ["kerberoasting"]} for i in range(6)]
    out = _campaign_rollup(cl)
    assert len(out) == 1


def test_private_ip_never_merges():
    # RFC-1918 IPs are not campaign links at all.
    out = _campaign_rollup(_clusters(2, "10.20.1.5"))
    assert len(out) == 2


def test_ip_link_is_not_identity_by_default(monkeypatch):
    monkeypatch.delenv("JANUSEC_ENABLE_IP_CAMPAIGN_UNION", raising=False)
    assert len(_campaign_rollup(_clusters(2, "203.0.113.9"))) == 2
