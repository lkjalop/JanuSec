"""Clustering hardening: unioning across an unparsed (epoch-zero) timestamp is allowed
only on STRONG identity pivots (user/session/token/cloud-identity), never on weak
infrastructure pivots (ip/cidr/asn/ja3/host) where it would smear unrelated actors.

The real behavioural validation is the ground-truth gate (green across VESPER/Meridian/
Santos with this guard); this locks the strong/weak classification against drift."""
import pytest

from src.core.ingest.cluster_merge import _STRONG_TS_PIVOTS

pytestmark = pytest.mark.acceptance


def test_strong_identity_pivots_permit_zero_ts_union():
    for p in ("canon_user", "canon_user_breach", "cloud_identity", "session", "device", "oauth_token"):
        assert p in _STRONG_TS_PIVOTS


def test_weak_infrastructure_pivots_excluded():
    # These must NOT permit zero-ts unions (unbounded smear risk).
    for p in ("ip", "cidr24", "cidr16", "cidr28", "asn", "ja3", "ja3s", "ja4",
              "host", "sig", "attacker_zone", "recipient_domain"):
        assert p not in _STRONG_TS_PIVOTS
