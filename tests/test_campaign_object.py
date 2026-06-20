"""Canonical Campaign object — the single source of breach truth.

Locks that build_campaign assembles the full breach picture from a cluster (actor,
verdict, kill chain incl. exfil, real IOC entities, entry point, exfil destination) so
reports/personas/grounding stop re-deriving it ad-hoc.
"""
from __future__ import annotations

import pytest

from src.core.campaign import build_campaign, build_campaigns, Campaign

pytestmark = pytest.mark.acceptance


def _martin_cluster() -> dict:
    return {
        "cluster_id": "analysis-0-powershell-47",
        "parent_cluster_id": "analysis-0",
        "verdict": "VALIDATED_BREACH",
        "confidence": 0.97,
        "severity": "critical",
        "shared_users": ["martin.chen"],
        "shared_ips": ["203.45.11.147", "10.42.3.79"],     # external + private
        "shared_hosts": ["ws-martin-01"],
        "present_phase_ids": ["oauth_device_code", "ad_recon_discovery", "kerberoasting",
                              "wmi_dcom_lateral", "powershell_staged_payload"],
        "phases": [{"phase_id": "powershell_staged_payload", "case_role": "execution"}],
        "factor_tags": ["iam:kerberoasting", "exfil:cumulative_bytes_anomaly"],
        "_entry_point": {"type": "oauth_consent_grant", "user": "martin.chen"},
        "_exfil_destinations": {"d1": {"destination": "martin-chen.sharepoint.com"}},
        "row_refs": list(range(50)),
        "row_count": 50,
    }


def test_build_campaign_assembles_full_truth():
    c = build_campaign(_martin_cluster())
    assert isinstance(c, Campaign)
    assert c.campaign_id == "analysis-0"          # rolls up to the parent
    assert c.actor == "martin.chen"
    assert c.verdict == "VALIDATED_BREACH" and c.is_breach
    assert c.entry_point and c.entry_point["type"] == "oauth_consent_grant"
    assert "martin-chen.sharepoint.com" in c.exfil_destinations


def test_campaign_kill_chain_includes_exfil_finale():
    c = build_campaign(_martin_cluster())
    assert len(c.phases) >= 4, f"kill chain too thin: {c.phases}"
    assert "exfiltration" in c.phases, "the breach finale (exfil) must be in the kill chain"


def test_campaign_entities_are_grounding_ready():
    c = build_campaign(_martin_cluster())
    # external IPs isolated (for attacker-infra / hunt grounding), private excluded
    assert "203.45.11.147" in c.entities["external_ips"]
    assert "10.42.3.79" not in c.entities["external_ips"]
    assert "martin-chen.sharepoint.com" in c.entities["domains"]
    assert c.actor in c.entities["users"]


def test_build_campaigns_filters_to_breaches_and_dedupes():
    breach = _martin_cluster()
    benign = {"cluster_id": "c2", "verdict": "NO_VALIDATED_BREACH", "shared_users": ["bob"]}
    dup_child = dict(breach, cluster_id="analysis-0-recon-12",
                     present_phase_ids=["ad_recon_discovery"])  # same parent, fewer phases
    camps = build_campaigns([breach, benign, dup_child])
    assert len(camps) == 1, "breach-only + per-campaign dedupe expected"
    assert camps[0].campaign_id == "analysis-0"
    assert len(camps[0].phase_ids) == 5, "kept the richest representative of the campaign"


def test_persona_grounding_reads_from_campaign_when_rows_sparse():
    # The keystone payoff: with NO evidence rows but a canonical campaign present, the
    # hunter queries still ground in the campaign's real IOCs.
    from src.reporting.comprehensive_report_generator import _build_threat_hunter_page
    payload = {
        "rows": [],
        "meta": {"verdict": "VALIDATED_BREACH"},
        "campaigns": [{
            "actor": "martin.chen", "verdict": "VALIDATED_BREACH",
            "entities": {"external_ips": ["203.45.42.201"], "domains": ["martin-chen.sharepoint.com"]},
        }],
    }
    html = _build_threat_hunter_page(payload, payload["meta"], {}, "s", "Acme", "2026-01-01")
    assert "203.45.42.201" in html, "campaign external IP not grounded into queries"
    assert "known_bad_ips" not in html, "placeholder survived despite campaign IOCs"
