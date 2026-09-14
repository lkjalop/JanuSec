"""Decomposed DREAD engine: 5 components with rationale, evidence-grounded Affected
deep-dive, and drivers wired to infrastructure / investments / improvements.

Reengineers the legacy numeric scorer (which was blind to the phase vocabulary,
neutral on Reproducibility/Affected, and scored a validated breach as 'trace').
"""
import pytest

from src.core.grc.dread import assess_dread

pytestmark = pytest.mark.acceptance


def _breach():
    return {
        "cluster_id": "vesper-01",
        "final_verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "shared_users": ["martin.chen"],
        "shared_hosts": ["ws-martin-01"],
        "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
                        "exfil:cumulative_bytes_anomaly"],
        "_exfil_destinations": {"martin.chen": {"destination": "acme-vesper.io", "cumulative_bytes": 350 * 1024 * 1024}},
    }


def test_validated_breach_scores_critical_not_trace():
    d = assess_dread(_breach()).to_dict()
    # The legacy engine scored this 'trace'; the reengineered one must reflect reality.
    assert d["overall_level"] in {"critical", "high"}
    assert d["overall_score"] >= 6.0


def test_all_five_components_present_with_rationale():
    comps = assess_dread(_breach()).to_dict()["components"]
    for name in ("damage", "reproducibility", "exploitability", "affected", "discoverability"):
        assert name in comps
        assert comps[name].get("rationale")
        assert comps[name].get("score") is not None


def test_exploitability_boosted_for_confirmed_breach():
    d = assess_dread(_breach()).to_dict()
    assert d["components"]["exploitability"]["exploited"] is True
    assert d["components"]["exploitability"]["score"] >= 8
    assert "not theoretical" in d["components"]["exploitability"]["rationale"].lower()


def test_affected_deepdive_is_evidence_grounded():
    aff = assess_dread(_breach()).to_dict()["components"]["affected"]
    assert "martin.chen" in aff["identities"]
    assert "Active Directory" in aff["asset_classes"]
    assert "MB egressed" in aff["data_scope"]        # pulled from exfil evidence
    assert aff["blast_radius"]


def test_drivers_wire_to_actionable_purchases():
    drv = assess_dread(_breach()).to_dict()["drivers"]
    invest = " ".join(drv["investments"]).lower()
    infra = " ".join(drv["infrastructure"]).lower()
    # OAuth + Kerberoast + lateral + exfil must drive concrete buys/changes.
    assert "sspm" in invest or "pam" in invest or "itdr" in invest or "edr" in invest
    assert "microsegmentation" in infra or "consent" in infra or "aes" in infra
    assert drv["improvements"]


def test_reproducibility_and_affected_are_real_not_neutral():
    # The legacy engine hardcoded these; the new one derives them.
    comps = assess_dread(_breach()).to_dict()["components"]
    assert comps["reproducibility"]["score"] >= 6      # kerberoasting is highly reproducible
    assert comps["affected"]["score"] >= 3
