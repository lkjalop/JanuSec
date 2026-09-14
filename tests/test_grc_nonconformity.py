"""GRC combine: breach finding -> auditable Nonconformity.

Locks the differentiators: DREAD-derived priority (not LLM-chosen), grounded
per-phase remediation, control-ref bridging across both factor vocabularies, and a
clean audit-pack export.
"""
import pytest

from src.core.grc.nonconformity import (
    build_audit_pack,
    build_nonconformities,
    dread_priority,
)

pytestmark = pytest.mark.acceptance


def _breach_cluster():
    return {
        "cluster_id": "vesper-attack-01",
        "final_verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "shared_users": ["martin.chen"],
        "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
                        "exfil:cumulative_bytes_anomaly"],
        "_llm_evidence_refs": [52, 20430, 20431],
    }


def test_dread_priority_is_deterministic():
    assert dread_priority("critical") == ("P1", 24)
    assert dread_priority("high") == ("P1", 48)
    assert dread_priority("medium") == ("P2", 168)
    assert dread_priority("low") == ("P3", 720)
    assert dread_priority("nonsense") == ("P3", 720)


def test_breach_produces_grounded_ncs():
    ncs = build_nonconformities(_breach_cluster())
    assert ncs, "a breach must yield at least one Nonconformity"
    # priority is DREAD-derived and uniform across the finding's NCs
    assert all(nc["priority"] in {"P1", "P2"} for nc in ncs)
    assert all(nc["dread_level"] in {"critical", "high", "medium"} for nc in ncs)
    # remediation is grounded (names the specific control action), not generic
    joined = " ".join(nc["remediation"].lower() for nc in ncs)
    assert "oauth" in joined and ("kerberoast" in joined or "krbtgt" in joined)
    # each NC carries evidence, an owner, and MITRE
    for nc in ncs:
        assert nc["owner"]
        assert nc["evidence_rows"] == [52, 20430, 20431]
        assert any(m.startswith("T") for m in nc["mitre"])


def test_control_refs_bridge_phase_vocabulary():
    ncs = build_nonconformities(_breach_cluster())
    all_iso = {c for nc in ncs for c in (nc["control_refs"].get("iso27001") or [])}
    # OAuth phase must map to identity-access controls even though its phase-id
    # ('oauth_device_code') is NOT a factor_to_compliance key.
    assert "A.5.15" in all_iso
    assert any(nc["control_refs"].get("soc2") for nc in ncs)


def test_non_breach_yields_no_nc():
    benign = {"cluster_id": "c", "final_verdict": "BENIGN_EXPECTED", "factor_tags": []}
    assert build_nonconformities(benign) == []


def test_remediation_dedup():
    # Duplicate phases must not produce duplicate corrective actions.
    c = _breach_cluster()
    c["factor_tags"] = ["oauth_device_code", "oauth_device_code", "kerberoasting"]
    ncs = build_nonconformities(c)
    remediations = [nc["remediation"] for nc in ncs]
    assert len(remediations) == len(set(remediations))


def test_audit_pack_structure():
    pack = build_audit_pack([_breach_cluster()])
    assert pack["summary"]["total_ncs"] >= 1
    assert "iso27001" in pack["summary"]["frameworks"]
    assert pack["summary"]["p1_count"] >= 1
    # control_coverage indexes controls back to the NCs that violate them
    iso = pack["control_coverage"].get("iso27001") or {}
    assert any(nc_ids for nc_ids in iso.values())
