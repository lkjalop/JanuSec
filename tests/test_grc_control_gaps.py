"""ISO 27001 / SOC 2 per-control gap scoring (G2)."""
import pytest

from src.core.grc.control_gaps import build_control_gaps, FRAMEWORK_TOTALS
from src.core.grc.nonconformity import build_audit_pack

pytestmark = pytest.mark.acceptance


def _breach():
    return {
        "cluster_id": "c1", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
        "shared_users": ["martin.chen"],
        "factor_tags": ["oauth_device_code", "kerberoasting", "wmi_dcom_lateral",
                        "exfil:cumulative_bytes_anomaly"],
        "_llm_evidence_refs": [1, 2, 3],
    }


def test_control_gaps_grade_severity_and_name():
    pack = build_audit_pack([_breach()])
    cg = pack["control_gaps"]
    iso = cg["gaps"].get("iso27001", {})
    assert "A.5.15" in iso
    rec = iso["A.5.15"]
    assert rec["status"] == "candidate"
    assert rec["name"] == "Access control"          # human-readable
    assert rec["severity"] in {"critical", "high", "medium"}
    assert rec["finding_count"] >= 1


def test_framework_summary_has_honest_denominator():
    pack = build_audit_pack([_breach()])
    summ = pack["control_gaps"]["summary"]["iso27001"]
    assert summ["total_controls"] == FRAMEWORK_TOTALS["iso27001"] == 93
    assert summ["controls_failing"] == 0
    assert 0 < summ["controls_requiring_review"] <= 93
    assert summ["gap_pct"] is None
    assert summ["candidate_reference_pct"] is not None
    assert summ["worst_severity"] in {"critical", "high", "medium"}


def test_gaps_promoted_to_pack_summary():
    pack = build_audit_pack([_breach()])
    assert "framework_gaps" in pack["summary"]
    assert "iso27001" in pack["summary"]["framework_gaps"]


def test_no_breach_no_gaps():
    pack = build_audit_pack([{"cluster_id": "b", "final_verdict": "BENIGN_EXPECTED", "factor_tags": []}])
    assert pack.get("control_gaps", {}).get("summary", {}) == {}
