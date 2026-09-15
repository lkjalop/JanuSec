"""#3 Bitemporal provenance on findings: valid_time (when the evidence was true) vs
transaction_time (when JanuSec decided) — reconstructable, defensible AI decisions."""
import pytest

from src.core.grc.nonconformity import build_audit_pack

pytestmark = pytest.mark.acceptance

_TT = "2026-07-06T00:00:00+00:00"


def _cluster():
    return {"cluster_id": "c1", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
            "shared_users": ["martin.chen"], "factor_tags": ["kerberoasting", "exfil:cumulative_bytes_anomaly"],
            "time_window": {"start": 1776087462.0, "end": 1777408963.0, "span_seconds": 1321501.0},
            "_llm_evidence_refs": [1, 2, 3]}


def test_finding_carries_bitemporal_provenance():
    pack = build_audit_pack([_cluster()], transaction_time=_TT)
    p = pack["findings"][0]["provenance"]
    assert p["decision_id"].startswith("dec-")
    assert p["transaction_time"] == _TT
    assert p["valid_time"]["from"].startswith("2026-04")   # when the evidence was true
    assert p["valid_time"]["to"]
    assert len(p["evidence_content_hash"]) == 64


def test_decision_id_deterministic():
    a = build_audit_pack([_cluster()], transaction_time=_TT)["findings"][0]["provenance"]
    b = build_audit_pack([_cluster()], transaction_time=_TT)["findings"][0]["provenance"]
    assert a["decision_id"] == b["decision_id"]


def test_valid_and_transaction_time_are_distinct_axes():
    p = build_audit_pack([_cluster()], transaction_time=_TT)["findings"][0]["provenance"]
    # valid_time (evidence, April) is a different axis from transaction_time (decision, July)
    assert p["valid_time"]["from"][:7] != p["transaction_time"][:7]
