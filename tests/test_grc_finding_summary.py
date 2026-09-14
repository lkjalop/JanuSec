"""Deterministic 3-paragraph executive summary + attack-complexity (structured-slot
narration foundation). Every fact is projected from computed fields — no LLM."""
import pytest

from src.core.grc.dread import assess_dread
from src.core.grc.finding_summary import build_finding_summary
from src.core.grc.nonconformity import build_finding, build_audit_pack

pytestmark = pytest.mark.acceptance


def _cluster():
    return {
        "cluster_id": "vesper-01", "final_verdict": "VALIDATED_BREACH", "severity": "critical",
        "shared_users": ["martin.chen"], "shared_hosts": ["ws-martin-01"],
        "factor_tags": ["oauth_device_code", "iam:oauth_consent_excessive_scope",
                        "kerberoasting", "wmi_dcom_lateral",
                        "exfil:cumulative_bytes_anomaly", "exfil:cumulative_cloud_bytes_anomaly"],
        "time_window": {"start": 1776825886.0, "end": 1776851665.0, "span_seconds": 25779.0},
        "_exfil_destinations": {"martin.chen": {"destination": "acme-vesper.io", "cumulative_bytes": 350 * 1024 * 1024}},
        "_llm_evidence_refs": [52, 20430, 20431],
    }


def test_attack_complexity_derived():
    ac = assess_dread(_cluster()).to_dict()["attack_complexity"]
    assert ac["level"] in {"low", "medium", "high"}
    assert ac["exploited"] is True
    # kerberoasting (R9) + confirmed-exploit boost (E8) => easy/repeatable => LOW complexity
    assert ac["level"] == "low"
    assert "repeatable" in ac["label"]


def test_three_paragraphs_and_headline():
    f = build_finding(_cluster())
    s = f["summary"]
    assert len(s["paragraphs"]) == 3
    assert "martin.chen" in s["headline"]
    p1, p2, p3 = s["paragraphs"]
    # ¶1 — window, affected, damage, complexity
    assert "Apr" in p1 and "hours" in p1
    assert "martin.chen" in p1 and "asset class" in p1
    assert "MB egressed" in p1
    assert "Attack complexity: LOW" in p1
    # ¶2 — do next, P1
    assert p2.startswith("Do next [P1/")
    assert "OAuth" in p2
    # ¶3 — controls
    assert "Controls affected" in p3 and "ISO27001" in p3


def test_kill_chain_deduped_by_rank():
    # Two OAuth phases + two exfil phases must collapse to one step per kill-chain rank.
    s = build_finding(_cluster())["summary"]
    kc = s["occurred"]["kill_chain"]
    assert sum(1 for step in kc if "OAuth" in step) == 1
    assert sum(1 for step in kc if "exfiltration" in step.lower()) == 1


def test_structured_fields_present():
    s = build_finding(_cluster())["summary"]
    occ = s["occurred"]
    assert occ["affected_identities"] == ["martin.chen"]
    assert "Active Directory" in occ["asset_classes"]
    assert occ["complexity_level"] == "low"
    assert s["do_next"] and s["do_next"][0]["priority"] == "P1"
    assert s["controls_affected"].get("iso27001")


def test_pack_carries_executive_summary_with_gap_denominator():
    pack = build_audit_pack([_cluster()])
    es = pack["executive_summary"]
    assert es["paragraphs"]
    # framework-gap denominator threads into ¶3
    assert "/93 ISO 27001 controls" in es["paragraphs"][2]


def test_evidence_never_dropped_falls_back_to_row_refs():
    # When the narrator didn't populate _llm_evidence_refs, evidence must fall back to
    # the cluster's row_refs — never empty.
    c = _cluster()
    c.pop("_llm_evidence_refs", None)
    c["row_refs"] = list(range(200))
    f = build_finding(c)
    assert f["evidence_rows"], "evidence must not be dropped"
    assert len(f["evidence_rows"]) == 20


def test_affected_hosts_include_chrono_touched_not_just_shared():
    # shared_hosts undercounts; chrono first-seen hosts must be merged in.
    c = _cluster()
    c["shared_hosts"] = ["ws-martin-01"]
    c["_chrono_first_seen"] = {"martin.chen": ["svr-app-02", "svr-db-01", "svr-file-01", "ws-martin-01"]}
    aff = build_finding(c)["dread"]["components"]["affected"]
    assert len(aff["hosts"]) == 4
    assert aff["blast_radius"] == "multi-host campaign"


def test_campaign_window_uses_true_event_span():
    from src.core.grc.nonconformity import build_audit_pack
    c = _cluster()
    c["row_refs"] = [0, 1, 2]
    c["time_window"] = {"start": 1776825886.0, "end": 1776851665.0, "span_seconds": 25779.0}  # 7.2h (wrong)
    rows = [
        {"_ts_epoch": 1776000000.0}, {"_ts_epoch": 1776500000.0}, {"_ts_epoch": 1777300000.0},  # ~15 days
    ]
    pack = build_audit_pack([c], rows=rows)
    win = pack["findings"][0]["window"]
    assert win["span_seconds"] > 25779.0        # corrected past the stale 7.2h
    assert win["span_seconds"] == pytest.approx(1300000.0, rel=0.01)


def test_summary_degrades_without_window():
    c = _cluster()
    c.pop("time_window")
    s = build_finding(c)["summary"]
    # still renders 3 paragraphs, just without the explicit window
    assert len(s["paragraphs"]) == 3
    assert "martin.chen" in s["paragraphs"][0]
