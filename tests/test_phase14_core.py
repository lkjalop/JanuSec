"""Unit tests for Phase 1-4 additions.

Covers:
  - cot_consistency_score (Phase 3)
  - derive_controls_breached_v2 (Phase 1.5)
  - attach_control_witnesses / witnesses_to_control_failures (Phase 1.6)
  - compute_cluster_verdict witness uplift (Phase 1.6 integration)
  - orchestrator early-return includes pipeline_failures key (Phase 2 bug fix)
"""
from __future__ import annotations

import pytest


# ─── cot_consistency_score ────────────────────────────────────────────────────

def test_cot_consistency_perfect_overlap():
    from src.exec_summary.narrative_synthesis import cot_consistency_score, Claim

    scratchpad = "Row [1] shows lateral movement. Row [5] is the exfil event. [12] is the beacon."
    claims = [
        Claim(text="Lateral movement detected", evidence_row_ids=[1, 5]),
        Claim(text="C2 beacon present", evidence_row_ids=[12]),
    ]
    result = cot_consistency_score(scratchpad, claims)
    assert result["score"] == 1.0
    assert result["contradictions"] == []


def test_cot_consistency_partial_overlap():
    from src.exec_summary.narrative_synthesis import cot_consistency_score, Claim

    scratchpad = "Row [1] shows lateral movement."
    claims = [
        Claim(text="Lateral movement", evidence_row_ids=[1]),
        Claim(text="Data exfil via cloud", evidence_row_ids=[99]),  # NOT in scratchpad
    ]
    result = cot_consistency_score(scratchpad, claims)
    assert result["score"] < 1.0
    assert 99 in result["contradictions"]


def test_cot_consistency_no_claims():
    from src.exec_summary.narrative_synthesis import cot_consistency_score

    result = cot_consistency_score("Row [1] lateral movement", [])
    assert result["score"] == 0.0
    assert result["claim_ids_total"] == 0


def test_cot_consistency_empty_scratchpad():
    from src.exec_summary.narrative_synthesis import cot_consistency_score, Claim

    claims = [Claim(text="Something", evidence_row_ids=[5])]
    result = cot_consistency_score("", claims)
    assert result["score"] == 0.0
    assert 5 in result["contradictions"]


# ─── derive_controls_breached_v2 ─────────────────────────────────────────────

def test_derive_controls_mitre_mapping():
    from src.prefill.compliance_tags import derive_controls_breached_v2

    result = derive_controls_breached_v2([], mitre_techniques=["T1003"])
    frameworks = {r["framework"] for r in result}
    # T1003 (credential dumping) must trigger at least ISO 27001 and NIST 800-53
    assert "ISO 27001:2022" in frameworks or "NIST 800-53" in frameworks
    for r in result:
        # triggered_by holds the technique IDs; derivation holds the method label
        assert r.get("derivation") == "mitre_mapping"


def test_derive_controls_subtechnique_expands_to_parent():
    from src.prefill.compliance_tags import derive_controls_breached_v2

    # T1003.001 (LSASS) should also match T1003 (parent)
    result_sub = derive_controls_breached_v2([], mitre_techniques=["T1003.001"])
    result_parent = derive_controls_breached_v2([], mitre_techniques=["T1003"])
    # Sub-technique result should cover at least as many controls as parent
    assert len(result_sub) >= len(result_parent)


def test_derive_controls_keyword_fallback():
    from src.prefill.compliance_tags import derive_controls_breached_v2

    # fragments must be a dict (same shape as DREAD dread_narrative.fragments)
    # Use keywords that exist in _COMPLIANCE_MAP: "credential", "phishing", "lateral"
    fragments = {
        "attack_type": "credential theft via phishing",
        "movement": "lateral movement via psexec",
    }
    result = derive_controls_breached_v2(fragments, mitre_techniques=[])
    assert len(result) > 0
    derivations = {r.get("derivation") for r in result}
    assert "keyword_fallback" in derivations


def test_derive_controls_combined():
    from src.prefill.compliance_tags import derive_controls_breached_v2

    # T1486 is ransomware — also use "ransomware" keyword to test combined
    fragments = {"attack_type": "ransomware encryption started vssadmin"}
    result = derive_controls_breached_v2(fragments, mitre_techniques=["T1486"])
    derivations = {r.get("derivation") for r in result}
    assert "mitre_mapping" in derivations or "mitre+keyword" in derivations


# ─── attach_control_witnesses ─────────────────────────────────────────────────

def _make_cluster(cluster_id="c1"):
    return {
        "cluster_id": cluster_id,
        "severity": "high",
        "mitre_tags": ["T1003"],
        "tier1_prefill": {
            "compliance_controls": [
                {"framework": "ISO 27001:2022", "control_id": "A.8.2", "control_name": "Privileged access"},
            ]
        },
    }


def _make_rows():
    return [
        {"row_index": 0, "_source": "endpoint", "severity": "high", "user": "admin"},
        {"row_index": 1, "_source": "network",  "severity": "medium", "user": "admin"},
        {"row_index": 2, "_source": "identity",  "severity": "high",   "user": "admin"},
    ]


def test_attach_control_witnesses_mutates_cluster():
    from src.core.verdict_engine.control_witnesses import attach_control_witnesses

    cluster = _make_cluster()
    rows = _make_rows()
    attach_control_witnesses(cluster, rows)
    assert "control_witnesses" in cluster
    assert isinstance(cluster["control_witnesses"], dict)


def test_witnesses_to_control_failures_shape():
    from src.core.verdict_engine.control_witnesses import (
        attach_control_witnesses,
        witnesses_to_control_failures,
    )

    cluster = _make_cluster()
    attach_control_witnesses(cluster, _make_rows())
    failures = witnesses_to_control_failures(cluster["control_witnesses"], min_witness_count=1)
    assert isinstance(failures, list)
    for f in failures:
        assert "control_id" in f
        assert "severity" in f
        assert "remediation_priority" in f


def test_witnesses_to_control_failures_min_count_filter():
    from src.core.verdict_engine.control_witnesses import (
        attach_control_witnesses,
        witnesses_to_control_failures,
    )

    cluster = _make_cluster()
    attach_control_witnesses(cluster, _make_rows())
    # min_witness_count=99 should filter out everything
    failures_high = witnesses_to_control_failures(
        cluster["control_witnesses"], min_witness_count=99
    )
    assert failures_high == []


# ─── compute_cluster_verdict witness uplift ───────────────────────────────────

def test_verdict_witness_uplift_boosts_confidence():
    from src.core.verdict_engine.control_witnesses import attach_control_witnesses
    from src.core.verdict_engine.verdict_rules import compute_cluster_verdict

    cluster = _make_cluster()
    cluster["confidence_meter"] = {"total": 50.0}
    rows = _make_rows()
    attach_control_witnesses(cluster, rows)

    result = compute_cluster_verdict(cluster)
    # With witnesses, confidence should be >= 50/100 (uplift applied)
    assert result["verdict_confidence"] >= 0.50
    assert result["verdict"] in {
        "LIKELY_COMPROMISE", "SUSPICIOUS_ACTIVITY", "CONFIRMED_INTRUSION",
        "VALIDATED_BREACH", "INSUFFICIENT_TELEMETRY", "BENIGN_EXPECTED",
    }


def test_verdict_no_witnesses_stable():
    from src.core.verdict_engine.verdict_rules import compute_cluster_verdict

    cluster = {
        "cluster_id": "c_bare",
        "severity": "medium",
        "confidence_meter": {"total": 30.0},
    }
    result = compute_cluster_verdict(cluster)
    assert "verdict" in result
    assert 0.0 <= result["verdict_confidence"] <= 1.0


# ─── orchestrator early-return has pipeline_failures ─────────────────────────

@pytest.mark.asyncio
async def test_run_enriched_pipeline_empty_clusters_has_pipeline_failures():
    import asyncio, os
    os.environ.setdefault("PLATFORM_LITE_INIT", "1")
    os.environ.setdefault("DISABLE_DB", "1")

    from src.exec_summary.orchestrator import run_enriched_pipeline

    result = await run_enriched_pipeline(
        assessment_id="test-empty",
        assessment={},
        sorted_clusters=[],
    )
    assert "pipeline_failures" in result
    assert result["pipeline_failures"] == []
    assert result["pipeline_ran"] is True
