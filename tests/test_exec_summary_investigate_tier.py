"""Verdict surfacing — the corroboration grader downgrades lone-ambiguous clusters to
SUSPECTED_BREACH. They must surface as a distinct 'investigate' tier in the rollup, not
vanish (previously only confirmed breaches were counted)."""
from __future__ import annotations

from src.exec_summary.deep_analysis import _build_deep_rollup


def test_investigate_tier_counted_separately_from_confirmed():
    results = [
        {"synthesis": {"final_verdict": "VALIDATED_BREACH", "confidence": 0.9}},
        {"synthesis": {"final_verdict": "SUSPECTED_BREACH", "confidence": 0.5}},
        {"synthesis": {"final_verdict": "SUSPECTED_BREACH", "confidence": 0.4}},
        {"synthesis": {"final_verdict": "BENIGN_EXPECTED", "confidence": 0.2}},
    ]
    rollup = _build_deep_rollup(results, {})
    assert rollup["confirmed_clusters"] == 1      # the real breach
    assert rollup["investigate_clusters"] == 2    # the two downgraded — visible, not lost


def test_no_investigate_when_all_confirmed_or_benign():
    results = [
        {"synthesis": {"final_verdict": "VALIDATED_BREACH"}},
        {"synthesis": {"final_verdict": "BENIGN_EXPECTED"}},
    ]
    rollup = _build_deep_rollup(results, {})
    assert rollup["investigate_clusters"] == 0
