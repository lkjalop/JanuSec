"""End-to-end clustering regression gate (pytest wrapper around scripts/e2e_assess.py).

Marked `slow` — it parses + clusters the full Vesper/Meridian/Santos datasets (~40s).
Skipped automatically when the datasets or the golden baseline are absent, so it never
breaks a checkout that lacks the (large, un-versioned) sample data.

This is the structural guard the unit tests could not provide: it asserts whole-pipeline
invariants — merge version, zero empty-entity clusters (the over-merge smell), full
evidence retention — on real data, the exact class of bug that shipped before.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

DATA = ROOT / "dump" / "test files"
BASELINE = ROOT / "tests" / "fixtures" / "e2e_golden_baseline.json"

pytestmark = pytest.mark.slow

_data_present = (DATA / "Santos").exists() and (DATA / "Vesper").exists()
requires_data = pytest.mark.skipif(
    not (_data_present and BASELINE.exists()),
    reason="e2e datasets or golden baseline not present",
)


@requires_data
def test_e2e_clustering_matches_baseline():
    import json
    import e2e_assess  # type: ignore

    current = e2e_assess.run_all()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    failures = e2e_assess.compare(current, baseline)
    assert not failures, "E2E clustering regressed:\n" + "\n".join(failures)


@requires_data
def test_no_over_merge_empty_entity_clusters():
    """Hard invariant: no actionable cluster may have zero shared entities.

    A 2,696-row entity-less mega-component (CloudTrail over-merge) is exactly what
    this catches — it must never return.
    """
    import e2e_assess  # type: ignore

    result = e2e_assess.run_all()
    for scen, m in result["scenarios"].items():
        assert m["empty_entity_clusters"] == 0, (
            f"{scen}: {m['empty_entity_clusters']} cluster(s) with no shared entity "
            f"— over-merge / normalization regression"
        )
