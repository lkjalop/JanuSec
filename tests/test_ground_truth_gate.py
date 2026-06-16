"""Ground-truth gate tests — assert detection correctness, ratchet the known gaps.

Phase 0 of the entity-resolution roadmap. This replaces 'did clustering move?' with
'is the right breach detected, the exfil stitched, the red herrings suppressed?'.

Design:
  - HARD assert what already works (martin.chen breach + entry-point; Meridian clean).
    These must never regress.
  - RATCHET the known gaps (FP network breaches) — they may only go DOWN. When Phase 2
    drives them to 0, tighten the baseline here and the improvement is locked in.
  - The exfil-stitched gap (currently False) is the Phase-2 target; tracked, not yet
    asserted True. Flipping it to True is the proof the entity layer works.

Run scripts/ground_truth_gate.py to see the full truth delta.
"""
from __future__ import annotations

import pytest

from scripts.ground_truth_gate import evaluate, dataset_present

pytestmark = pytest.mark.skipif(
    not all(dataset_present(s) for s in ("vesper", "meridian", "santos")),
    reason="VESPER/Meridian/Santos datasets not present in this checkout",
)


@pytest.fixture(scope="module")
def results():
    return {s: evaluate(s) for s in ("vesper", "meridian", "santos")}


# ── What already works — must never regress ──────────────────────────────────
def test_vesper_martin_chen_breach_detected_with_entry_point(results):
    tp = results["vesper"]["tp"]
    martin = next((t for t in tp if t["actor"] == "martin.chen"), None)
    assert martin is not None, "VESPER: martin.chen breach no longer detected (REGRESSION)"
    assert martin["verdict"] == "VALIDATED_BREACH"
    assert martin["entry_point_ok"] is True, "OAuth consent entry-point attribution regressed"


def test_meridian_stays_clean_positive_control(results):
    # Meridian is identity-rich and already clean. It is the positive control: the
    # entity-layer refactor (Phase 1-2) must NOT introduce no-user breach noise here.
    assert results["meridian"]["gaps"]["fp_network_breaches"] == 0


# ── Known gaps — ratchet (may only improve) ──────────────────────────────────
# Phase 1 (entity resolution) backfilled host->owner, eliminating VESPER's no-user
# network 'breaches' (4 -> 0, now LOCKED). Santos still 4 (its no-user clusters are
# IP-only network rows that host->owner can't reach — needs ip->owner / Phase 2 grading).
_FP_NETWORK_BREACH_BASELINE = {"vesper": 0, "santos": 4, "meridian": 0}


@pytest.mark.parametrize("scenario", ["vesper", "santos", "meridian"])
def test_no_false_network_breach_regression(results, scenario):
    got = results[scenario]["gaps"]["fp_network_breaches"]
    assert got <= _FP_NETWORK_BREACH_BASELINE[scenario], (
        f"{scenario}: no-identity 'breach' clusters rose to {got} "
        f"(baseline {_FP_NETWORK_BREACH_BASELINE[scenario]}) — verdict grading regressed"
    )


def test_vesper_exfil_stitch_gap_is_tracked(results):
    # PHASE-2 TARGET: this must become True once host->user entity resolution attaches
    # the cumulative exfil rows to martin.chen's cluster. Tracked here so the fix is
    # measurable against truth; not yet asserted True (that's the point of Phase 1-2).
    stitched = results["vesper"]["gaps"].get("exfil_stitched_to_actor")
    assert stitched is False, (
        "VESPER exfil now stitches to the actor — Phase 2 worked! "
        "Flip this assertion to `is True` and update the roadmap."
    )
