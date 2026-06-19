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

pytestmark = [
    pytest.mark.acceptance,  # part of the golden acceptance harness
    pytest.mark.skipif(
        not all(dataset_present(s) for s in ("vesper", "meridian", "santos")),
        reason="VESPER/Meridian/Santos datasets not present in this checkout",
    ),
]


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


@pytest.mark.parametrize("scenario", ["vesper", "santos", "meridian"])
def test_red_herrings_suppressed(results, scenario):
    # Phase 2 corroboration grading must keep the red herrings out of confirmed
    # breaches: VESPER's anna (legit upload), Santos's sanctioned pentest. These were
    # FPs before the regrade; lock them suppressed.
    fp = results[scenario]["fp"]
    assert fp == [], f"{scenario}: red herring(s) graded as confirmed breach: {fp}"


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


def test_vesper_exfil_stitches_to_actor(results):
    # THE FINALE: the cumulative <350MB exfil to the lookalike destination
    # (martin-chen.sharepoint.com) now attaches to martin.chen's breach cluster.
    # Entity resolution (host->user) gives the benign-per-row exfil rows an actor, and
    # ChronoGraph (data-time-anchored cumulative per-destination bytes) surfaces the
    # signal that only exists across the batch. The whole kill chain stitches.
    assert results["vesper"]["gaps"]["exfil_stitched_to_actor"] is True, (
        "VESPER exfil no longer stitches to martin.chen — entity resolution or "
        "ChronoGraph cumulative-exfil regressed."
    )


def test_vesper_full_killchain_in_one_campaign(results):
    # The intrusion is a single campaign for martin.chen: oauth -> recon -> kerberoast
    # -> lateral -> powershell, surfaced as the actor's present_phase_ids across the
    # decomposed parent. Was the open full_killchain_one_cluster gap (1 phase visible);
    # the AD-recon + Kerberos detectors + per-actor phase aggregation close it.
    gaps = results["vesper"]["gaps"]
    assert gaps.get("full_killchain_one_cluster") is True, (
        f"martin.chen kill chain fragmented — only {gaps.get('actor_killchain_phases')} "
        f"phases in one campaign (need >=5)")
    assert gaps.get("actor_killchain_phases", 0) >= 5


def test_vesper_red_herrings_not_full_campaigns(results):
    # The detectors must not inflate the red herrings into multi-phase campaigns: the
    # bait users (anna/james/sarah legit RDP, svc_jenkins legacy RC4) must each stay a
    # lone-phase cluster, never picking up the actor's kill chain (over-merge guard).
    herrings = {"anna.kowalski", "james.wright", "sarah.lin", "svc_jenkins"}
    for c in results["vesper"]["_clusters"]:
        users = {str(u).lower() for u in (c.get("shared_users") or c.get("shared_accounts") or [])}
        if users & herrings:
            n = len({p for p in (c.get("present_phase_ids") or []) if p})
            who = sorted(users & herrings)
            assert n <= 2, f"red herring {who} inflated to {n}-phase campaign (over-merge)"
