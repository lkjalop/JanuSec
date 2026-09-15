"""Canonical verdict-taxonomy guard (Phase 0.2 / 1.3).

Regression cover for the class of bug where a report-aggregation loop used a
hand-rolled verdict set that omitted the breach verdicts, silently dropping a
CONFIRMED BREACH from the report. All verdict-class membership now lives in
src/core/verdicts.py; these tests fail if it drifts or if a consumer re-rolls
its own set.
"""
import inspect

import pytest

from src.core.verdicts import (
    CONFIRMED_BREACH_VERDICTS,
    FLAGGED_VERDICTS,
    is_autoblock,
    is_breach,
    is_flagged,
)

pytestmark = pytest.mark.acceptance


def test_every_confirmed_breach_verdict_is_flagged():
    # The exact regression: a confirmed-breach verdict must always surface in a report.
    for v in CONFIRMED_BREACH_VERDICTS:
        assert is_flagged(v), f"{v} breach verdict missing from FLAGGED_VERDICTS"
    assert CONFIRMED_BREACH_VERDICTS <= FLAGGED_VERDICTS


def test_case_insensitive_and_accepts_both_forms():
    assert is_flagged("validated_breach") and is_flagged("VALIDATED_BREACH")
    assert is_breach("likely_breach") and is_breach("INCIDENT")


def test_suspected_breach_is_flagged_but_not_a_confirmed_breach():
    # "suspected" surfaces in the report but is not a confirmed-breach assertion,
    # so a red herring landing here is not graded as a false positive.
    assert is_flagged("suspected_breach")
    assert not is_breach("suspected_breach")


def test_malicious_is_autoblock_not_flagged():
    assert is_autoblock("malicious") and is_autoblock("block")
    assert not is_flagged("malicious")   # autoblock lane, not the flagged list
    assert not is_autoblock("escalate")  # escalate is triage, not an autoblock


def test_benign_and_empty_are_neither():
    for v in ("benign", "", None, "unknown"):
        assert not is_flagged(v) and not is_breach(v) and not is_autoblock(v)


def test_report_aggregation_loops_use_canonical_predicate():
    """Both aggregation loops must call the canonical predicate, and the old
    hand-rolled breach tuple must be gone — the drift that caused the bug."""
    import src.api.report_aggregation as ra

    src_txt = inspect.getsource(ra)
    assert src_txt.count("is_flagged(verdict)") >= 2, "a loop still hand-rolls its flagged set"
    assert src_txt.count("is_autoblock(verdict)") >= 2
    # the specific narrow/hand-rolled sets that caused the divergence are gone
    assert "'suspicious', 'review', 'malicious', 'escalate'" not in src_txt
    assert "'validated_breach', 'likely_breach', 'likely_compromise'" not in src_txt
