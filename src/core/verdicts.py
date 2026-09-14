"""Canonical verdict taxonomy — the single source of truth for breach / flagged /
autoblock verdict-class membership across the platform.

Historically this membership was re-declared independently in at least four places
with divergent contents (the two report-aggregation loops, the ground-truth gate,
and the Tier-1 verdict engine). That drift is exactly how a CONFIRMED BREACH decision
was silently dropped from a report: one aggregation loop's "flagged" set omitted the
breach verdicts, so every framework rollup (kill_chain / stride / maestro / dread)
came back empty for the very thing the platform exists to surface.

Any code that needs to decide "is this verdict a breach / does it belong in the
flagged list / is it an autoblock" MUST use the constants and predicates here.

Casing note: verdicts appear both UPPERCASE (verdict_engine, ground_truth_gate) and
lowercase (report_aggregation decision records). The predicates normalise case, so
callers may pass either form.

Out of scope: `src/artifact/models.Verdict` is a SEPARATE taxonomy (artifact / binary
scanning: GOOD / CONTROLLED / PUA / SUSPICIOUS / MALICIOUS / UNKNOWN) and is
intentionally not merged here — it describes a file's disposition, not an incident
decision.
"""
from __future__ import annotations

from typing import Any

# Two distinct concepts that were historically conflated:
#
#   1. CONFIRMED_BREACH_VERDICTS — a *strong assertion* that a breach / compromise /
#      confirmed intrusion occurred. This is the set used for ground-truth TP/FP
#      grading: a red herring landing here is a real false positive. Note that
#      SUSPECTED_BREACH is deliberately NOT here — "suspected" is a weaker signal, so
#      a red herring at "suspected" is acceptable, not an FP.
#
#   2. FLAGGED_VERDICTS — anything that belongs in a report's "needs attention" list,
#      which is broader and DOES include SUSPECTED_BREACH plus the triage verdicts.
#
# Canonical UPPERCASE form.
CONFIRMED_BREACH_VERDICTS: frozenset[str] = frozenset({
    "VALIDATED_BREACH",
    "CONFIRMED_BREACH",
    "CONFIRMED_INTRUSION",
    "LIKELY_BREACH",
    "LIKELY_COMPROMISE",
    "INCIDENT",
})

# Lower-confidence verdicts that still warrant surfacing in a report's flagged list
# but are not, on their own, confirmed-breach assertions. SUSPECTED_BREACH lives here.
TRIAGE_VERDICTS: frozenset[str] = frozenset({
    "SUSPECTED_BREACH",
    "REVIEW",
    "ESCALATE",
    "SUSPICIOUS",
    "REQUIRES_INVESTIGATION",
    "INVESTIGATION_REQUIRED",
})

# Everything that belongs in a report's "flagged / needs attention" list.
FLAGGED_VERDICTS: frozenset[str] = CONFIRMED_BREACH_VERDICTS | TRIAGE_VERDICTS

# Verdicts that make a cluster breach-worthy for NARRATION / action-seeding — the
# confirmed breaches PLUS the weaker SUSPECTED_BREACH (a suspected breach still gets a
# narrative and proposed actions, even though it is not graded as a confirmed FP-able
# breach). Used by the ingest worker's breach-cluster gate.
NARRATABLE_BREACH_VERDICTS: frozenset[str] = CONFIRMED_BREACH_VERDICTS | {"SUSPECTED_BREACH"}

# Verdicts indicating an automated block / malicious auto-decision.
AUTOBLOCK_VERDICTS: frozenset[str] = frozenset({
    "BLOCK",
    "MALICIOUS",
    "AUTOBLOCK",
    "AUTO_BLOCK",
})

# Minimum displayed confidence consistent with a verdict. A verdict and its confidence
# must never contradict each other: a VALIDATED_BREACH shown at 0.55 reads as incoherent
# ("you validated it but you're barely sure?") and destroys trust — the whole product
# for a compromise-assessment buyer. A deterministic breach verdict is phase-detector-
# backed, so the displayed confidence is floored to match the verdict rather than letting
# the LLM's low self-rating drag it below its own threshold. Values mirror the Tier-1
# verdict-engine gates (confirmed >= 0.75, likely >= 0.55).
_CONFIDENCE_FLOORS: dict[str, float] = {
    "VALIDATED_BREACH": 0.75,
    "CONFIRMED_BREACH": 0.75,
    "CONFIRMED_INTRUSION": 0.75,
    "INCIDENT": 0.75,
    "LIKELY_BREACH": 0.55,
    "LIKELY_COMPROMISE": 0.55,
    "SUSPECTED_BREACH": 0.50,
}


def confidence_floor(verdict: Any) -> float:
    """Minimum confidence consistent with the verdict (0.0 if none applies)."""
    return _CONFIDENCE_FLOORS.get(normalize(verdict), 0.0)


def normalize(verdict: Any) -> str:
    """Canonical comparison form: trimmed UPPERCASE string ('' for None)."""
    return str(verdict or "").strip().upper()


def is_breach(verdict: Any) -> bool:
    """True if the verdict is a *confirmed* breach / compromise / intrusion assertion
    (strict — excludes the weaker SUSPECTED_BREACH). Use for TP/FP grading."""
    return normalize(verdict) in CONFIRMED_BREACH_VERDICTS


def is_flagged(verdict: Any) -> bool:
    """True if the verdict belongs in a report's flagged / needs-attention list."""
    return normalize(verdict) in FLAGGED_VERDICTS


def is_autoblock(verdict: Any) -> bool:
    """True if the verdict indicates an automated block / malicious auto-decision."""
    return normalize(verdict) in AUTOBLOCK_VERDICTS
