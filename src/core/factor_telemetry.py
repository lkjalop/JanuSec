"""Factor telemetry + tuning advice — the analyst-toil-reduction data layer.

`compute_factor_telemetry` turns the runtime's per-factor TP/FP counts into precision /
noise stats (Horizon-2 #5, the data the drawer renders). `tuning_advice` consumes those
stats to recommend concrete tuning (#6: "this factor is noisy -> lower weight / require
corroboration"). Both are pure functions so they're trivially testable and reusable by
the report, the personas, and any future tuning UI.

Business outcome: quantifiable analyst-time saved — surface which factors waste triage,
and tell the operator exactly what to do about it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any

# A factor needs at least this many observations before we judge it noisy (avoid
# penalising a factor on 1-2 samples).
_MIN_SAMPLE = int(os.getenv("JANUSEC_FACTOR_TUNING_MIN_SAMPLE", "10"))
# FP ratio above which a factor is "noisy" enough to recommend tuning.
_NOISY_FP_RATIO = float(os.getenv("JANUSEC_FACTOR_NOISY_FP_RATIO", "0.5"))
# FP ratio above which corroboration should be required (very noisy).
_REQUIRE_CORROBORATION_RATIO = float(os.getenv("JANUSEC_FACTOR_CORROBORATION_RATIO", "0.7"))


@dataclass
class FactorStat:
    factor: str
    occurrences: int          # total times the factor fired
    fp_count: int             # of those, how many were labelled false positive
    fp_ratio: float           # fp_count / occurrences
    precision: float          # (occurrences - fp_count) / occurrences
    is_noisy: bool            # enough sample AND fp_ratio over threshold

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_factor_telemetry(
    factors: list[str],
    total_counts: dict[str, int],
    fp_counts: dict[str, int],
) -> list[FactorStat]:
    """Per-factor precision/noise for the given factors, from the runtime TP/FP counts.
    Sorted worst-precision-first (the factors most worth tuning)."""
    stats: list[FactorStat] = []
    seen: set[str] = set()
    for f in factors:
        f = str(f)
        if f in seen:
            continue
        seen.add(f)
        total = int(total_counts.get(f, 0) or 0)
        if total <= 0:
            continue
        fp = min(int(fp_counts.get(f, 0) or 0), total)
        fp_ratio = fp / total
        stats.append(FactorStat(
            factor=f,
            occurrences=total,
            fp_count=fp,
            fp_ratio=round(fp_ratio, 3),
            precision=round((total - fp) / total, 3),
            is_noisy=(total >= _MIN_SAMPLE and fp_ratio >= _NOISY_FP_RATIO),
        ))
    stats.sort(key=lambda s: (s.precision, -s.occurrences))
    return stats


def tuning_advice(stats: list[FactorStat]) -> list[dict[str, Any]]:
    """Concrete tuning recommendations for the noisy factors (#6 advisor). Each item:
    {factor, severity, recommendation, rationale, metric}."""
    advice: list[dict[str, Any]] = []
    for s in stats:
        if not s.is_noisy:
            continue
        if s.fp_ratio >= _REQUIRE_CORROBORATION_RATIO:
            rec = "Require corroboration (don't alert on this factor alone)"
            sev = "high"
        else:
            rec = "Lower this factor's weight"
            sev = "medium"
        advice.append({
            "factor": s.factor,
            "severity": sev,
            "recommendation": rec,
            "rationale": (f"{int(s.fp_ratio * 100)}% of {s.occurrences} firings were "
                          f"false positives (precision {s.precision:.2f})."),
            "metric": {"occurrences": s.occurrences, "fp_ratio": s.fp_ratio, "precision": s.precision},
        })
    return advice
