"""Factor telemetry + tuning advice (Horizon-2 #5/#6) — the analyst-toil data layer."""
from __future__ import annotations

import pytest

from src.core.factor_telemetry import compute_factor_telemetry, tuning_advice

pytestmark = pytest.mark.acceptance


def test_precision_and_noise_computed():
    # factor 'noisy' fired 100x, 80 FP -> precision .20, noisy; 'clean' 50x, 1 FP -> .98
    stats = compute_factor_telemetry(
        ["noisy", "clean"],
        total_counts={"noisy": 100, "clean": 50},
        fp_counts={"noisy": 80, "clean": 1},
    )
    by = {s.factor: s for s in stats}
    assert by["noisy"].precision == 0.2 and by["noisy"].is_noisy
    assert by["clean"].precision == 0.98 and not by["clean"].is_noisy
    # worst precision first
    assert stats[0].factor == "noisy"


def test_low_sample_not_flagged_noisy():
    # 3 firings all FP -> high fp_ratio but below min sample, so NOT flagged (avoid
    # penalising on tiny evidence).
    stats = compute_factor_telemetry(["rare"], {"rare": 3}, {"rare": 3})
    assert stats[0].fp_ratio == 1.0 and not stats[0].is_noisy


def test_factors_with_no_history_are_skipped():
    stats = compute_factor_telemetry(["unknown"], total_counts={}, fp_counts={})
    assert stats == []


def test_tuning_advice_escalates_with_noise():
    stats = compute_factor_telemetry(
        ["very_noisy", "noisy", "clean"],
        {"very_noisy": 100, "noisy": 100, "clean": 100},
        {"very_noisy": 85, "noisy": 55, "clean": 2},
    )
    advice = {a["factor"]: a for a in tuning_advice(stats)}
    assert "clean" not in advice                      # clean factors get no advice
    assert "corroboration" in advice["very_noisy"]["recommendation"].lower()
    assert advice["very_noisy"]["severity"] == "high"
    assert "weight" in advice["noisy"]["recommendation"].lower()
    assert advice["noisy"]["severity"] == "medium"


def test_soc_renders_factor_telemetry_drawer():
    # The drawer + advisor surface in the analyst (SOC) report.
    from src.reporting.comprehensive_report_generator import _build_soc_page
    p = {"rows": [], "meta": {"verdict": "VALIDATED_BREACH"},
         "factor_telemetry": [{"factor": "dns:tunnel_suspected", "occurrences": 100,
                               "fp_ratio": 0.8, "precision": 0.2, "is_noisy": True}],
         "tuning_advice": [{"factor": "dns:tunnel_suspected", "severity": "high",
                            "recommendation": "Require corroboration (don't alert on this factor alone)",
                            "rationale": "80% of 100 firings were false positives (precision 0.20)."}]}
    html = _build_soc_page(p, p["meta"], {}, "s", "Acme", "2026-01-01").lower()
    assert "factor telemetry" in html and "tuning advisor" in html
    assert "dns:tunnel_suspected" in html and "corroboration" in html
