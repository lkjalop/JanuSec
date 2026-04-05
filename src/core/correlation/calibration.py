"""Calibration helpers for correlation rules.

This module exposes a simple function `suggest_threshold_adjustments` which
consumes per-rule FP/TP metrics and returns a list of suggested adjustments.
It is intentionally lightweight so it can be called from a scheduled job or
an admin endpoint.
"""
from typing import Dict, List
from src.core.correlation.rules.registry import CORRELATION_RULES


def suggest_threshold_adjustments(min_support: int = 5) -> List[Dict[str, object]]:
    """Return suggested adjustments based on FP/TP ratios.

    For rules with low support (< min_support) no change is suggested.
    Otherwise we compute fp_rate = fp/(fp+tp) and suggest a small delta.
    """
    metrics = CORRELATION_RULES.get_metrics()
    suggestions = []
    for rule, vals in metrics.items():
        fp = int(vals.get('fp', 0))
        tp = int(vals.get('tp', 0))
        support = fp + tp
        if support < min_support:
            continue
        fp_rate = fp / support if support else 0.0
        # simple policy: if fp_rate > 0.5 suggest lowering confidence by 0.05
        delta = 0.0
        if fp_rate > 0.6:
            delta = -0.05
        elif fp_rate < 0.2:
            delta = 0.03
        if delta != 0.0:
            suggestions.append({
                "rule": rule,
                "fp_rate": fp_rate,
                "support": support,
                "suggested_confidence_delta": delta
            })
    return suggestions


def persist_suggestions_to_file(suggestions: List[Dict[str, object]], path: str = "data/calibration_suggestions.json") -> None:
    import json, pathlib
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(suggestions, indent=2))
