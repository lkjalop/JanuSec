"""Cost Estimator Utility

Provides rough estimation for hunt or pipeline sidecar runs.
Uses rolling averages from FinOpsManager daily/hourly summaries.
"""
from __future__ import annotations
from .finops_manager import get_finops_manager
from typing import Dict, Any
import statistics

def estimate_hunt_cost(window_hours: int, tenant: str, model_enabled: bool = False) -> Dict[str, Any]:
    fm = get_finops_manager()
    # Simplistic placeholder stats: derive average hourly spend for tenant
    hs = fm.hourly_summary(tenant)
    hours = hs.get('hours', [])
    # Fallback constants
    avg_events = 8000  # placeholder events per hour
    fusion_density = 0.002
    model_ratio = 0.1 if model_enabled else 0.0

    # Derive approximate cost per 1K events from historical cost pattern if any
    cost_per_1k = 1.0
    if hours:
        # Assume previous cost mostly from base events
        total_cost = sum(h['cost_units'] for h in hours)
        total_hours = len({h['hour'] for h in hours}) or 1
        observed_hourly_cost = total_cost / total_hours
        # With assumed events/hour -> cost/1k events
        cost_per_1k = (observed_hourly_cost / (avg_events/1000)) if avg_events else 1.0

    events_est = avg_events * window_hours
    fusion_candidates = int(events_est * fusion_density)
    model_calls = int(fusion_candidates * model_ratio)

    C_f = 0.05  # cost per fusion candidate (abstract)
    C_m = 0.5   # cost per model summarization call

    base = (events_est/1000)*cost_per_1k
    fusion_cost = fusion_candidates * C_f
    model_cost = model_calls * C_m
    total = base + fusion_cost + model_cost
    # Adaptive margin using hourly variance (coefficient of variation)
    if hours:
        hour_costs = [h['cost_units'] for h in hours]
        if len(hour_costs) >= 4 and any(c > 0 for c in hour_costs):
            mean_c = sum(hour_costs)/len(hour_costs)
            # sample stdev; guard for zero mean
            try:
                stdev_c = statistics.stdev(hour_costs)
            except Exception:
                stdev_c = 0.0
            cv = (stdev_c/mean_c) if mean_c > 0 else 0.0
            if cv < 0.2:
                margin_pct = 0.10
                conf = 'high'
            elif cv < 0.5:
                margin_pct = 0.15
                conf = 'medium'
            else:
                margin_pct = 0.25
                conf = 'low'
        else:
            margin_pct = 0.15
            conf = 'medium'
    else:
        margin_pct = 0.25
        conf = 'low'
    margin = total * margin_pct
    return {
        'window_hours': window_hours,
        'events_estimate': events_est,
        'fusion_candidates_estimate': fusion_candidates,
        'model_calls_estimate': model_calls,
        'cost_units_estimate': round(total,2),
        'error_margin_units': round(margin,2),
        'confidence': conf
    }
