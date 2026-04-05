from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = Gauge = None  # type: ignore

baseline_events_total = None
baseline_intel_match_total = None
baseline_intel_match_ratio = None

def init():  # idempotent
    global baseline_events_total, baseline_intel_match_total, baseline_intel_match_ratio
    if baseline_events_total is not None:
        return
    if Counter and Gauge:
        try:
            baseline_events_total = Counter('baseline_events_total','Total baseline module invocations')  # type: ignore
            baseline_intel_match_total = Counter('baseline_intel_match_total','Baseline events with threat intel matches')  # type: ignore
            baseline_intel_match_ratio = Gauge('baseline_intel_match_ratio','Ratio of baseline events with threat intel matches')  # type: ignore
        except Exception:
            baseline_events_total = baseline_intel_match_total = baseline_intel_match_ratio = None

def observe(event_had_intel: bool):
    if baseline_events_total is None:
        return
    try:
        baseline_events_total.inc()
        if event_had_intel:
            baseline_intel_match_total.inc()
        # Update ratio conservatively (avoid division by zero)
        total = baseline_events_total._value.get()  # type: ignore
        matched = baseline_intel_match_total._value.get()  # type: ignore
        if total:
            baseline_intel_match_ratio.set(matched / total)
    except Exception:
        pass

__all__ = ['init','observe']
