"""Alert Coverage Tracker

Tracks how many targeted alert types are routed through the pipeline and which
processing path (fast_path / adaptive / correlated) they took. Exposes a
Prometheus gauge for coverage ratio.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None    # type: ignore

class CoverageTracker:
    def __init__(self, target_alert_types: list[str] | None = None):
        self.target_alert_types = set(target_alert_types or [])
        self.seen_target: set[str] = set()
        self.total_target = 0
        self.path_counts = defaultdict(int)
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__, '_init', False):
            return
        try:
            if Counter:
                self.__class__.alert_type_total = Counter('alert_type_total','Alerts by type', ['alert_type'])
                self.__class__.alert_route_total = Counter('alert_routed_total','Alerts routed by path', ['route'])
            if Gauge:
                self.__class__.alert_coverage_ratio = Gauge('alert_coverage_ratio','Ratio of targeted alert types seen at least once')
            self.__class__._init = True
        except Exception:
            pass

    def record(self, event: dict[str, Any], route: str):
        atype = event.get('alert_type') or event.get('event_type') or 'unknown'
        if getattr(self.__class__, 'alert_type_total', None):
            try: self.__class__.alert_type_total.labels(alert_type=atype).inc()
            except Exception: pass
        if getattr(self.__class__, 'alert_route_total', None):
            try: self.__class__.alert_route_total.labels(route=route).inc()
            except Exception: pass
        if atype in self.target_alert_types:
            self.total_target += 1
            self.seen_target.add(atype)
            if getattr(self.__class__, 'alert_coverage_ratio', None):
                try:
                    denom = len(self.target_alert_types) or 1
                    self.__class__.alert_coverage_ratio.set(len(self.seen_target)/denom)
                except Exception:
                    pass
        self.path_counts[route] += 1

    def summary(self) -> dict[str, Any]:
        return {
            'target_total': len(self.target_alert_types),
            'target_seen': len(self.seen_target),
            'coverage_ratio': len(self.seen_target) / (len(self.target_alert_types) or 1),
            'path_counts': dict(self.path_counts)
        }

_global_tracker: CoverageTracker | None = None

def get_coverage_tracker(target_alert_types: list[str] | None = None) -> CoverageTracker:
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CoverageTracker(target_alert_types)
    return _global_tracker
