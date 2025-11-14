"""Lightweight telemetry collectors for factor frequency, risk component distribution, extraction latency."""
from __future__ import annotations
import time
from typing import Dict, List, Any

class TelemetryCollector:
    def __init__(self):
        self.factor_frequency: Dict[str, int] = {}
        self.risk_component_dist: Dict[str, List[float]] = {}
        self.extraction_latencies: List[float] = []

    def observe_factors(self, factors: List[str]):
        for f in factors:
            self.factor_frequency[f] = self.factor_frequency.get(f, 0) + 1

    def observe_risk_components(self, comps: List[Dict[str, Any]]):
        # comps: [{'component': 'behavior', 'contribution': 0.12}, ...]
        for c in comps:
            name = c.get('component')
            contrib = float(c.get('contribution') or 0.0)
            if name not in self.risk_component_dist:
                self.risk_component_dist[name] = []
            self.risk_component_dist[name].append(contrib)

    def observe_extraction_latency(self, seconds: float):
        self.extraction_latencies.append(seconds)

    def snapshot(self) -> Dict[str, Any]:
        avg_latency = sum(self.extraction_latencies)/len(self.extraction_latencies) if self.extraction_latencies else 0.0
        comp_avg = {k: (sum(v)/len(v) if v else 0.0) for k, v in self.risk_component_dist.items()}
        return {
            'factor_frequency': dict(self.factor_frequency),
            'risk_component_average': comp_avg,
            'extraction_latency_avg': avg_latency,
            'samples': len(self.extraction_latencies)
        }

# module-level collector
_col = TelemetryCollector()
observe_factors = _col.observe_factors
observe_risk_components = _col.observe_risk_components
observe_extraction_latency = _col.observe_extraction_latency
telemetry_snapshot = _col.snapshot
