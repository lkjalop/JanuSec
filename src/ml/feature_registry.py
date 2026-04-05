"""Feature Registry Scaffold for Temporal / TFT Models.

Defines a lightweight declarative registry for time-series features used in
per-entity temporal modeling. This enables consistent window materialization,
validation, and downstream model input ordering.

Future extensions:
 - Persist historical windows (e.g., parquet or feather) keyed by entity & feature set.
 - Dynamic feature toggling via environment variables.
 - Automatic schema version hashing for backward compatibility.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Any, Dict, List, Optional
import os

@dataclass(frozen=True)
class FeatureSpec:
    name: str
    kind: str  # numeric | categorical | counter | ratio
    agg: str   # last | mean | sum | ewma | max | min
    window_sec: int
    default: float | int | str | None = 0.0
    desc: str = ''

class FeatureRegistry:
    def __init__(self):
        self._features: Dict[str, FeatureSpec] = {}

    def register(self, spec: FeatureSpec) -> None:
        if spec.name in self._features:
            # idempotent (must match existing)
            if self._features[spec.name] != spec:
                raise ValueError(f'Feature mismatch for {spec.name}')
            return
        self._features[spec.name] = spec

    def get(self, name: str) -> Optional[FeatureSpec]:
        return self._features.get(name)

    def all(self) -> List[FeatureSpec]:
        return list(self._features.values())

    def enabled(self) -> List[FeatureSpec]:
        # environment toggle: FEATURE_INCLUDE=feat1,feat2 (whitelist) or FEATURE_EXCLUDE=featX
        inc = {s.strip() for s in os.getenv('FEATURE_INCLUDE','').split(',') if s.strip()}
        exc = {s.strip() for s in os.getenv('FEATURE_EXCLUDE','').split(',') if s.strip()}
        feats = self.all()
        if inc:
            feats = [f for f in feats if f.name in inc]
        if exc:
            feats = [f for f in feats if f.name not in exc]
        return feats

GLOBAL_FEATURE_REGISTRY = FeatureRegistry()

# Default core features (can be extended by import side-effects)
CORE_FEATURES = [
    FeatureSpec('failed_login_count', 'counter', 'last', 3600, 0, 'Recent failed authentication attempts'),
    FeatureSpec('suspicious_factor_count', 'counter', 'last', 3600, 0, 'Recent suspicious factor occurrences'),
    FeatureSpec('anomaly_score', 'numeric', 'last', 900, 0.0, 'Short-term anomaly score'),
    FeatureSpec('unique_hosts_24h', 'counter', 'last', 86400, 0, 'Distinct hosts touched (24h)'),
]
for _spec in CORE_FEATURES:
    GLOBAL_FEATURE_REGISTRY.register(_spec)

__all__ = ['FeatureSpec','FeatureRegistry','GLOBAL_FEATURE_REGISTRY']
