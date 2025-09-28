"""Runtime Threshold & Quota Configuration

Centralizes environment-derived thresholds/weights for governance & introspection.

Exposed values are resolved once on import; call refresh() to re-read env.
"""
from __future__ import annotations
import os, json
from dataclasses import dataclass, asdict
from typing import Dict, Any

@dataclass
class SeverityWeights:
    weights: Dict[str, float]
    override_source: str | None

@dataclass
class PromotionPolicy:
    min_sessions: int
    min_avg_score: float
    min_median_score: float

@dataclass
class Quotas:
    max_hunts_per_tenant_window: int | None
    hunts_window_seconds: int
    max_domain_entries_per_tenant: int | None

@dataclass
class RuntimeConfigSnapshot:
    severity: SeverityWeights
    promotion: PromotionPolicy
    quotas: Quotas
    factor_fp_ratio_threshold: float
    factor_min_observations: int
    rare_token_min_count: int
    rare_token_max_tokens: int

_current: RuntimeConfigSnapshot | None = None

def _load_severity_weights() -> SeverityWeights:
    base = {
        'component_hash_drift': 4.0,
        'non_sbom_component_exec': 3.5,
        'egress_volume_spike': 3.0,
        'beacon_periodic': 3.0,
        'beacon_low_jitter': 2.5,
        'suspicious_parent_child_pair': 2.5,
        'new_domain_seen': 1.5,
        'cmd_rare_token_spike': 2.0
    }
    override = os.getenv('SEVERITY_WEIGHTS_JSON')
    src = None
    if override:
        try:
            parsed = json.loads(override)
            if isinstance(parsed, dict):
                for k,v in parsed.items():
                    try:
                        base[k] = float(v)
                    except Exception:
                        pass
                src = 'env:SEVERITY_WEIGHTS_JSON'
        except Exception:
            pass
    return SeverityWeights(weights=base, override_source=src)

def _load_promotion() -> PromotionPolicy:
    return PromotionPolicy(
        min_sessions=int(os.getenv('PROMOTION_MIN_SESSIONS','3')),
        min_avg_score=float(os.getenv('PROMOTION_MIN_AVG_SCORE','0.15')),
        min_median_score=float(os.getenv('PROMOTION_MIN_MEDIAN_SCORE','0.10')),
    )

def _load_quotas() -> Quotas:
    return Quotas(
        max_hunts_per_tenant_window=int(os.getenv('MAX_HUNTS_PER_TENANT_WINDOW','0') or 0) or None,
        hunts_window_seconds=int(os.getenv('HUNTS_PER_TENANT_WINDOW_SECONDS','3600')),
        max_domain_entries_per_tenant=int(os.getenv('MAX_DOMAIN_TRACK_ENTRIES_PER_TENANT','0') or 0) or None,
    )

def refresh() -> RuntimeConfigSnapshot:
    global _current
    _current = RuntimeConfigSnapshot(
        severity=_load_severity_weights(),
        promotion=_load_promotion(),
        quotas=_load_quotas(),
        factor_fp_ratio_threshold=float(os.getenv('FACTOR_FP_RATIO_THRESHOLD','0.8')),
        factor_min_observations=int(os.getenv('FACTOR_MIN_OBSERVATIONS','10')),
        rare_token_min_count=int(os.getenv('RARE_TOKEN_MIN_COUNT','3')),
        rare_token_max_tokens=int(os.getenv('RARE_TOKEN_MAX_TOKENS','50000')),
    )
    return _current

def snapshot() -> Dict[str, Any]:
    if _current is None:
        refresh()
    assert _current is not None
    data = asdict(_current)
    return data

# Initialize on import
refresh()

__all__ = ['snapshot','refresh','RuntimeConfigSnapshot']
