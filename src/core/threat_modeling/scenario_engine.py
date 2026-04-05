"""Scenario evaluation engine (PASTA Phase 1).

Evaluates configured scenarios against a list of detection factors.
Lightweight, stateless (per call) for now; future iterations may include
frequency memory or asset context.
"""
from __future__ import annotations

import os
import time
from collections.abc import Iterable
from typing import Any, Dict, List

from .pasta_scenarios import SCENARIOS, Scenario
from .scenario_taxonomy import SCENARIO_TAXONOMY_VERSION, SCENARIO_CONTROL_MAP  # type: ignore

try:
    from core.metrics.registry import metric_counter, metric_histogram  # type: ignore
    _SCENARIO_MATCHES = metric_counter('scenario','matches','Scenario matches', labels=['scenario_id','status'])
    _SCENARIO_EVAL_LAT = metric_histogram('scenario','eval_latency','Scenario evaluation latency', labels=None, unit_seconds=True)
    # Legacy mirror without namespace for backward-compat tests that grep for
    # 'scenario_matches_total' — attempt to register it in the app registry if
    # available, otherwise fall back to None.
    _LEGACY_SCENARIO_MATCHES = None  # type: ignore
    try:
        from src.api.metrics_init import REGISTRY as _REG_A  # type: ignore
        from prometheus_client import Counter as _PCounter  # type: ignore
        try:
            _LEGACY_SCENARIO_MATCHES = _PCounter('scenario_matches_total', 'Scenario matches', ['scenario_id','status'], registry=_REG_A)
        except Exception:
            _LEGACY_SCENARIO_MATCHES = getattr(_REG_A, '_names_to_collectors', {}).get('scenario_matches_total')
    except Exception:
        _LEGACY_SCENARIO_MATCHES = None  # type: ignore
except Exception:  # pragma: no cover
    _SCENARIO_MATCHES = None  # type: ignore
    _SCENARIO_EVAL_LAT = None  # type: ignore
    _LEGACY_SCENARIO_MATCHES = None  # type: ignore
from .factor_taxonomy import aggregate_threat_model

# Bounds for DREAD adjustments
_DREAD_KEYS = ("damage","reproducibility","exploitability","affected_users","discoverability")

class ScenarioEngine:
    def __init__(self) -> None:
        # Future: hot reload or external storage
        self.scenarios: list[Scenario] = list(SCENARIOS)
        self.enabled = os.getenv("ENABLE_SCENARIOS","1").lower() not in {"0","false","no"}

    def evaluate(self, factors: Iterable[str]) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        fset = {f for f in factors if isinstance(f,str)}
        start = time.perf_counter()
        base_model = aggregate_threat_model(list(fset))
        dread_avg = base_model.get('dread',{}).get('average',{})
        results: list[dict[str, Any]] = []
        for sc in self.scenarios:
            # Required factors missing
            missing_required = [r for r in sc.required_factors if r not in fset]
            if missing_required:
                results.append({
                    'id': sc.id,
                    'status': 'missing_required',
                    'matched': {'required': [], 'any': [], 'optional': []},
                    'missing_required': missing_required,
                    'exclusions_hit': [],
                    'composite_risk': None,
                    'pasta_stages': sc.pasta_stages,
                    'tags': sc.tags,
                    'taxonomy_version': SCENARIO_TAXONOMY_VERSION,
                    'controls': SCENARIO_CONTROL_MAP.get(sc.id, []),
                })
                continue
            any_matches = [a for a in sc.any_factors if a in fset] if sc.any_factors else []
            if sc.any_factors and not any_matches:
                results.append({
                    'id': sc.id,
                    'status': 'not_applicable',
                    'matched': {'required': list(sc.required_factors), 'any': [], 'optional': []},
                    'missing_required': [],
                    'exclusions_hit': [],
                    'composite_risk': None,
                    'pasta_stages': sc.pasta_stages,
                    'tags': sc.tags,
                    'taxonomy_version': SCENARIO_TAXONOMY_VERSION,
                    'controls': SCENARIO_CONTROL_MAP.get(sc.id, []),
                })
                continue
            exclusions_hit = [e for e in sc.exclusions if e in fset]
            if exclusions_hit:
                results.append({
                    'id': sc.id,
                    'status': 'invalidated',
                    'matched': {'required': list(sc.required_factors), 'any': any_matches, 'optional': []},
                    'missing_required': [],
                    'exclusions_hit': exclusions_hit,
                    'composite_risk': None,
                    'pasta_stages': sc.pasta_stages,
                    'tags': sc.tags,
                    'taxonomy_version': SCENARIO_TAXONOMY_VERSION,
                    'controls': SCENARIO_CONTROL_MAP.get(sc.id, []),
                })
                continue
            optional_matches = [o for o in sc.optional_factors if o in fset]
            adjusted = dict(dread_avg) if isinstance(dread_avg, dict) else {}
            for k, v in sc.risk_adjustments.items():
                if k in adjusted:
                    base = adjusted[k]
                    try:
                        adjusted[k] = max(1, min(5, base + v))
                    except Exception:
                        adjusted[k] = base
            try:
                nums = [adjusted[k] for k in _DREAD_KEYS if k in adjusted]
                composite = round(sum(nums)/len(nums), 2) if nums else None
            except Exception:
                composite = None
            status = 'observed'
            if not optional_matches and len(any_matches) == 1 and not sc.optional_factors:
                status = 'observed'
            elif not optional_matches and any_matches:
                status = 'weak_signal'
            res = {
                'id': sc.id,
                'status': status,
                'matched': {
                    'required': list(sc.required_factors),
                    'any': any_matches,
                    'optional': optional_matches,
                },
                'missing_required': [],
                'exclusions_hit': [],
                'adjusted_dread': adjusted,
                'composite_risk': composite,
                'pasta_stages': sc.pasta_stages,
                'tags': sc.tags,
                'mitigations': sc.mitigation_recs,
                'taxonomy_version': SCENARIO_TAXONOMY_VERSION,
                'controls': SCENARIO_CONTROL_MAP.get(sc.id, []),
            }
            results.append(res)
            try:
                if _SCENARIO_MATCHES:
                    _SCENARIO_MATCHES.labels(scenario_id=sc.id, status=status).inc()
            except Exception:
                pass
            try:
                if _LEGACY_SCENARIO_MATCHES:
                    _LEGACY_SCENARIO_MATCHES.labels(scenario_id=sc.id, status=status).inc()
            except Exception:
                pass
        try:
            if _SCENARIO_EVAL_LAT:
                _SCENARIO_EVAL_LAT.observe(time.perf_counter() - start)
        except Exception:
            pass
        return results

# Singleton instance (lightweight)
ENGINE = ScenarioEngine()

__all__ = ["ENGINE","ScenarioEngine"]
