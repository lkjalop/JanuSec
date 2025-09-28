"""Correlation Engine (Phase 0 Skeleton)

Future: Combine multiple lane & base factors into synthesized higher-confidence correlation factors.
Current: No-op pass-through with metric stub.
"""
from __future__ import annotations
from typing import List
from .factor_constants import (
    OFFICE_MACRO_SPAWN_POWERSHELL,
    POWERSHELL_ENCODED_COMMAND,
    SIGNED_TO_UNSIGNED_TRANSITION,
    PROC_PARENT_CHAIN,
    JA3_RARE,
    CORR_OFFICE_PS_RARE_JA3,
    CORR_ENCODED_PS_SIGNED_TO_UNSIGNED,
    CORR_LATERAL_PIVOT_POSSIBLE,
)
import logging

try:
    from prometheus_client import Counter
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__, '_init', False):
            return
        try:
            if Counter:
                self.__class__.corr_factors_total = Counter('hunt_correlation_factors_total','Correlation synthesized factors emitted')
                self.__class__.corr_rule_hits = Counter('hunt_correlation_rule_hits_total','Correlation rule hit count', ['rule'])
                self.__class__.corr_tp_before = Counter('hunt_corr_tp_before_total','Correlation pipeline true-positive factors before correlation')
                self.__class__.corr_tp_after = Counter('hunt_corr_tp_after_total','Correlation pipeline true-positive factors after correlation')
                self.__class__.corr_fp_before = Counter('hunt_corr_fp_before_total','Correlation pipeline false-positive factors before correlation')
                self.__class__.corr_fp_after = Counter('hunt_corr_fp_after_total','Correlation pipeline false-positive factors after correlation')
            self.__class__._init = True
        except Exception:
            pass

    async def correlate(self, factors: List[str], *, tp_factors: List[str] | None = None, fp_factors: List[str] | None = None) -> List[str]:
        new: List[str] = []
        fset = set(factors)
        # Record before stats (if provided)
        if tp_factors and getattr(self.__class__, 'corr_tp_before', None):
            try:
                for _ in tp_factors: self.__class__.corr_tp_before.inc()
            except Exception: pass
        if fp_factors and getattr(self.__class__, 'corr_fp_before', None):
            try:
                for _ in fp_factors: self.__class__.corr_fp_before.inc()
            except Exception: pass
        # Rule 1: Office macro spawning PS + rare JA3
        if OFFICE_MACRO_SPAWN_POWERSHELL in fset and JA3_RARE in fset:
            new.append(CORR_OFFICE_PS_RARE_JA3)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='office_ps_rare_ja3').inc()
                except Exception: pass
        # Rule 2: Encoded PS + signed→unsigned transition synergy
        if POWERSHELL_ENCODED_COMMAND in fset and SIGNED_TO_UNSIGNED_TRANSITION in fset:
            new.append(CORR_ENCODED_PS_SIGNED_TO_UNSIGNED)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='encoded_signed_unsigned').inc()
                except Exception: pass
        # Rule 3: Lateral pivot possible (generic lineage chain + rare JA3)
        if PROC_PARENT_CHAIN in fset and JA3_RARE in fset:
            new.append(CORR_LATERAL_PIVOT_POSSIBLE)
            if getattr(self.__class__, 'corr_rule_hits', None):
                try: self.__class__.corr_rule_hits.labels(rule='lateral_pivot_possible').inc()
                except Exception: pass
        if new:
            if getattr(self.__class__, 'corr_factors_total', None):
                for _ in new:
                    try:
                        self.__class__.corr_factors_total.inc()
                    except Exception:
                        pass
            # Post-correlation stats (simplistic: treat new factors as TP contributors if any original TP)
            if tp_factors and getattr(self.__class__, 'corr_tp_after', None):
                try:
                    for _ in tp_factors: self.__class__.corr_tp_after.inc()
                except Exception: pass
            if fp_factors and getattr(self.__class__, 'corr_fp_after', None):
                try:
                    for _ in fp_factors: self.__class__.corr_fp_after.inc()
                except Exception: pass
        return new

# Factory
_engine_instance: CorrelationEngine | None = None

def get_correlation_engine(config) -> CorrelationEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CorrelationEngine(config)
    return _engine_instance
