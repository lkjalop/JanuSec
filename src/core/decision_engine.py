"""
Decision Engine - Centralized routing and confidence calculation logic
Author: Security Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

try:
    from src.core.correlation.factor_synthesis import Factor, FactorCategory  # type: ignore
    from src.core.correlation.factor_synthesis_runtime import (  # type: ignore
        get_factor_synthesis_engine,
        factor_category_for_name,
    )
except Exception:  # pragma: no cover
    Factor = None  # type: ignore
    FactorCategory = None  # type: ignore
    get_factor_synthesis_engine = None  # type: ignore
    factor_category_for_name = None  # type: ignore


@dataclass
class RoutingDecision:
    """Routing decision with justification and pipeline metadata"""
    path: str  # 'benign', 'malicious', 'deep'
    confidence: float
    factors: list
    reason: str
    processing_time: float | None = None
    stage_timings: list | None = None
    config_digests: dict[str, str] | None = None
    custody_hash: str | None = None
    verdict: str | None = None
    factor_synthesis: dict | None = None
    correlation_insights: list | None = None
    metadata: dict | None = None

class DecisionEngine:
    """Centralized routing and confidence calculation logic"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load thresholds from config
        self.benign_threshold = config.get('confidence', {}).get('benign_threshold', 0.1)
        self.malicious_threshold = config.get('confidence', {}).get('malicious_threshold', 0.9)
    
    async def initialize(self):
        """Initialize decision engine"""
        self.logger.info("Decision engine initialized")
    
    async def make_decision(self, pipeline_result) -> RoutingDecision:
        """Make routing decision based on confidence"""
        confidence = pipeline_result.confidence
        stage_timings = getattr(pipeline_result, 'stage_timings', [])
        processing_time = getattr(pipeline_result, 'processing_time', 0.0)
        metadata: Dict[str, Any] = dict(pipeline_result.metadata or {})
        metadata.update({
            'processing_time': processing_time,
            'stage_timings': stage_timings,
            'config_digests': self.config.get_current_digests(),
        })
        if 'factor_synthesis' not in metadata:
            self._ensure_factor_synthesis(pipeline_result.factors, metadata)
        if isinstance(metadata.get('factor_synthesis'), dict):
            metadata.setdefault('baseline_confidence', confidence)
            try:
                confidence = float(metadata['factor_synthesis'].get('confidence') or confidence)
            except Exception:
                pass

        if confidence >= self.malicious_threshold:
            return RoutingDecision(
                path='malicious',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"High confidence malicious ({confidence:.2f})",
                verdict='malicious',
                processing_time=metadata.get('processing_time'),
                stage_timings=metadata.get('stage_timings'),
                config_digests=metadata.get('config_digests'),
                factor_synthesis=metadata.get('factor_synthesis'),
                correlation_insights=metadata.get('correlation_insights'),
                metadata=metadata,
            )
        elif confidence <= self.benign_threshold:
            return RoutingDecision(
                path='benign',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"Low confidence benign ({confidence:.2f})",
                verdict='benign',
                processing_time=metadata.get('processing_time'),
                stage_timings=metadata.get('stage_timings'),
                config_digests=metadata.get('config_digests'),
                factor_synthesis=metadata.get('factor_synthesis'),
                correlation_insights=metadata.get('correlation_insights'),
                metadata=metadata,
            )
        else:
            return RoutingDecision(
                path='deep',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"Uncertain - needs deep analysis ({confidence:.2f})",
                verdict='suspicious',
                processing_time=metadata.get('processing_time'),
                stage_timings=metadata.get('stage_timings'),
                config_digests=metadata.get('config_digests'),
                factor_synthesis=metadata.get('factor_synthesis'),
                correlation_insights=metadata.get('correlation_insights'),
                metadata=metadata,
            )

    async def finalize_decision(self, analysis_result):
        """Finalize decision after deep analysis"""
        return analysis_result
    
    async def update_thresholds(self, new_thresholds: dict[str, float]):
        """Update confidence thresholds"""
        self.benign_threshold = new_thresholds.get('benign', self.benign_threshold)
        self.malicious_threshold = new_thresholds.get('malicious', self.malicious_threshold)
        self.logger.info(f"Updated thresholds: benign={self.benign_threshold}, malicious={self.malicious_threshold}")
    
    async def shutdown(self):
        """Shutdown decision engine"""
        self.logger.info("Decision engine shutdown")

    def _build_factor_context(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        for key in ('tenant_id', 'severity', 'domain', 'source', 'ingest_source'):
            val = metadata.get(key)
            if val:
                ctx[key] = val
        return ctx

    def _ensure_factor_synthesis(self, factors: List[str], metadata: Dict[str, Any]) -> None:
        if metadata.get('factor_synthesis'):
            return
        if not (Factor and FactorCategory and get_factor_synthesis_engine and factor_category_for_name):
            return
        engine = get_factor_synthesis_engine()
        if engine is None:
            return
        now_dt = datetime.utcnow()
        uniq = []
        seen: set[str] = set()
        for name in factors or []:
            if name in seen:
                continue
            seen.add(name)
            try:
                category = factor_category_for_name(name)
            except Exception:
                category = FactorCategory.META  # type: ignore[attr-defined]
            try:
                uniq.append(Factor(name=name, category=category, timestamp=now_dt, base_weight=0.5, metadata={}))
            except Exception:
                continue
        if not uniq:
            return
        try:
            result = engine.synthesize(uniq, context=self._build_factor_context(metadata))
        except Exception:
            return
        insight = {
            'type': 'factor_synthesis',
            'confidence': result.confidence,
            'final_score': result.final_score,
            'synergies': result.synergies_detected,
            'factor_synthesis': {
                'final_score': result.final_score,
                'confidence': result.confidence,
                'contributing_factors': result.contributing_factors,
                'synergies': result.synergies_detected,
                'context_multiplier': result.context_multiplier,
                'decay_applied': result.decay_applied,
                'explanation': result.explanation,
            },
        }
        metadata.setdefault('correlation_insights', []).append(insight)
        metadata['factor_synthesis'] = insight['factor_synthesis']
        metadata['factor_synthesis_insight'] = insight
