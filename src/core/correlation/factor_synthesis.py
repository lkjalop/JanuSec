"""Production-grade factor synthesis engine.

Backfills the roadmap spec by providing Bayesian combination, FP suppression,
temporal decay, context-aware weighting, and synergy boosts. Configuration is
JSON-driven so SecOps can calibrate weights without code changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


class FactorCategory(Enum):
    """Factor categories for independence analysis."""

    ENDPOINT = "endpoint"
    NETWORK = "network"
    EMAIL = "email"
    IDENTITY = "identity"
    CLOUD = "cloud"
    DATA = "data"
    API = "api"
    PROCESS = "process"
    META = "meta"
    REMOTE_ACCESS = "remote"


@dataclass
class Factor:
    """Security factor emitted by detectors or correlators."""

    name: str
    category: FactorCategory
    timestamp: datetime
    base_weight: float = 0.5
    source_event_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    fp_rate: Optional[float] = None


@dataclass
class SynthesisResult:
    """Detailed output of factor combination."""

    final_score: float
    confidence: float
    contributing_factors: List[Tuple[str, float]]
    synergies_detected: List[str]
    decay_applied: float
    context_multiplier: float
    fp_adjustment: float
    explanation: str
    mitre_tactics: List[str]


def _now() -> datetime:
    return datetime.utcnow()


class FactorSynthesisEngine:
    """Implements Bayesian factor combination with configurable calibration."""

    DEFAULT_FP_THRESHOLD = 0.70
    DEFAULT_FP_SUPPRESSION = 0.3
    DEFAULT_TEMPORAL_HALF_LIFE_MINUTES = 30

    DEFAULT_CATEGORY_INDEPENDENCE: Dict[Tuple[FactorCategory, FactorCategory], float] = {
        (FactorCategory.ENDPOINT, FactorCategory.NETWORK): 0.95,
        (FactorCategory.ENDPOINT, FactorCategory.EMAIL): 0.90,
        (FactorCategory.NETWORK, FactorCategory.CLOUD): 0.85,
        (FactorCategory.IDENTITY, FactorCategory.CLOUD): 0.80,
        (FactorCategory.ENDPOINT, FactorCategory.ENDPOINT): 0.45,
        (FactorCategory.NETWORK, FactorCategory.NETWORK): 0.45,
    }

    def __init__(self, config_path: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        cfg = config or self._load_config(config_path)
        self.base_weights: Dict[str, float] = {k.lower(): float(v) for k, v in (cfg.get("base_weights") or {}).items()}
        self.factor_fp_rates: Dict[str, float] = {
            k.lower(): float(v.get("fp_rate", v) if isinstance(v, dict) else v)
            for k, v in (cfg.get("factor_fp_stats") or {}).items()
        }
        self.context_multipliers: Dict[str, float] = {
            k.lower(): float(v) for k, v in (cfg.get("context_multipliers") or {}).items()
        }
        self.factor_history = cfg.get("factor_history") or []
        for row in self.factor_history:
            try:
                name = str(row.get("factor") or "").lower()
                if not name or name in self.factor_fp_rates:
                    continue
                tp = float(row.get("tp", 0.0))
                fp = float(row.get("fp", 0.0))
                total = tp + fp
                if total <= 0:
                    continue
                self.factor_fp_rates[name] = min(1.0, fp / total)
            except Exception:
                continue
        self.synergy_matrix: Dict[Tuple[str, str], float] = self._parse_synergy(cfg.get("synergy"))
        self.fp_threshold = float(cfg.get("fp_threshold", self.DEFAULT_FP_THRESHOLD))
        self.fp_suppression = float(cfg.get("fp_suppression", self.DEFAULT_FP_SUPPRESSION))
        temporal_cfg = cfg.get("temporal") or {}
        self.half_life_minutes = float(temporal_cfg.get("half_life_minutes", self.DEFAULT_TEMPORAL_HALF_LIFE_MINUTES))
        self.category_independence = self._build_category_independence(cfg.get("category_independence"))

    # ------------------------------------------------------------------ public
    def synthesize(
        self,
        factors: Iterable[Factor],
        context: Optional[Dict[str, Any]] = None,
        reference_time: Optional[datetime] = None,
    ) -> SynthesisResult:
        """Combine factors into a single score & explanation."""

        factor_list = list(factors or [])
        if not factor_list:
            return SynthesisResult(
                final_score=0.0,
                confidence=0.0,
                contributing_factors=[],
                synergies_detected=[],
                decay_applied=0.0,
                context_multiplier=1.0,
                fp_adjustment=0.0,
                explanation="No factors supplied",
                mitre_tactics=[],
            )

        reference_time = reference_time or _now()
        context = context or {}

        adjusted_factors = self._apply_fp_suppression(factor_list)
        decayed_factors, avg_decay = self._apply_temporal_decay(adjusted_factors, reference_time)
        synergies, synergy_boost = self._detect_synergies(decayed_factors)
        base_score, contributions = self._bayesian_combine(decayed_factors)
        score_with_synergy = min(1.0, base_score + synergy_boost)
        context_multiplier = self._calculate_context_multiplier(context)
        final_score = min(1.0, score_with_synergy * context_multiplier)
        confidence = self._calculate_confidence(decayed_factors, final_score, len(synergies))
        mitre_tactics = self._extract_mitre_tactics(decayed_factors)
        explanation = self._generate_explanation(decayed_factors, contributions, synergies, context_multiplier, avg_decay)
        fp_adj = sum(f.fp_rate or self.factor_fp_rates.get(f.name.lower(), 0.0) for f in factor_list) / len(factor_list)

        return SynthesisResult(
            final_score=final_score,
            confidence=confidence,
            contributing_factors=contributions,
            synergies_detected=synergies,
            decay_applied=avg_decay,
            context_multiplier=context_multiplier,
            fp_adjustment=fp_adj,
            explanation=explanation,
            mitre_tactics=mitre_tactics,
        )

    # ----------------------------------------------------------------- helpers
    def _load_config(self, path: Optional[str]) -> Dict[str, Any]:
        default = os.getenv("FACTOR_SYNTHESIS_CONFIG", "config/factor_synthesis.json")
        cfg_path = Path(path or default)
        if not cfg_path.exists():
            return {}
        try:
            return json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _parse_synergy(self, raw: Optional[Dict[str, Any]]) -> Dict[Tuple[str, str], float]:
        synergy: Dict[Tuple[str, str], float] = {}
        for key, value in (raw or {}).items():
            if "|" in key:
                a, b = key.split("|", 1)
            elif "," in key:
                a, b = key.split(",", 1)
            else:
                continue
            try:
                synergy[(a.strip().lower(), b.strip().lower())] = float(value)
            except Exception:
                continue
        return synergy

    def _build_category_independence(
        self, overrides: Optional[Dict[str, Dict[str, float]]]
    ) -> Dict[Tuple[FactorCategory, FactorCategory], float]:
        independence = dict(self.DEFAULT_CATEGORY_INDEPENDENCE)
        for key, value in (overrides or {}).items():
            try:
                cat_a = FactorCategory(key)
            except Exception:
                continue
            for inner_cat, score in value.items():
                try:
                    cat_b = FactorCategory(inner_cat)
                    independence[(cat_a, cat_b)] = float(score)
                except Exception:
                    continue
        return independence

    # -- core stages ----------------------------------------------------------
    def _apply_fp_suppression(self, factors: List[Factor]) -> List[Factor]:
        adjusted: List[Factor] = []
        for factor in factors:
            fp_rate = self.factor_fp_rates.get(factor.name.lower(), factor.fp_rate or 0.0)
            if fp_rate >= self.fp_threshold:
                adjusted.append(
                    Factor(
                        name=factor.name,
                        category=factor.category,
                        timestamp=factor.timestamp,
                        base_weight=factor.base_weight * self.fp_suppression,
                        source_event_id=factor.source_event_id,
                        metadata={**factor.metadata, "fp_suppressed": True, "original_weight": factor.base_weight},
                        fp_rate=fp_rate,
                    )
                )
            else:
                adjusted.append(factor)
        return adjusted

    def _apply_temporal_decay(
        self, factors: List[Factor], reference_time: datetime
    ) -> Tuple[List[Factor], float]:
        if self.half_life_minutes <= 0:
            return factors, 0.0

        decayed: List[Factor] = []
        decay_total = 0.0
        for factor in factors:
            age_minutes = (reference_time - factor.timestamp).total_seconds() / 60.0
            if age_minutes <= 0:
                decay = 1.0
            else:
                decay = math.pow(0.5, age_minutes / self.half_life_minutes)
            decay_total += (1.0 - decay)
            decayed.append(
                Factor(
                    name=factor.name,
                    category=factor.category,
                    timestamp=factor.timestamp,
                    base_weight=factor.base_weight * decay,
                    source_event_id=factor.source_event_id,
                    metadata={**factor.metadata, "temporal_decay": decay},
                    fp_rate=factor.fp_rate,
                )
            )
        avg_decay = decay_total / len(factors) if factors else 0.0
        return decayed, avg_decay

    def _detect_synergies(self, factors: List[Factor]) -> Tuple[List[str], float]:
        present = {f.name.lower() for f in factors}
        synergies: List[str] = []
        boost = 0.0

        for (a, b), value in self.synergy_matrix.items():
            if a in present and b in present:
                synergies.append(f"synergy:{a}+{b}")
                boost += float(value)
        return synergies, min(0.5, boost)

    def _bayesian_combine(self, factors: List[Factor]) -> Tuple[float, List[Tuple[str, float]]]:
        contributions: List[Tuple[str, float]] = []
        if not factors:
            return 0.0, contributions

        grouped: Dict[FactorCategory, List[Factor]] = {}
        for factor in factors:
            grouped.setdefault(factor.category, []).append(factor)

        category_probs: Dict[FactorCategory, float] = {}
        for category, cat_factors in grouped.items():
            prob = 0.0
            for factor in cat_factors:
                w = self.base_weights.get(factor.name.lower(), factor.base_weight)
                w = max(0.01, min(0.99, w))
                prob = 1 - (1 - prob) * (1 - w)
                contributions.append((factor.name, round(w, 4)))
            category_probs[category] = prob

        final = 0.0
        for cat_a, prob in category_probs.items():
            if prob <= 0:
                continue
            adj = prob
            for cat_b, other_prob in category_probs.items():
                if cat_a == cat_b or other_prob <= 0:
                    continue
                weight = self.category_independence.get((cat_a, cat_b)) or self.category_independence.get((cat_b, cat_a)) or 0.7
                adj *= weight
            final = 1 - (1 - final) * (1 - adj)
        return min(0.99, final), contributions

    def _calculate_context_multiplier(self, context: Dict[str, Any]) -> float:
        multiplier = 1.0
        for key, value in (context or {}).items():
            marker = f"{key}:{value}".lower()
            if marker in self.context_multipliers:
                multiplier *= self.context_multipliers[marker]
        return max(0.5, min(1.5, multiplier))

    def _calculate_confidence(self, factors: List[Factor], final_score: float, synergy_count: int) -> float:
        base = final_score
        density_bonus = min(0.1, len(factors) * 0.01)
        synergy_bonus = min(0.1, synergy_count * 0.02)
        return min(0.99, base + density_bonus + synergy_bonus)

    def _extract_mitre_tactics(self, factors: List[Factor]) -> List[str]:
        tactics: List[str] = []
        for factor in factors:
            meta = factor.metadata or {}
            if "mitre" in meta and isinstance(meta["mitre"], (list, tuple)):
                for tactic in meta["mitre"]:
                    if tactic not in tactics:
                        tactics.append(tactic)
        return tactics

    def _generate_explanation(
        self,
        factors: List[Factor],
        contributions: List[Tuple[str, float]],
        synergies: List[str],
        context_multiplier: float,
        avg_decay: float,
    ) -> str:
        parts = [
            f"{len(factors)} factors evaluated.",
            f"Avg decay reduction {avg_decay:.2f}.",
            f"Context multiplier {context_multiplier:.2f}.",
        ]
        if contributions:
            top = ", ".join(f"{name}:{weight:.2f}" for name, weight in contributions[:5])
            parts.append(f"Top contributions: {top}")
        if synergies:
            parts.append(f"Synergy triggers: {', '.join(synergies)}")
        return " ".join(parts)


__all__ = ["Factor", "FactorCategory", "FactorSynthesisEngine", "SynthesisResult"]
