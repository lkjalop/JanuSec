"""Shallow risk scorer: linear combination with explanation.

Provides a simple risk score and breakdown for explainability.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class RiskScorer:
    weights: dict[str, float]
    intercept: float = 0.0

    def score(self, features: dict[str, float]) -> dict[str, Any]:
        """Compute a risk score and a simple explanation.

        features: mapping of feature_name->value (already normalized where appropriate)
        Returns: {score: float, breakdown: {feature: contrib}, reason: str}
        """
        total = self.intercept
        breakdown = {}
        for k, v in features.items():
            w = self.weights.get(k, 0.0)
            contrib = w * v
            breakdown[k] = contrib
            total += contrib
        # map to 0..1 via logistic-like squash (optional); keep linear for now
        score = 1 / (1 + 2.718281828 ** (-total))  # sigmoid
        reason = "; ".join([f"{k}:{v:.2f}->{breakdown[k]:.2f}" for k, v in features.items()])
        return {"score": score, "raw": total, "breakdown": breakdown, "reason": reason}
