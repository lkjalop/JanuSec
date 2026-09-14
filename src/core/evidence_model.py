from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
import math


@dataclass
class EvidenceItem:
    """Atomic piece of evidence used for RCA scoring."""
    kind: str  # e.g. heartbeat_zero, collector_crash, api_401, api_429
    score: float  # log-likelihood ratio or weight (positive supports hypothesis)
    meta: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisScore:
    hypothesis: str
    log_odds: float
    probability: float
    evidence: List[EvidenceItem]


class BayesianFusion:
    """Very small fusion helper using log-odds accumulation.

    Uses neutral prior (odds = 1 => log_odds=0) unless a prior is provided.
    Evidence items provide additive log-likelihood-ratios (LLRs).
    """

    def __init__(self, prior_odds: Optional[Dict[str, float]] = None):
        # prior_odds maps hypothesis -> odds (not probability). default odds=1
        self.prior_odds = prior_odds or {}

    def _odds_to_prob(self, odds: float) -> float:
        return odds / (1.0 + odds)

    def score(self, hypothesis: str, evidence: List[EvidenceItem]) -> HypothesisScore:
        prior_odds = float(self.prior_odds.get(hypothesis, 1.0))
        # log odds
        log_odds = math.log(prior_odds) if prior_odds > 0 else 0.0

        for e in evidence:
            # e.score is treated as LLR (log-likelihood ratio). Add directly.
            log_odds += float(e.score)

        odds = math.exp(log_odds)
        prob = self._odds_to_prob(odds)
        return HypothesisScore(hypothesis=hypothesis, log_odds=log_odds, probability=prob, evidence=evidence)


def normalize_score_to_confidence(p: float) -> float:
    """Map probability to a 0..1 confidence with simple smoothing."""
    # clamp
    p = max(0.0, min(1.0, p))
    return p
