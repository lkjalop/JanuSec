from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from src.reporting.schemas import PersonaType


DEFAULT_WEIGHTS = {
    'triage_score': 0.35,
    'confidence': 0.25,
    'evidence_count': 0.15,
    'novelty_score': 0.15,
    'time_decay': 0.10,
}


def _load_weights() -> Dict[str, float]:
    weights = DEFAULT_WEIGHTS.copy()
    raw = os.getenv('SCORING_WEIGHTS_JSON')
    if not raw:
        return weights
    try:
        parsed = json.loads(raw)
    except Exception:
        return weights
    for key in weights.keys():
        if key in parsed:
            try:
                weights[key] = float(parsed[key])
            except Exception:
                continue
        # backward compatibility with previous w_* keys
        legacy_key = f'w_{key}'
        if legacy_key in parsed:
            try:
                weights[key] = float(parsed[legacy_key])
            except Exception:
                continue
    return weights


def _time_decay(age_seconds: float, half_life_hours: float = 6.0) -> float:
    if half_life_hours <= 0:
        return 1.0
    decay = math.exp(-math.log(2) * (age_seconds / (half_life_hours * 3600.0)))
    return max(0.0, min(1.0, decay))


def _norm(value: float) -> float:
    if value is None:
        return 0.0
    return max(0.0, min(1.0, float(value)))


def _normalize_confidence(row: Dict[str, Any]) -> float:
    for key in ('confidence', 'confidence_score', 'weighted_confidence', '_pipeline_confidence'):
        if key in row and row[key] is not None:
            try:
                return _norm(float(row[key]))
            except Exception:
                continue
    return 0.0


def _evidence_norm(row: Dict[str, Any]) -> float:
    refs = row.get('evidence_refs') or row.get('evidence') or []
    try:
        if isinstance(refs, dict):
            refs = list(refs.values())
        count = len(refs) if isinstance(refs, (list, tuple, set)) else float(refs or 0)
    except Exception:
        count = 0.0
    if count <= 0:
        return 0.0
    return min(1.0, math.log1p(float(count)) / math.log1p(10.0))


def _novelty(row: Dict[str, Any]) -> float:
    for key in ('novelty_score', 'novelty', '_rarity'):
        if key in row and row[key] is not None:
            try:
                return _norm(float(row[key]))
            except Exception:
                continue
    return 0.0


def _timestamp(row: Dict[str, Any]) -> float:
    for key in ('ingested_ts', 'created_ts', 'timestamp', 'ts', 'event_ts'):
        if key in row and row[key] is not None:
            try:
                return float(row[key])
            except Exception:
                continue
    return time.time()


def _persona_allowed(row: Dict[str, Any], persona: PersonaType) -> bool:
    tags = row.get('persona_tags')
    if tags and isinstance(tags, Iterable):
        normalized_tags = {str(tag).lower() for tag in tags}
        if persona.value not in normalized_tags and persona.name.lower() not in normalized_tags:
            return False
    explainability = str(row.get('explainability_level') or row.get('explainability') or '').lower()
    requires_budget = bool(row.get('decision_gate', {}).get('requires_budget') or row.get('requires_budget'))
    if persona == PersonaType.EXECUTIVE:
        if explainability and 'minimal' not in explainability:
            return False
        return requires_budget or row.get('impact_score', 0) >= 0.7 or row.get('estimated_cost', 0) >= 10000
    if persona == PersonaType.THREAT_HUNTER:
        return bool(row.get('factors') or row.get('factor_breakdown'))
    return True


@dataclass
class RankedRow:
    row: Dict[str, Any]
    score: float
    features: Dict[str, float]


class PersonaForwarder:
    def __init__(self) -> None:
        self._weights = _load_weights()

    def refresh_weights(self) -> None:
        self._weights = _load_weights()

    def compute_score(self, row: Dict[str, Any], *, now_ts: Optional[float] = None) -> RankedRow:
        now = now_ts or time.time()
        triage = _norm(row.get('triage_score') or 0.0)
        confidence = _normalize_confidence(row)
        evidence = _evidence_norm(row)
        novelty = _novelty(row)
        seen = _timestamp(row)
        age = max(0.0, now - seen)
        decay = _time_decay(age)
        score = (
            self._weights['triage_score'] * triage
            + self._weights['confidence'] * confidence
            + self._weights['evidence_count'] * evidence
            + self._weights['novelty_score'] * novelty
            + self._weights['time_decay'] * decay
        )
        return RankedRow(
            row=row,
            score=float(score),
            features={
                'triage_score': triage,
                'confidence': confidence,
                'evidence_count': evidence,
                'novelty_score': novelty,
                'time_decay': decay,
            },
        )

    def rank(self, rows: List[Dict[str, Any]], persona: PersonaType, top_n: int = 5, *, now_ts: Optional[float] = None) -> List[RankedRow]:
        now = now_ts or time.time()
        ranked: List[RankedRow] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            if not _persona_allowed(row, persona):
                continue
            ranked.append(self.compute_score(row, now_ts=now))
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:top_n]


__all__ = ['PersonaForwarder', 'RankedRow']
