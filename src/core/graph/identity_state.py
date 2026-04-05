from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, Literal

from src.config import risk_loader

# Simple canonical states for identities
State = Literal['Benign', 'Suspicious', 'Threat']


@dataclass
class Weights:
    lateral: float = 0.3
    priv_escalation: float = 0.5
    cloud_pivot: float = 0.25
    new_host: float = 0.25
    high_value_touch: float = 0.3


@dataclass
class Thresholds:
    suspicious: float = 0.5
    threat: float = 1.2


class IdentityStateMachine:
    """Minimal per-identity risk accumulator with time decay and state transitions.

    - Maintains a floating risk score per identity
    - Applies exponential decay based on elapsed seconds
    - Transitions: Benign -> Suspicious -> Threat based on thresholds
    """

    def __init__(self, half_life_seconds: float | None = None,
                 weights: Weights | None = None,
                 thresholds: Thresholds | None = None) -> None:
        self._risk: Dict[str, float] = {}
        self._state: Dict[str, State] = {}
        self._last_ts: Dict[str, float] = {}
        cfg = risk_loader.current_config()
        th_cfg = cfg.get('thresholds', {})
        if half_life_seconds is None:
            half_life_seconds = float(th_cfg.get('decay_half_life_seconds', 900.0))
        self._half_life = max(60.0, float(half_life_seconds))
        w_cfg = cfg.get('weights', {})
        self._weights = weights or Weights(
            lateral=float(w_cfg.get('lateral', 0.3)),
            priv_escalation=float(w_cfg.get('priv_escalation', 0.5)),
            cloud_pivot=float(w_cfg.get('cloud_pivot', 0.25)),
            new_host=float(w_cfg.get('new_host', 0.25)),
            high_value_touch=float(w_cfg.get('high_value_touch', 0.3)),
        )
        self._th = thresholds or Thresholds(
            suspicious=float(th_cfg.get('suspicious', 0.5)),
            threat=float(th_cfg.get('threat', 1.2)),
        )

    @staticmethod
    def _now() -> float:
        return time.time()

    def _decay_factor(self, dt: float) -> float:
        # Exponential half-life decay
        return 0.5 ** (max(0.0, dt) / self._half_life)

    def score_increment(self, *, lateral: bool, priv_escalation: bool,
                        cloud_pivot: bool, new_host_ratio: float,
                        high_value_touch: bool) -> float:
        s = 0.0
        if lateral:
            s += self._weights.lateral
        if priv_escalation:
            s += self._weights.priv_escalation
        if cloud_pivot:
            s += self._weights.cloud_pivot
        # Soft cap new-host contribution
        s += min(1.0, max(0.0, float(new_host_ratio))) * self._weights.new_host
        if high_value_touch:
            s += self._weights.high_value_touch
        return s

    def update(self, identity: str, *, lateral: bool, priv_escalation: bool,
               cloud_pivot: bool, new_host_ratio: float, high_value_touch: bool,
               ts: float | None = None) -> State:
        # Refresh config lazily if weights changed (simple hash check can be added later)
        # For now, periodic re-pull each update (fast small dict) to reflect hot reload.
        cfg = risk_loader.current_config()
        th_cfg = cfg.get('thresholds', {})
        w_cfg = cfg.get('weights', {})
        # Update thresholds dynamically
        self._th.suspicious = float(th_cfg.get('suspicious', self._th.suspicious))
        self._th.threat = float(th_cfg.get('threat', self._th.threat))
        self._weights.lateral = float(w_cfg.get('lateral', self._weights.lateral))
        self._weights.priv_escalation = float(w_cfg.get('priv_escalation', self._weights.priv_escalation))
        self._weights.cloud_pivot = float(w_cfg.get('cloud_pivot', self._weights.cloud_pivot))
        self._weights.new_host = float(w_cfg.get('new_host', self._weights.new_host))
        self._weights.high_value_touch = float(w_cfg.get('high_value_touch', self._weights.high_value_touch))
        now = ts if ts is not None else self._now()
        prev = float(self._risk.get(identity, 0.0))
        last = float(self._last_ts.get(identity, now))
        df = self._decay_factor(now - last)
        decayed = prev * df
        inc = self.score_increment(lateral=lateral, priv_escalation=priv_escalation,
                                   cloud_pivot=cloud_pivot, new_host_ratio=new_host_ratio,
                                   high_value_touch=high_value_touch)
        score = max(0.0, decayed + inc)
        # Clamp score to a small upper bound to avoid runaway values
        score = min(score, 5.0)
        self._risk[identity] = score
        self._last_ts[identity] = now
        # Transition
        if score >= self._th.threat:
            st: State = 'Threat'
        elif score >= self._th.suspicious:
            st = 'Suspicious'
        else:
            st = 'Benign'
        self._state[identity] = st
        return st

    def current(self, identity: str) -> State:
        return self._state.get(identity, 'Benign')

    def risk(self, identity: str) -> float:
        # Return current decayed risk without mutating timestamp
        prev = float(self._risk.get(identity, 0.0))
        last = float(self._last_ts.get(identity, self._now()))
        df = self._decay_factor(self._now() - last)
        return max(0.0, prev * df)

    def snapshot(self, identity: str) -> dict:
        return {
            'identity': identity,
            'state': self.current(identity),
            'risk': round(self.risk(identity), 4),
            'last_ts': float(self._last_ts.get(identity, 0.0)),
        }

