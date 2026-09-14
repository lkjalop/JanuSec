"""Temporal Model Scaffold

Abstraction layer for per-entity temporal risk scoring. Provides a pluggable
interface so that a future Temporal Fusion Transformer (TFT) or similar model
can replace the lightweight EWMA placeholder without changing callers.

Design Notes:
 - update(entity_id, features: dict) -> score (float)
 - supports basic persistence hooks (save/load) for future state retention.
 - handles missing features gracefully; merges into rolling exponential window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Any
import math, time, json, os


@dataclass
class TemporalEntityState:
    last_update: float
    ewma_score: float = 0.0
    count: int = 0


class TemporalModel:
    def __init__(self, alpha: float = 0.3, state_path: str = "data/temporal_state.json") -> None:
        # Base EWMA settings (override via env: TEMPORAL_ALPHA, *_MIN, *_MAX)
        try:
            import os as _os
            self.alpha = float(_os.getenv('TEMPORAL_ALPHA', str(alpha)) or alpha)
            self.alpha_min = float(_os.getenv('TEMPORAL_ALPHA_MIN', '0.1') or 0.1)
            self.alpha_max = float(_os.getenv('TEMPORAL_ALPHA_MAX', '0.6') or 0.6)
            self.method = (_os.getenv('TEMPORAL_METHOD', 'ewma') or 'ewma').lower()
        except Exception:
            self.alpha = alpha
            self.alpha_min = 0.1
            self.alpha_max = 0.6
            self.method = 'ewma'
        self.state_path = state_path
        self._entities: Dict[str, TemporalEntityState] = {}
        self._loaded = False

    # ---------------- Persistence -----------------
    def load(self) -> None:
        if self._loaded:
            return
        try:
            if os.path.exists(self.state_path):
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    raw = json.load(f)
                for k, v in raw.items():
                    self._entities[k] = TemporalEntityState(**v)
        except Exception:
            pass
        self._loaded = True

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            with open(self.state_path, 'w', encoding='utf-8') as f:
                json.dump({k: vars(v) for k, v in self._entities.items()}, f)
        except Exception:
            pass

    def rotate(self, persist: bool = True) -> None:
        """Persist current state (optional) and clear in-memory entities.

        Used to flush/rotate temporal state on admin demand or cadence.
        """
        try:
            if persist:
                self.save()
        except Exception:
            # Ignore persistence errors on rotate; rotation still clears memory
            pass
        self._entities.clear()
        # Keep loaded flag to avoid re-reading old state immediately
        self._loaded = True

    # ---------------- Core API -----------------
    def update(self, entity_id: str, features: Dict[str, Any]) -> float:
        """Update temporal model for an entity and return new score.

        Placeholder scoring logic:
          - Derive instantaneous risk proxy from a few heuristic feature patterns:
              * failed_login_count, suspicious_factor_count, anomaly_score
          - Combine and EWMA smooth.
        """
        self.load()
        now = time.time()
        st = self._entities.get(entity_id)
        if not st:
            st = TemporalEntityState(last_update=now)
            self._entities[entity_id] = st

        # Instantaneous proxy
        failed = float(features.get('failed_login_count', 0))
        suspicious = float(features.get('suspicious_factor_count', 0))
        anomaly = float(features.get('anomaly_score', 0.0))
        # Non-linear dampening
        inst = min(1.0, 0.02 * failed + 0.05 * suspicious + 0.5 * (1 - math.exp(-anomaly)))

        # Effective alpha: adapt to bursts and higher instantaneous risk
        try:
            alpha_eff = float(self.alpha)
            if failed >= 10 or inst >= 0.7:
                alpha_eff = min(self.alpha_max, alpha_eff + 0.1)
            elif st.count > 50 and inst < 0.2:
                alpha_eff = max(self.alpha_min, alpha_eff - 0.05)
        except Exception:
            alpha_eff = float(self.alpha)

        # EWMA smoothing (default method); simple hybrid allows minor boost from optional predictive score
        if st.count == 0:
            st.ewma_score = inst
        else:
            st.ewma_score = alpha_eff * inst + (1 - alpha_eff) * st.ewma_score

        if self.method in {'hybrid','tft-lite','tft_lite'}:
            # Optional predictive boost if caller supplies a tft_score (0..1)
            try:
                tft_score = float(features.get('tft_score') or 0.0)
            except Exception:
                tft_score = 0.0
            if tft_score > 0:
                # small blend toward predictive risk
                st.ewma_score = max(0.0, min(1.0, 0.9 * st.ewma_score + 0.1 * tft_score))
        st.count += 1
        st.last_update = now
        return st.ewma_score

    def get(self, entity_id: str) -> float:
        st = self._entities.get(entity_id)
        return st.ewma_score if st else 0.0

    def stats(self) -> dict:
        return {
            'entities': len(self._entities),
            'avg_score': (sum(e.ewma_score for e in self._entities.values()) / len(self._entities)) if self._entities else 0.0,
            'method': getattr(self, 'method', 'ewma'),
            'alpha': getattr(self, 'alpha', 0.3),
            'alpha_min': getattr(self, 'alpha_min', 0.1),
            'alpha_max': getattr(self, 'alpha_max', 0.6),
        }

    def recent_history(self, tenant: str | None = None, limit: int = 50) -> dict:
        """Return a lightweight snapshot of recent temporal states.

        If tenant is provided, filter entity ids that start with the tenant prefix
        (convention depends on ingestion tagging). This is a best-effort helper
        used by the UI to draw per-tenant sparklines without exposing full state.
        """
        # Entities are keyed by entity_id; in multi-tenant deployments the key
        # convention may include tenant_id as a prefix (e.g., 'tenant:entity').
        items = []
        try:
            for eid, st in list(self._entities.items()):
                if tenant:
                    if not str(eid).startswith(f"{tenant}:"):
                        continue
                items.append({'entity_id': eid, 'ewma_score': st.ewma_score, 'last_update': st.last_update})
        except Exception:
            items = []
        # sort by last_update desc and limit
        items.sort(key=lambda x: x.get('last_update', 0), reverse=True)
        # compress into series of recent avg values for quick sparklines
        series = [round(x['ewma_score'], 4) for x in items[:limit]]
        return {'count': len(items), 'series': series, 'limit': limit}


# Global placeholder instance
GLOBAL_TEMPORAL_MODEL = TemporalModel()

__all__ = ['TemporalModel', 'GLOBAL_TEMPORAL_MODEL']
