"""Factor quality scoring and suppression logic.

Tracks TP/FP counts for factors (approx) and computes suppression decisions based on
configured FP ratio threshold and minimum observation count. Persists aggregate
statistics so downstream modules (factor synthesis, UI) can reuse calibration
data across restarts.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
import math
from pathlib import Path
from typing import Any, Deque, Dict, Set, Tuple

from src.core.quality.factor_telemetry import persist_factor_telemetry
try:
    from src.feedback.store import GLOBAL_FEEDBACK_STORE  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_FEEDBACK_STORE = None  # type: ignore

try:
    from prometheus_client import Counter, Gauge
except Exception:
    def Counter(*a, **k):
        return None  # type: ignore
    def Gauge(*a, **k):
        return None    # type: ignore

# Safely create Prometheus metrics; tests may import modules multiple times so guard
_factor_tp = None
_factor_fp = None
_suppressed_gauge = None
if callable(Counter):
    try:
        _factor_tp = Counter('factor_tp_total','True positive factor attributions', ['factor'])
    except Exception:
        _factor_tp = None
    try:
        _factor_fp = Counter('factor_fp_total','False positive factor attributions', ['factor'])
    except Exception:
        _factor_fp = None
if callable(Gauge):
    try:
        _suppressed_gauge = Gauge('factor_suppressed','Factor suppression active (1/0)', ['factor'])
    except Exception:
        _suppressed_gauge = None

class FactorQualityManager:
    def __init__(self):
        self.tp: dict[str,int] = defaultdict(int)
        self.fp: dict[str,int] = defaultdict(int)
        self.suppressed: set[str] = set()
        self.fp_ratio_threshold = float(os.getenv('FACTOR_FP_RATIO_THRESHOLD','0.8'))  # suppress if >80% FP
        self.min_observations = int(os.getenv('FACTOR_MIN_OBSERVATIONS','10'))
        # Sliding window (global) last N factor attributions for precision tracking
        self.window_size = int(os.getenv('FACTOR_PRECISION_WINDOW','500'))
        self._window: deque[tuple[str,bool]] = deque(maxlen=self.window_size)
        # Aggregate counters for quick precision computation
        self._window_tp = 0
        self._window_fp = 0
        # Lifecycle tracking
        self._suppress_started: dict[str,float] = {}
        self._suppress_durations: dict[str,float] = {}  # cumulative if toggled
        self._reactivation_cooldown = float(os.getenv('FACTOR_REENABLE_MIN_SECONDS','3600'))
        self._min_precision_for_reenable = float(os.getenv('FACTOR_REENABLE_MIN_PRECISION','0.6'))
        # Persistence + context overrides
        self.state_path = Path(os.getenv('FACTOR_QUALITY_STATE_PATH','data/factor_quality_state.json'))
        self._persist_interval = float(os.getenv('FACTOR_QUALITY_PERSIST_INTERVAL','5') or 5)
        self._last_persist = 0.0
        self._dirty = False
        self.context_multipliers: dict[str,float] = {}
        self._last_snapshot_ts = 0.0
        # Long-horizon history (decaying priors feed telemetry + Bayesian calibration)
        self.history_half_life_minutes = float(os.getenv('FACTOR_HISTORY_HALF_LIFE_MINUTES','1440') or 1440.0)
        self._history: dict[str, dict[str, float]] = defaultdict(lambda: {'tp': 0.0, 'fp': 0.0, 'last_ts': 0.0})
        if self.history_half_life_minutes <= 0:
            self.history_half_life_minutes = 1440.0
        self._calibration_path = os.getenv('FACTOR_CALIBRATION_CONFIG')
        self._load_state()
        self._seed_from_feedback_store()
        if self._calibration_path:
            self._load_calibration_config(self._calibration_path)

    # ------------------------------------------------------------------ state
    def _load_state(self) -> None:
        try:
            if not self.state_path.exists():
                return
            data = json.loads(self.state_path.read_text(encoding='utf-8') or '{}')
            for key, val in (data.get('tp') or {}).items():
                self.tp[key] = int(val)
            for key, val in (data.get('fp') or {}).items():
                self.fp[key] = int(val)
            ctx_raw = data.get('context') or {}
            self.context_multipliers = {str(k): float(v) for k, v in ctx_raw.items()}
            hist_raw = data.get('history') or {}
            for key, row in hist_raw.items():
                try:
                    tp = float(row.get('tp', 0.0))
                    fp = float(row.get('fp', 0.0))
                    last_ts = float(row.get('last_ts', 0.0))
                    self._history[key] = {'tp': tp, 'fp': fp, 'last_ts': last_ts}
                except Exception:
                    continue
        except Exception:
            # Ignore corrupt state but continue operating
            self.context_multipliers = dict(self.context_multipliers)

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._maybe_persist()

    def _maybe_persist(self) -> None:
        if not self._dirty:
            return
        now = time.time()
        if (now - self._last_persist) < self._persist_interval:
            return
        self._save_state(now)

    def _save_state(self, ts: float | None = None) -> None:
        try:
            payload = {
                'tp': dict(self.tp),
                'fp': dict(self.fp),
                'context': dict(self.context_multipliers),
                'history': {k: {'tp': v['tp'], 'fp': v['fp'], 'last_ts': v['last_ts']} for k, v in self._history.items()},
            }
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding='utf-8')
            self._dirty = False
            self._last_persist = ts or time.time()
            self._persist_telemetry_snapshot(self._last_persist)
        except Exception:
            # Best-effort persistence; ignore failures
            pass

    def persist(self, force: bool = False) -> None:
        """Flush state to disk immediately (tests/admin)."""
        if force:
            self._save_state(time.time())
            return
        self._maybe_persist()

    def record(self, factor: str, is_tp: bool):
        if is_tp:
            self.tp[factor]+=1
            if _factor_tp: _factor_tp.labels(factor=factor).inc()
        else:
            self.fp[factor]+=1
            if _factor_fp: _factor_fp.labels(factor=factor).inc()
        self._evaluate(factor)
        self._update_history(factor, is_tp)
        # Maintain sliding window stats
        if len(self._window) == self.window_size:
            # Remove impact of oldest
            old_factor, old_is_tp = self._window[0]
            if old_is_tp:
                self._window_tp -= 1
            else:
                self._window_fp -= 1
        self._window.append((factor, is_tp))
        if is_tp:
            self._window_tp += 1
        else:
            self._window_fp += 1
        self._mark_dirty()

    def _evaluate(self, factor: str):
        t = self.tp[factor]; f = self.fp[factor]
        total = t+f
        if total < self.min_observations:
            return
        fp_ratio = f / total if total>0 else 0.0
        if fp_ratio >= self.fp_ratio_threshold:
            if factor not in self.suppressed:
                self.suppressed.add(factor)
                if _suppressed_gauge:
                    _suppressed_gauge.labels(factor=factor).set(1)
                # Start lifecycle timer
                if factor not in self._suppress_started:
                    import time as _t
                    self._suppress_started[factor] = _t.time()
        else:
            if factor in self.suppressed:
                self.suppressed.remove(factor)
                if _suppressed_gauge:
                    _suppressed_gauge.labels(factor=factor).set(0)
                # Close lifecycle
                import time as _t
                start = self._suppress_started.pop(factor, None)
                if start:
                    self._suppress_durations[factor] = self._suppress_durations.get(factor,0.0) + (_t.time()-start)
        self._mark_dirty()

    def _history_decay_factor(self, elapsed_seconds: float) -> float:
        if elapsed_seconds <= 0:
            return 1.0
        half_life = max(60.0, self.history_half_life_minutes * 60.0)
        return math.pow(0.5, elapsed_seconds / half_life)

    def _update_history(self, factor: str, is_tp: bool) -> None:
        now = time.time()
        entry = self._history.setdefault(factor, {'tp': 0.0, 'fp': 0.0, 'last_ts': now})
        elapsed = now - float(entry.get('last_ts') or 0.0)
        decay = self._history_decay_factor(elapsed)
        entry['tp'] = float(entry.get('tp', 0.0)) * decay
        entry['fp'] = float(entry.get('fp', 0.0)) * decay
        if is_tp:
            entry['tp'] += 1.0
        else:
            entry['fp'] += 1.0
        entry['last_ts'] = now

    def history_snapshot(self, limit: int = 50) -> list[dict[str, float | str]]:
        rows: list[dict[str, float | str]] = []
        now = time.time()
        for factor, entry in self._history.items():
            tp = float(entry.get('tp', 0.0))
            fp = float(entry.get('fp', 0.0))
            total = tp + fp
            if total <= 0:
                continue
            fp_rate = fp / total if total else 0.0
            rows.append({
                'factor': factor,
                'tp': round(tp, 3),
                'fp': round(fp, 3),
                'fp_rate': round(min(1.0, max(0.0, fp_rate)), 4),
                'last_ts': float(entry.get('last_ts') or 0.0),
                'age_seconds': round(now - float(entry.get('last_ts') or 0.0), 2),
            })
        rows.sort(key=lambda r: r.get('fp_rate', 0.0), reverse=True)
        return rows[:limit]

    def filter_factors(self, factors):
        return [f for f in factors if f not in self.suppressed]

    def export_fp_rates(self, min_observations: int | None = None) -> dict[str, dict[str, float]]:
        """Return mapping of factor -> {'fp_rate': ...} for factors with enough samples."""
        threshold = min_observations or self.min_observations
        stats: dict[str, dict[str, float]] = {}
        for factor in set(self.tp.keys()) | set(self.fp.keys()):
            t = self.tp.get(factor, 0)
            f = self.fp.get(factor, 0)
            total = t + f
            history = self._history.get(factor)
            if total <= 0 or total < threshold:
                if not history:
                    continue
                hist_total = float(history.get('tp', 0.0)) + float(history.get('fp', 0.0))
                if hist_total <= 0:
                    continue
                fp_rate = min(1.0, float(history.get('fp', 0.0)) / hist_total)
                stats[factor] = {
                    'fp_rate': fp_rate,
                    'history': {
                        'tp': history.get('tp', 0.0),
                        'fp': history.get('fp', 0.0),
                        'last_ts': history.get('last_ts', 0.0),
                    },
                }
                continue
            entry: dict[str, float | dict[str, float]] = {'fp_rate': min(1.0, f / total)}
            if history:
                entry['history'] = {
                    'tp': history.get('tp', 0.0),
                    'fp': history.get('fp', 0.0),
                    'last_ts': history.get('last_ts', 0.0),
                }
            stats[factor] = entry  # type: ignore[assignment]
        return stats

    def get_context_multipliers(self) -> dict[str, float]:
        """Return persisted context multipliers for synthesis calibration."""
        return dict(self.context_multipliers)

    def set_context_multiplier(self, marker: str, value: float) -> None:
        """Update or add a context multiplier (admin hooks/tests)."""
        try:
            self.context_multipliers[str(marker)] = float(value)
            self._mark_dirty()
        except Exception:
            pass

    def window_precision(self) -> float:
        total = self._window_tp + self._window_fp
        if total == 0:
            return 0.0
        return self._window_tp / total

    def window_counts(self) -> dict[str,int]:
        return {
            'tp': self._window_tp,
            'fp': self._window_fp,
            'total': self._window_tp + self._window_fp,
            'window_size': self.window_size
        }

    def suppression_lifecycle(self) -> dict[str, dict[str, float | int | str]]:
        """Return lifecycle analytics for suppressed factors.

        Provides: duration (current or cumulative), observations, tp, fp, fp_ratio,
        and re_enable_suggestion (yes/no) based on cooldown + precision recovery.
        """
        import time as _t
        rows: dict[str, dict[str, float | int | str]] = {}
        now = _t.time()
        for f in self.suppressed:
            t = self.tp.get(f,0); fp = self.fp.get(f,0); tot = t+fp
            fp_ratio = (fp / tot) if tot else 0.0
            start = self._suppress_started.get(f)
            duration = (now - start) if start else 0.0
            # Re-enable heuristic: enough time elapsed AND precision improved in recent window
            # Approx precision recent: use window counts filtered to factor
            recent_tp = sum(1 for fac,is_tp in self._window if fac==f and is_tp)
            recent_fp = sum(1 for fac,is_tp in self._window if fac==f and not is_tp)
            recent_total = recent_tp + recent_fp
            recent_precision = (recent_tp / recent_total) if recent_total else 0.0
            suggest_reenable = 'no'
            if duration >= self._reactivation_cooldown and recent_total >= max(3, self.min_observations/2):
                if recent_precision >= self._min_precision_for_reenable and fp_ratio < self.fp_ratio_threshold:
                    suggest_reenable = 'yes'
            rows[f] = {
                'tp': t,
                'fp': fp,
                'observations': tot,
                'fp_ratio': round(fp_ratio,3),
                'duration_seconds': round(duration,1),
                'recent_precision': round(recent_precision,3),
                're_enable_suggestion': suggest_reenable
            }
        return rows

    # ---------------------------- telemetry/admin helpers --------------------
    def telemetry_snapshot(self) -> dict[str, Any]:
        """Return richer telemetry for admin panels + synthesis priors."""
        now = time.time()
        snapshot: dict[str, Any] = {
            'timestamp': now,
            'window_precision': round(self.window_precision(), 5),
            'window_counts': self.window_counts(),
            'context_multipliers': dict(self.context_multipliers),
            'factor_fp_stats': self.export_fp_rates(min_observations=1),
            'suppressed': sorted(self.suppressed),
            'factor_history': self.history_snapshot(),
            'history_half_life_minutes': self.history_half_life_minutes,
        }
        rankings: list[dict[str, Any]] = []
        for factor in set(list(self.tp.keys()) + list(self.fp.keys())):
            t = self.tp.get(factor, 0)
            f = self.fp.get(factor, 0)
            total = t + f
            if total <= 0:
                continue
            fp_ratio = (f / total) if total else 0.0
            rankings.append({
                'factor': factor,
                'tp': t,
                'fp': f,
                'observations': total,
                'fp_ratio': round(fp_ratio, 4),
                'suppressed': factor in self.suppressed,
            })
        rankings.sort(key=lambda row: row['fp_ratio'], reverse=True)
        snapshot['factor_rankings'] = rankings[:25]
        return snapshot

    def calibration_path(self) -> str | None:
        return self._calibration_path

    def apply_admin_observations(self, overrides: dict[str, dict[str, int | float]]) -> None:
        """Allow admin APIs to set TP/FP counts directly for calibration."""
        if not overrides:
            return
        for factor, counts in overrides.items():
            if not isinstance(counts, dict):
                continue
            tp = counts.get('tp')
            fp = counts.get('fp')
            if tp is not None:
                try:
                    self.tp[factor] = max(0, int(tp))
                except Exception:
                    pass
            if fp is not None:
                try:
                    self.fp[factor] = max(0, int(fp))
                except Exception:
                    pass
        self._mark_dirty()

    def _persist_telemetry_snapshot(self, ts: float) -> None:
        """Persist the latest telemetry snapshot for runtime helpers."""
        if ts - self._last_snapshot_ts < 1:
            return
        snapshot = self.telemetry_snapshot()
        snapshot['timestamp'] = ts
        try:
            persist_factor_telemetry(snapshot)
            self._last_snapshot_ts = ts
        except Exception:
            pass

    def _seed_from_feedback_store(self) -> None:
        """Hydrate priors from the feedback quality tables."""
        if not GLOBAL_FEEDBACK_STORE:
            return
        try:
            rows = GLOBAL_FEEDBACK_STORE.list_factor_qualities(limit=5000, sort='desc')
        except Exception:
            return
        now = time.time()
        changed = False
        for row in rows or []:
            factor = row.get('factor')
            if not factor:
                continue
            tp = int(row.get('tp') or 0)
            fp = int(row.get('fp') or 0)
            if tp <= 0 and fp <= 0:
                continue
            if tp > self.tp.get(factor, 0):
                self.tp[factor] = tp
                changed = True
            if fp > self.fp.get(factor, 0):
                self.fp[factor] = fp
                changed = True
            hist = self._history.setdefault(factor, {'tp': 0.0, 'fp': 0.0, 'last_ts': now})
            hist['tp'] = max(hist.get('tp', 0.0), float(tp))
            hist['fp'] = max(hist.get('fp', 0.0), float(fp))
            hist['last_ts'] = now
        if changed:
            self._mark_dirty()

    def _load_calibration_config(self, path: str) -> None:
        """Apply calibration overrides from JSON config."""
        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception:
            return
        self.apply_calibration_dict(data if isinstance(data, dict) else None)

    def reload_calibration_config(self, path: str | None = None) -> bool:
        cfg_path = path or self._calibration_path
        if not cfg_path:
            return False
        self._load_calibration_config(cfg_path)
        self._calibration_path = cfg_path
        self.persist(force=True)
        return True

    def apply_calibration_dict(self, data: dict[str, Any] | None) -> None:
        """Apply calibration overrides from an in-memory dict."""
        if not data or not isinstance(data, dict):
            return
        ctx = data.get('context_multipliers') or data.get('context')
        updated = False
        if isinstance(ctx, dict):
            for key, value in ctx.items():
                try:
                    self.context_multipliers[str(key)] = float(value)
                    updated = True
                except Exception:
                    continue
        obs = data.get('observations')
        if isinstance(obs, dict):
            self.apply_admin_observations(obs)
            updated = True
        if updated:
            self._mark_dirty()

_quality_mgr: FactorQualityManager | None = None

def get_quality_manager() -> FactorQualityManager:
    global _quality_mgr
    if _quality_mgr is None:
        _quality_mgr = FactorQualityManager()
    return _quality_mgr

__all__ = ['get_quality_manager','FactorQualityManager']
