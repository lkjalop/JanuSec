from __future__ import annotations

import os
import pickle
from pathlib import Path
from typing import Any, List, Optional


class IsolationWrapper:
    """Optional isolation forest wrapper with persistent save/load.

    Enabled when env ENABLE_ISO_ML in {'1','true','yes'} and scikit-learn is importable.
    Fallback returns neutral scores (0.0) when disabled or unavailable.
    """

    DEFAULT_PATH = Path(os.getenv('ISO_MODEL_PATH', 'data/iso_model.pkl'))

    def __init__(self, model_path: Optional[str] = None) -> None:
        self.enabled = os.getenv('ENABLE_ISO_ML', '0').lower() in {'1', 'true', 'yes'}
        self._impl: Any = None
        self.model_path = Path(model_path) if model_path else self.DEFAULT_PATH
        if self.enabled:
            try:
                from sklearn.ensemble import IsolationForest  # type: ignore

                # instantiate a default model; will be replaced by load if exists
                self._impl = IsolationForest(n_estimators=50, contamination='auto', random_state=42)
                # try to load an existing persisted model
                if self.model_path.exists():
                    try:
                        self.load_model(self.model_path)
                    except Exception:
                        # ignore load errors and continue with fresh model
                        pass
            except Exception:
                # sklearn missing or import error -> disable
                self.enabled = False

    def fit_partial(self, X: List[List[float]], persist: bool = True, path: Optional[str] = None) -> None:
        """Fit the model on X. If persist True, save to disk after fit.

        Note: Not incremental; this replaces the current model by fitting on X.
        """
        if not self.enabled:
            return
        if not X:
            return
        if self._impl is None:
            return
        try:
            self._impl.fit(X)
            if persist:
                save_path = Path(path) if path else self.model_path
                try:
                    self.save_model(save_path)
                except Exception:
                    # best-effort persistence
                    pass
        except Exception:
            # swallow training errors in demo context
            pass

    def score(self, x: List[float]) -> float:
        if not self.enabled or self._impl is None:
            return 0.0
        try:
            import numpy as np  # type: ignore

            s = float(self._impl.decision_function(np.array([x]))[0])
            # normalize roughly to 0..1 where negative is anomalous
            # isolation returns higher for normal; invert-ish
            return max(0.0, min(1.0, 0.5 - s))
        except Exception:
            return 0.0

    def save_model(self, path: Path | str) -> None:
        """Persist the underlying sklearn model to disk using pickle."""
        if not self.enabled or self._impl is None:
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            with p.open('wb') as f:
                pickle.dump(self._impl, f)
        except Exception:
            # ignore persistence errors in demo mode
            pass

    def load_model(self, path: Path | str) -> None:
        """Load a persisted model from disk."""
        p = Path(path)
        if not p.exists():
            return
        try:
            with p.open('rb') as f:
                self._impl = pickle.load(f)
        except Exception:
            # ignore load errors
            pass

    def is_ready(self) -> bool:
        return self.enabled and self._impl is not None


GLOBAL_ISO_MODEL = IsolationWrapper()

