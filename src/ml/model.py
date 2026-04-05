"""Model wrapper for ml_score LightGBM baseline.
Provides train, save, load, and predict helpers. If LightGBM is not
installed, falls back to sklearn RandomForest for portability.
"""
from __future__ import annotations
import os
import pickle
from typing import Any, Dict, List

_MODEL_CACHE: Dict[str, Any] = {}

def _try_import_lightgbm():
    try:
        import lightgbm as lgb  # type: ignore
        return lgb
    except Exception:
        return None

def _try_import_sklearn():
    try:
        from sklearn.ensemble import RandomForestRegressor  # type: ignore
        return RandomForestRegressor
    except Exception:
        return None

def train_model(X: List[Dict[str, float]], y: List[float], model_path: str | None = None) -> Any:
    """Train a simple regressor on feature dicts. Returns trained model.
    X: list of feature dicts (same keys expected across rows)
    y: list of target float scores (0-100)
    """
    if not X:
        raise ValueError('empty training data')
    feature_names = list(X[0].keys())
    import numpy as _np
    Xmat = _np.array([[float(x.get(f, 0.0)) for f in feature_names] for x in X])
    yvec = _np.array([float(v) for v in y])

    lgb = _try_import_lightgbm()
    if lgb:
        dtrain = lgb.Dataset(Xmat, label=yvec, feature_name=feature_names)
        params = {'objective': 'regression', 'metric': 'l2', 'verbosity': -1}
        model = lgb.train(params, dtrain, num_boost_round=50)
    else:
        RF = _try_import_sklearn()
        if not RF:
            raise RuntimeError('No supported ML backend (lightgbm or sklearn) available')
        model = RF(n_estimators=100, random_state=42)
        model.fit(Xmat, yvec)

    if model_path:
        save_model(model, feature_names, model_path)
    return {'model': model, 'feature_names': feature_names}

def save_model(model_bundle: Any, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fh:
        pickle.dump(model_bundle, fh)

def load_model(path: str) -> Any:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, 'rb') as fh:
        mb = pickle.load(fh)
    # attempt to load a companion scaler if present next to model
    try:
        from src.ml.scaler import load_scaler
        scaler_path = os.path.join(os.path.dirname(path), 'ml_score_scaler.pkl')
        if os.path.exists(scaler_path):
            try:
                mb['scaler'] = load_scaler(scaler_path)
            except Exception:
                mb['scaler'] = None
        else:
            mb['scaler'] = None
    except Exception:
        mb['scaler'] = None
    return mb

def predict(model_bundle: Any, X: List[Dict[str, float]]) -> List[float]:
    if not X:
        return []
    feat = model_bundle.get('feature_names')
    model = model_bundle.get('model')
    import numpy as _np
    Xmat = _np.array([[float(x.get(f, 0.0)) for f in feat] for x in X])
    # apply scaler if available
    scaler = model_bundle.get('scaler')
    try:
        if scaler is not None:
            # scaler may be a sklearn StandardScaler or similar with transform()
            Xmat = scaler.transform(Xmat)
    except Exception:
        # fallback to unscaled
        pass
    lgb = _try_import_lightgbm()
    if lgb and hasattr(model, 'predict'):
        preds = model.predict(Xmat)
    else:
        preds = model.predict(Xmat)
    # clip and normalize
    out = [float(max(0.0, min(100.0, float(p)))) for p in preds]
    return out
