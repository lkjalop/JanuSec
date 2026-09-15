"""TF-IDF corpus seeder and simple classifier hook for DREAD inputs.

This module is optional: if scikit-learn is available it will build a
TF-IDF vectorizer and a small LogisticRegression classifier. The model is
persisted under `data/tfidf_model.json` (vectorizer vocabs + coef simplified).
"""
from __future__ import annotations

import os
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import random

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import joblib
    SKLEARN_OK = True
except Exception:
    SKLEARN_OK = False

DATA_DIR = Path('data')
MODEL_PATH = DATA_DIR / 'tfidf_model.json'
JOBLIB_PATH = DATA_DIR / 'tfidf_model.joblib'
METRICS_PATH = DATA_DIR / 'tfidf_metrics.json'


def seed_corpus_from_observations(observations: List[Dict], test_fraction: float = 0.2, random_seed: int = 42) -> None:
    """Seed corpus using observation 'meta' and 'dread_inputs' to create text docs.

    Splits into train/test, fits TF-IDF + LogisticRegression, persists joblib model
    and writes evaluation metrics (precision/recall) to data/tfidf_metrics.json.
    """
    docs = []
    labels = []
    for obs in observations:
        di = obs.get('dread_inputs') or {}
        parts = []
        for k, v in di.items():
            parts.append(f"{k}:{v}")
        meta = obs.get('meta') or {}
        if meta:
            for k, v in meta.items():
                parts.append(f"meta_{k}:{v}")
        if parts:
            docs.append(" ".join(parts))
            # label derive from expected_loss threshold
            labels.append(1 if (obs.get('expected_loss', 0.0) > 1000.0) else 0)
    if not docs:
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SKLEARN_OK:
        # Persist simple bag-of-words as fallback
        MODEL_PATH.write_text(json.dumps({'docs': docs, 'labels': labels}), encoding='utf-8')
        return
    # Train/test split
    paired = list(zip(docs, labels))
    rand = random.Random(random_seed)
    rand.shuffle(paired)
    split_at = int(len(paired) * (1.0 - float(test_fraction)))
    # Ensure we have at least one training sample when observations are small
    if paired:
        split_at = max(1, min(split_at, len(paired)))
    train = paired[:split_at]
    test = paired[split_at:]
    train_docs, train_labels = zip(*train) if train else ([], [])
    test_docs, test_labels = zip(*test) if test else ([], [])

    vec = TfidfVectorizer(max_features=1024)
    X_train = vec.fit_transform(train_docs)
    clf = None
    # Ensure there are at least two classes in training data
    try:
        classes = set(train_labels)
    except Exception:
        classes = set()
    if len(classes) >= 2:
        clf = LogisticRegression(max_iter=200)
        clf.fit(X_train, train_labels)
    else:
        # Single-class training: skip classifier fitting
        clf = None

    # Evaluate on test set
    metrics = {}
    if test_docs:
        X_test = vec.transform(test_docs)
        if clf is None:
            # classifier not trained (single-class); cannot compute precision/recall
            metrics = {'precision': None, 'recall': None, 'test_size': len(test_docs), 'train_size': len(train_docs), 'note': 'single_class_training'}
        else:
            try:
                if hasattr(clf, 'predict_proba'):
                    probs = clf.predict_proba(X_test)[:, 1]
                    preds = (probs >= 0.5).astype(int)
                else:
                    preds = clf.predict(X_test)
                    probs = None
            except Exception:
                preds = clf.predict(X_test)
                probs = None
            # compute precision/recall simply
            tp = sum(1 for p, t in zip(preds, test_labels) if p == 1 and t == 1)
            fp = sum(1 for p, t in zip(preds, test_labels) if p == 1 and t == 0)
            fn = sum(1 for p, t in zip(preds, test_labels) if p == 0 and t == 1)
            prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            rec = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            metrics = {'precision': prec, 'recall': rec, 'test_size': len(test_docs), 'train_size': len(train_docs)}
    else:
        metrics = {'precision': None, 'recall': None, 'test_size': 0, 'train_size': len(train_docs)}

    # Persist vocab and coefficients and joblib binary
    if clf is not None:
        payload = {'vocab': vec.vocabulary_, 'coef': clf.coef_.tolist(), 'intercept': clf.intercept_.tolist()}
        try:
            joblib.dump({'vectorizer': vec, 'clf': clf}, JOBLIB_PATH)
        except Exception:
            pass
    else:
        payload = {'vocab': vec.vocabulary_, 'note': 'classifier_not_trained_single_class'}
    def _json_conv(o):
        try:
            import numpy as _np
            if isinstance(o, (_np.integer,)):
                return int(o)
            if isinstance(o, (_np.floating,)):
                return float(o)
            if hasattr(o, 'tolist'):
                return o.tolist()
        except Exception:
            pass
        try:
            return str(o)
        except Exception:
            return None

    MODEL_PATH.write_text(json.dumps(payload, default=_json_conv), encoding='utf-8')
    try:
        METRICS_PATH.write_text(json.dumps(metrics), encoding='utf-8')
    except Exception:
        pass


def classify_observation(obs: Dict) -> Optional[Tuple[float, Dict[str, float]]]:
    """If model exists, return (probability, explanation) where explanation maps feature->contribution.

    Explanation contains top contributing TF-IDF features (by absolute weight*value).
    """
    if JOBLIB_PATH.exists() and SKLEARN_OK:
        try:
            mdl = joblib.load(JOBLIB_PATH)
            vec = mdl.get('vectorizer')
            clf = mdl.get('clf')
            di = obs.get('dread_inputs') or {}
            parts = [f"{k}:{v}" for k, v in di.items()]
            doc = " ".join(parts)
            X = vec.transform([doc])
            # return probability of positive class if available
            if hasattr(clf, 'predict_proba'):
                prob = float(clf.predict_proba(X)[0][1])
            else:
                sc = clf.decision_function(X)
                import math
                prob = float(1.0 / (1.0 + math.exp(-float(sc[0]))))
            # compute feature contributions: coef * tfidf_value
            try:
                feature_names = {v: k for k, v in vec.vocabulary_.items()}
                row = X.tocsr()
                contributions: Dict[str, float] = {}
                coefs = clf.coef_[0] if hasattr(clf, 'coef_') else None
                if coefs is not None:
                    # csr: indices and data correspond positionally for the row
                    data_arr = row.data
                    idx_arr = row.indices
                    for i, idx in enumerate(idx_arr):
                        try:
                            val = float(data_arr[i])
                        except Exception:
                            val = 0.0
                        fname = feature_names.get(idx, str(idx))
                        weight = float(coefs[idx])
                        contributions[fname] = weight * val
                # sort and trim to top 10
                top = dict(sorted(contributions.items(), key=lambda kv: abs(kv[1]), reverse=True)[:10])
            except Exception:
                top = {}
            return (prob, top)
        except Exception:
            return None
    return None


def seed_and_build_from_disk():
    """Helper: read persisted CRQ shadow observations and build model if possible."""
    p = Path('data') / 'crq_shadow.json'
    if not p.exists():
        return
    try:
        obs = json.loads(p.read_text(encoding='utf-8') or '[]')
    except Exception:
        return
    seed_corpus_from_observations(obs, test_fraction=float(os.getenv('TFIDF_TEST_FRACTION','0.2')))
    try:
        if METRICS_PATH.exists():
            return json.loads(METRICS_PATH.read_text(encoding='utf-8') or '{}')
    except Exception:
        pass
    return None
