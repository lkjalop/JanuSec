from typing import Dict, Any, List
import os
import json
import time
from collections import defaultdict

SKLEARN_AVAILABLE = None


MODEL_DIR = os.getenv('ML_MODEL_DIR', os.path.join('data', 'models'))
os.makedirs(MODEL_DIR, exist_ok=True)


class FactorWeightLearner:
    """Production-oriented factor weight learner.

    - Buffers labeled feedback (event_id, factors list, vote)
    - When `learn()` is invoked and enough samples, trains a logistic
      regression on sparse factor features to output factor weights in [0,1].
    - Persists candidate model JSON under `data/models/candidate_{ts}.json`
      for review/approval by ClosedLoopManager.
    """

    def __init__(self):
        self.buffer: List[Dict[str, Any]] = []
        # current deployed weights (factor -> float)
        self.weights: Dict[str, float] = {}

    def add_feedback(self, event_id: str, factors: List[str], vote: int):
        self.buffer.append({'event_id': event_id, 'factors': list(factors), 'vote': int(vote)})

    def ready(self) -> bool:
        try:
            min_samples = int(os.getenv('ML_MIN_SAMPLES', '100'))
        except Exception:
            min_samples = 100
        return len(self.buffer) >= min_samples

    def _build_feature_matrix(self):
        """Return (X_dicts, y) where X_dicts is list of factor->1 dicts and y is label list."""
        X = []
        y = []
        for rec in self.buffer:
            lab = 1 if int(rec.get('vote') or 0) > 0 else 0
            feats = {f: 1.0 for f in (rec.get('factors') or [])}
            X.append(feats)
            y.append(lab)
        return X, y

    def learn(self) -> Dict[str, float]:
        """Train model and return candidate factor weights.

        If sklearn is available, train logistic regression and compute per-factor
        positive probability contribution. Otherwise fall back to heuristic.
        """
        if not self.buffer:
            return dict(self.weights)

        X_dicts, y = self._build_feature_matrix()

        candidate_weights: Dict[str, float] = {}

        # Lazy-detect sklearn availability to avoid import-time cost
        use_sklearn = False
        try:
            if SKLEARN_AVAILABLE is None:
                try:
                    from sklearn.linear_model import LogisticRegression  # type: ignore
                    from sklearn.feature_extraction import DictVectorizer  # type: ignore
                    SKLEARN_AVAILABLE = True
                except Exception:
                    SKLEARN_AVAILABLE = False
            use_sklearn = bool(SKLEARN_AVAILABLE)
        except Exception:
            use_sklearn = False

        if use_sklearn and len(set(y)) > 1:
            try:
                from sklearn.feature_extraction import DictVectorizer
                from sklearn.linear_model import LogisticRegression
                vec = DictVectorizer(sparse=False)
                X = vec.fit_transform(X_dicts)
                clf = LogisticRegression(max_iter=1000)
                clf.fit(X, y)
                coef = clf.coef_[0]  # shape (n_features,)
                intercept = float(clf.intercept_[0])
                feature_names = vec.get_feature_names_out()
                # Convert log-odds contribution into [0,1] proxy weight
                for fname, c in zip(feature_names, coef):
                    # map coefficient to a [0,1] range via logistic of coef
                    prob = 1.0 / (1.0 + pow(2.718281828459045, - (c + intercept)))
                    candidate_weights[fname] = float(max(0.0, min(1.0, prob)))
            except Exception:
                # fallback to heuristic below
                SKLEARN_ERR = True
        # Heuristic fallback: sum votes per factor and normalize
        if not candidate_weights:
            scores: Dict[str, float] = defaultdict(float)
            counts: Dict[str, int] = defaultdict(int)
            for rec in self.buffer:
                v = 1.0 if int(rec.get('vote') or 0) > 0 else -1.0
                for f in rec.get('factors') or []:
                    scores[f] += v
                    counts[f] += 1
            for f, s in scores.items():
                # normalize by count and map to [0,1]
                avg = s / max(1.0, counts.get(f, 1))
                # avg in [-1,1] -> weight in [0,1]
                candidate_weights[f] = float(max(0.0, min(1.0, 0.5 + 0.5 * avg)))

        # Apply simple guardrail: limit per-update delta to configured MAX_WEIGHT_DELTA (default 0.05)
        max_delta = float(os.getenv('MAX_WEIGHT_DELTA', '0.05') or 0.05)
        applied: Dict[str, float] = {}
        for f, cand in candidate_weights.items():
            base = float(self.weights.get(f, 0.5))
            delta = cand - base
            if delta > max_delta:
                new = base + max_delta
            elif delta < -max_delta:
                new = base - max_delta
            else:
                new = cand
            new = max(0.0, min(1.0, new))
            applied[f] = new

        # Persist candidate to disk for auditing / approval (ClosedLoopManager will persist to DB when used)
        ts = int(time.time())
        candidate_path = os.path.join(MODEL_DIR, f'candidate_{ts}.json')
        try:
            with open(candidate_path, 'w', encoding='utf-8') as fh:
                fh.write(json.dumps({'candidate': applied, 'created_at': ts}, indent=2))
        except Exception:
            pass

        # Do not automatically apply; return candidate for ClosedLoopManager to handle approval
        self.buffer.clear()
        return dict(applied)
