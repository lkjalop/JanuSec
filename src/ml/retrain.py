import threading
import time
import os
import json
from typing import List, Dict, Any

RETRAIN_QUEUE: List[Dict[str, Any]] = []
RETRAIN_LOCK = threading.Lock()

RETRAIN_THRESHOLD = int(os.getenv('RETRAIN_THRESHOLD', '20'))
MODEL_SAVE_PATH = os.path.join(os.getcwd(), 'data', 'models', 'ml_score.pkl')


def enqueue_labels(labels: List[Dict[str, Any]]):
    """Add labeled examples to retrain queue."""
    with RETRAIN_LOCK:
        RETRAIN_QUEUE.extend(labels)


def queue_size() -> int:
    with RETRAIN_LOCK:
        return len(RETRAIN_QUEUE)


def drain_queue() -> List[Dict[str, Any]]:
    with RETRAIN_LOCK:
        items = list(RETRAIN_QUEUE)
        RETRAIN_QUEUE.clear()
        return items


def _train_from_queue():
    try:
        # Drain the in-memory queue first (for cases where enqueue_labels used)
        items = drain_queue()
        # Also call retrain_consumer to pull from durable outbox and write NDJSON files
        try:
            from src.api.retrain_consumer import consume_retrain_tasks
            processed = consume_retrain_tasks(limit=1000)
        except Exception:
            processed = []

        # If no items and no processed outbox rows, nothing to do
        if not items and not processed:
            return False

        # Aggregate training examples from training dir
        training_dir = os.path.join(os.getcwd(), 'data', 'training')
        examples = []
        if os.path.isdir(training_dir):
            for fn in sorted(os.listdir(training_dir)):
                if not fn.endswith('.ndjson'):
                    continue
                path = os.path.join(training_dir, fn)
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                obj = json.loads(line)
                                examples.append(obj)
                            except Exception:
                                continue
                except Exception:
                    continue

        # Also include any items directly enqueued (if they are in-memory payloads)
        for it in items:
            try:
                if isinstance(it, dict):
                    examples.append(it)
            except Exception:
                continue

        if not examples:
            return False

        # Extract features and targets; expect a minimal payload shape containing report_id,row_id,payload
        from src.ml.feature_extractor import extract_row_features
        X = []
        y = []
        for ex in examples:
            # accept payload under 'payload' or 'original_row' keys
            row = None
            try:
                if isinstance(ex, dict) and ex.get('payload'):
                    row = ex.get('payload')
                elif isinstance(ex, dict) and ex.get('original_row'):
                    row = ex.get('original_row')
                elif isinstance(ex, dict) and ex.get('raw'):
                    row = ex.get('raw')
                else:
                    row = ex
                # compute a synthetic target if label present (e.g., 'score'), else fallback to heuristic mapping
                target = None
                if isinstance(ex, dict) and ex.get('score') is not None:
                    target = float(ex.get('score'))
                elif isinstance(row, dict) and row.get('score') is not None:
                    target = float(row.get('score'))
                else:
                    # fallback using heuristic used in scripts/train_ml_score
                    try:
                        # reuse scoring heuristic from deep_analyze
                        from src.api.deep_analyze_endpoints import _compute_ml_score_for_row
                        target = float(_compute_ml_score_for_row(row or {}, None))
                    except Exception:
                        target = 0.0
                feats = extract_row_features(row or {}, {'created': int(time.time())})
                X.append(feats)
                y.append(float(target))
            except Exception:
                continue

        # Train model bundle and save together with StandardScaler
        from src.ml.model import train_model, save_model
        # Fit a StandardScaler on numeric matrix for persistence
        try:
            from sklearn.preprocessing import StandardScaler
            import numpy as _np
            feat_names = list(X[0].keys()) if X else []
            Xmat = _np.array([[float(x.get(f, 0.0)) for f in feat_names] for x in X])
            scaler = StandardScaler()
            Xscaled = scaler.fit_transform(Xmat)
            # convert scaled back to list-of-dicts format expected by train_model (train_model accepts dicts but will convert)
            X_scaled_dicts = [ {feat_names[i]: float(Xscaled[r,i]) for i in range(len(feat_names))} for r in range(Xscaled.shape[0]) ]
            model_bundle = train_model(X_scaled_dicts, y, None)
            # attach scaler to bundle
            model_bundle['scaler'] = scaler
            # persist model bundle and scaler
            os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
            save_model(model_bundle, MODEL_SAVE_PATH)
            # also persist scaler separately
            try:
                from src.ml.scaler import save_scaler
                scaler_path = os.path.join(os.path.dirname(MODEL_SAVE_PATH), 'ml_score_scaler.pkl')
                save_scaler(scaler, scaler_path)
            except Exception:
                # best-effort: pickle scaler directly
                try:
                    import pickle
                    scaler_path = os.path.join(os.path.dirname(MODEL_SAVE_PATH), 'ml_score_scaler.pkl')
                    with open(scaler_path, 'wb') as fh:
                        pickle.dump(scaler, fh)
                except Exception:
                    pass
            return True
        except Exception:
            # fallback: try to train without scaler
            try:
                model_bundle = train_model(X, y, None)
                os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
                save_model(model_bundle, MODEL_SAVE_PATH)
                return True
            except Exception:
                return False
    except Exception:
        return False


def start_background_retrainer(interval_seconds: int = 60):
    def _loop():
        while True:
            try:
                if queue_size() >= RETRAIN_THRESHOLD:
                    _train_from_queue()
            except Exception:
                pass
            time.sleep(interval_seconds)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


def run_retrain_once() -> bool:
    """Expose single-run retrain for scheduler jobs."""
    return bool(_train_from_queue())
