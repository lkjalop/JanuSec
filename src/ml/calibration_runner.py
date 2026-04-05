from __future__ import annotations
from typing import Dict, Any, Iterable, Tuple, List


def _predict_from_weights(weights: Dict[str, float], factors: Iterable[str], threshold: float = 0.5) -> bool:
    score = 0.0
    for f in factors:
        try:
            score += float(weights.get(f, 0.0))
        except Exception:
            score += 0.0
    return score >= threshold


def score_weights_on_labels(weights: Dict[str, float], labels: Iterable[Dict[str, Any]], threshold: float = 0.5) -> Dict[str, float]:
    """Compute precision/recall for given `weights` and labeled examples.

    Each label is expected to be a dict with keys: 'decision_id', 'label', 'factors'.
    The prediction is `True` when the weighted sum over factors >= `threshold`.
    Returns TP/FP/FN/precision/recall and support counts.
    """
    tp = fp = fn = tn = 0
    for rec in labels:
        label = rec.get('label')
        factors = rec.get('factors') or []
        pred_pos = _predict_from_weights(weights, factors, threshold)
        actual_pos = (label == 'true_positive' or label is True or label == 'positive')
        if pred_pos and actual_pos:
            tp += 1
        elif pred_pos and not actual_pos:
            fp += 1
        elif not pred_pos and actual_pos:
            fn += 1
        else:
            tn += 1
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    support = tp + fn
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'precision': precision, 'recall': recall, 'support': support}


def grid_search(candidate_weights: List[Dict[str, Any]], labels: Iterable[Dict[str, Any]], default_threshold: float = 0.5) -> Dict[str, Any]:
    """Evaluate each candidate weight dict and return ranked candidates.

    Each candidate can be either a mapping of factor->weight or a dict with optional 'weights' and 'threshold'.
    The returned summary contains per-candidate metrics and the best candidate index (precision then recall).
    """
    results = []
    best_idx = None
    best_score = (-1.0, -1.0)
    for i, c in enumerate(candidate_weights):
        if isinstance(c, dict) and 'weights' in c:
            weights = c.get('weights') or {}
            threshold = float(c.get('threshold', default_threshold))
        else:
            # Treat `c` as a simple weights dict
            weights = c
            threshold = default_threshold
        metrics = score_weights_on_labels(weights, labels, threshold)
        results.append({'index': i, 'candidate': c, 'metrics': metrics, 'threshold': threshold})
        key = (metrics['precision'], metrics['recall'])
        if key > best_score:
            best_score = key
            best_idx = i
    winner = results[best_idx] if best_idx is not None else None
    return {'winner_index': best_idx, 'winner': winner, 'results': results}


__all__ = ['score_weights_on_labels', 'grid_search']
