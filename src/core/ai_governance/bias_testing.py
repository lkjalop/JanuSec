from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _get_attr(obj: Any, attr: str) -> Any:
    try:
        if isinstance(obj, dict):
            return obj.get(attr)
        return getattr(obj, attr, None)
    except Exception:
        return None


def _is_positive(decision: Any, include_suspicious: bool = False) -> bool:
    v = str(_get_attr(decision, 'verdict') or '').lower()
    if v == 'malicious':
        return True
    if include_suspicious and v == 'suspicious':
        return True
    return False


def compute_bias(decisions: List[Any], group_attr: str, include_suspicious: bool = False) -> Dict[str, Any]:
    """Compute simple fairness metrics by a grouping attribute.

    - positive_rate per group (malicious [+ suspicious optional] over total)
    - disparate impact ratio (min positive_rate / max positive_rate)
    - equal opportunity difference approximation (max - min positive_rate)
    """
    groups: Dict[str, Tuple[int, int]] = {}  # group -> (total, positive)
    for d in decisions:
        g = _get_attr(d, group_attr)
        if g is None:
            g = 'unknown'
        g = str(g)
        tot, pos = groups.get(g, (0, 0))
        tot += 1
        if _is_positive(d, include_suspicious):
            pos += 1
        groups[g] = (tot, pos)

    rows: List[Dict[str, Any]] = []
    rates: List[float] = []
    for g, (tot, pos) in groups.items():
        rate = (pos / tot) if tot else 0.0
        rows.append({'group': g, 'count': tot, 'positive': pos, 'positive_rate': round(rate, 4)})
        rates.append(rate)
    if not rates:
        return {'attribute': group_attr, 'groups': [], 'dir': None, 'eod': None, 'flagged': False}
    mx = max(rates)
    mn = min(rates)
    dir_val = (mn / mx) if mx > 0 else 0.0
    eod = mx - mn
    flagged = (dir_val < 0.8) and (mx > 0)  # 80% rule
    return {
        'attribute': group_attr,
        'groups': rows,
        'dir': round(dir_val, 4),
        'eod': round(eod, 4),
        'flagged': flagged,
        'notes': 'Heuristic fairness metrics for decision outcomes (no ground truth).'
    }


__all__ = ['compute_bias']

