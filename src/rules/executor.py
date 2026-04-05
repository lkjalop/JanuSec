from __future__ import annotations

import os
import re
import logging
from typing import Any, Dict, List

from src.rules import loader

LOGGER = logging.getLogger(__name__)


def _get_by_path(obj: Dict[str, Any], path: str) -> Any:
    try:
        parts = [p for p in path.split('.') if p]
        cur = obj
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur
    except Exception:
        return None


def _match_condition(event: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    ctype = str(cond.get('type') or 'equals').lower()
    path = str(cond.get('path') or '')
    val = cond.get('value')
    got = _get_by_path(event, path) if path else event.get(cond.get('field'))
    try:
        if ctype == 'equals':
            return str(got) == str(val)

        if ctype == 'contains':
            if isinstance(got, (list, tuple)):
                return val in got
            if isinstance(got, str):
                return str(val) in got
            return False

        if ctype == 'regex':
            if not isinstance(got, str):
                return False
            return re.search(str(val), got) is not None

        if ctype == 'temporal_count':
            # expects: field, value, threshold, window_seconds, and optional 'history' list in event
            try:
                field = cond.get('field')
                val = cond.get('value')
                thresh = int(cond.get('threshold') or 1)
                window = int(cond.get('window_seconds') or 60)
                history = event.get('history') or []
                from src.rules.temporal import within_window

                cnt = within_window(history, field, val, window)
                return cnt > thresh
            except Exception:
                return False

    except Exception:
        return False
    return False


def _severity_to_score(sev: str) -> float:
    m = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.5,
        'low': 0.2,
    }
    try:
        return float(m.get((sev or '').lower(), 0.3))
    except Exception:
        return 0.3


def _apply_scoring_boosts(base: float, event: Dict[str, Any]) -> float:
    score = float(base)
    try:
        factors = event.get('factors') or []
        if isinstance(factors, (list, tuple)) and len(factors) >= 3:
            score += min(0.15, 0.03 * len(factors))
        # temporal hint: if event has timestamp_recent flag
        if event.get('recent'):
            score += 0.05
    except Exception:
        pass
    return min(1.0, score)


def _attempt_hopgraph_inspect(event: Dict[str, Any]) -> Dict[str, Any]:
    # Best-effort: import join helpers and execute lookups; tolerate absence
    try:
        from src.rules.hopgraph_joins import join_identity, join_network  # type: ignore
    except Exception:
        return {}
    ctx = {}
    try:
        try:
            id_ctx = join_identity(event)
            if id_ctx:
                ctx['identity'] = id_ctx
        except Exception:
            pass
        try:
            net_ctx = join_network(event)
            if net_ctx:
                ctx['network'] = net_ctx
        except Exception:
            pass
    except Exception:
        pass
    return ctx


def load_rules(rules_dir: str | None = None) -> List[Dict[str, Any]]:
    rd = rules_dir or os.getenv('RULES_DIR') or os.path.join(os.getcwd(), 'rules')
    try:
        rules = loader.load_rules_from_dir(rd)
        return rules
    except Exception as exc:
        LOGGER.warning('Failed to load rules from %s: %s', rd, exc)
        return []


def evaluate_event(event: Dict[str, Any], rules: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """Evaluate a single event against loaded rules and return ranked decisions.

    Decision format: {rule_id, name, matched, score, severity, mitre, evidence, hopgraph}
    """
    rules = rules if rules is not None else load_rules(None)
    decisions: List[Dict[str, Any]] = []
    for r in rules:
        try:
            conditions = r.get('conditions') or []
            if not conditions:
                # skip rules without conditions
                continue
            matched_all = True
            for c in conditions:
                if not _match_condition(event, c):
                    matched_all = False
                    break
            if not matched_all:
                continue
            base = r.get('score') if r.get('score') is not None else _severity_to_score(r.get('severity') or '')
            score = _apply_scoring_boosts(base, event)
            hopctx = _attempt_hopgraph_inspect(event)
            dec = {
                'rule_id': r.get('id') or r.get('name'),
                'name': r.get('name'),
                'matched': True,
                'score': round(float(score), 4),
                'severity': r.get('severity'),
                'mitre': r.get('mitre') or [],
                'evidence': {'event_snapshot': event, 'rule': r},
                'hopgraph': hopctx,
            }
            decisions.append(dec)
        except Exception as exc:
            LOGGER.exception('Rule eval error for rule %s: %s', r.get('id'), exc)
            continue
    # sort by score descending
    decisions.sort(key=lambda d: d.get('score', 0.0), reverse=True)
    return decisions


def evaluate_batch(events: List[Dict[str, Any]], rules: List[Dict[str, Any]] | None = None) -> Dict[str, List[Dict[str, Any]]]:
    rules = rules if rules is not None else load_rules(None)
    out = {}
    for i, ev in enumerate(events):
        out_key = ev.get('event_id') or f'row-{i}'
        out[out_key] = evaluate_event(ev, rules)
    return out


__all__ = ['load_rules', 'evaluate_event', 'evaluate_batch']
