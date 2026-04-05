"""Background recalibration stub.

Periodically samples labeled events (via FACTOR_ATTRIBUTIONS + LABELS) and
computes a simple logistic fit (k, x0) proposal by searching over a small grid.
The result is written to a file path defined by env VAR `RISK_RECALIBRATION_OUT` or
kept in-memory in `LAST_PROPOSAL` if not set.

This module does NOT apply proposals to runtime; it only writes proposals for
review. It is safe to run as a background task.
"""
from __future__ import annotations

import os
import time
import threading
from typing import Optional, Tuple, List
import json
import math

from core.factor_attribution_store import FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS
from core.factor_stats_manager import FACTOR_STATS
import math
import yaml
from core.metrics.registry import metric_gauge

# Gauges
_GAUGE_LAST_K = metric_gauge('risk', 'calibration_last_k', 'Last proposed sigmoid k')
_GAUGE_LAST_X0 = metric_gauge('risk', 'calibration_last_x0', 'Last proposed sigmoid x0')
_GAUGE_LAST_SAMPLES = metric_gauge('risk', 'calibration_last_samples', 'Samples used for last proposal')


def _collect_samples(limit: int = 2000):
    rows = []
    qualifying = {'tp','fp','benign'}
    for snap in FACTOR_ATTRIBUTIONS.recent(limit * 2):
        labels = LABELS.get(snap.event_id)
        lab = None
        for l in reversed(labels):
            if l.label in qualifying:
                lab = l.label
                break
        if not lab:
            continue
        rows.append((snap.raw_score if snap.raw_score is not None else snap.score, 1 if lab == 'tp' else 0))
        if len(rows) >= limit:
            break
    return rows


def _fit_simple_sigmoid(samples: List[Tuple[float,int]]):
    # Grid search for k in [1,8], x0 in [0.2,0.8]
    if not samples:
        return None
    best = None
    best_ll = -1e18
    for k in [1.0,2.0,3.0,4.0,6.0,8.0]:
        for x0 in [0.2,0.3,0.4,0.5,0.6,0.7,0.8]:
            ll = 0.0
            for x,y in samples:
                p = 1.0 / (1.0 + math.exp(-k * (x - x0)))
                # avoid log(0)
                p = max(1e-6, min(1 - 1e-6, p))
                ll += y * math.log(p) + (1 - y) * math.log(1 - p)
            if ll > best_ll:
                best_ll = ll
                best = (k, x0, ll)
    return best


LAST_PROPOSAL: dict | None = None
PROPOSAL_HISTORY: list[dict] = []


def get_last_proposal() -> dict | None:
    return LAST_PROPOSAL


def get_proposal_history(limit: int = 100) -> list[dict]:
    if not PROPOSAL_HISTORY:
        return []
    return list(reversed(PROPOSAL_HISTORY))[:limit]


def propose_and_write(limit: int = 1000) -> Optional[dict]:
    global LAST_PROPOSAL
    samples = _collect_samples(limit)
    fit = _fit_simple_sigmoid(samples)
    if not fit:
        return None
    k, x0, ll = fit
    # Compute additional analytics: factor prevalence among TP and FP
    tp_counts: dict = {}
    fp_counts: dict = {}
    qual = {'tp','fp','benign'}
    for snap in FACTOR_ATTRIBUTIONS.recent(limit * 2):
        labels = LABELS.get(snap.event_id)
        lab = None
        for l in reversed(labels):
            if l.label in qual:
                lab = l.label
                break
        if not lab:
            continue
        for f in snap.factors:
            if lab == 'tp':
                tp_counts[f] = tp_counts.get(f,0) + 1
            else:
                fp_counts[f] = fp_counts.get(f,0) + 1

    # KS statistic between TP and FP score distributions
    tp_scores = [x for x,y in samples if y==1]
    fp_scores = [x for x,y in samples if y==0]
    def _ks(a,b):
        if not a or not b:
            return None
        a_sorted = sorted(a)
        b_sorted = sorted(b)
        all_vals = sorted(set(a_sorted + b_sorted))
        n = len(a_sorted)
        m = len(b_sorted)
        i=j=0
        max_diff = 0.0
        for v in all_vals:
            while i < n and a_sorted[i] <= v:
                i+=1
            while j < m and b_sorted[j] <= v:
                j+=1
            fa = i / n
            fb = j / m
            max_diff = max(max_diff, abs(fa-fb))
        return max_diff

    ks = _ks(tp_scores, fp_scores)

    proposal = {
        'ts': time.time(),
        'k': float(k),
        'x0': float(x0),
        'loglik': float(ll),
        'samples': len(samples),
        'tp_factor_counts': tp_counts,
        'fp_factor_counts': fp_counts,
        'ks_tp_fp': ks,
    }
    out_path = os.getenv('RISK_RECALIBRATION_OUT')
    try:
        if out_path:
            with open(out_path, 'w', encoding='utf-8') as fh:
                json.dump(proposal, fh)
        LAST_PROPOSAL = proposal
        # Append to in-memory audit trail
        try:
            proposal['accepted'] = False
            proposal['rejected'] = False
            PROPOSAL_HISTORY.append(proposal)
        except Exception:
            pass
        # update gauges
        try:
            _GAUGE_LAST_K.set(float(proposal.get('k',0.0)))
            _GAUGE_LAST_X0.set(float(proposal.get('x0',0.0)))
            _GAUGE_LAST_SAMPLES.set(int(proposal.get('samples',0)))
        except Exception:
            pass
        # Optionally write an append-only audit file
        audit_path = os.getenv('RISK_RECALIBRATION_AUDIT')
        if audit_path:
            try:
                with open(audit_path, 'a', encoding='utf-8') as ah:
                    ah.write(json.dumps(proposal) + "\n")
            except Exception:
                pass
    except Exception:
        LAST_PROPOSAL = proposal
    return proposal


def mark_proposal(ts: float, accept: bool = True) -> bool:
    """Mark a proposal as accepted/rejected. Persist accepted proposals to YAML if configured."""
    found = None
    for p in PROPOSAL_HISTORY:
        if abs(p.get('ts',0) - ts) < 1e-6:
            found = p
            break
    if not found:
        return False
    if accept:
        found['accepted'] = True
        found['rejected'] = False
        # persist accepted proposal to history YAML
        try:
            hist_path = os.getenv('RISK_RECALIBRATION_HISTORY_FILE')
            if hist_path:
                with open(hist_path, 'a', encoding='utf-8') as fh:
                    yaml.safe_dump(found, fh)
                    fh.write('\n')
        except Exception:
            pass
        # Persist to repository if present
        try:
            from repositories.calibration_proposals_repo import persist_proposal
            try:
                persist_proposal(found)
            except Exception:
                pass
        except Exception:
            pass
        # Optionally apply sigmoid override file
        try:
            auto = os.getenv('RISK_SIGMOID_AUTO_APPLY','0').lower() in {'1','true','yes'}
            out = os.getenv('RISK_SIGMOID_OUT','risk_sigmoid.json')
            if auto:
                with open(out,'w',encoding='utf-8') as oh:
                    json.dump({'k': found['k'],'x0': found['x0']}, oh)
                # apply into running process if available
                try:
                    from core import risk_score as _rs
                    if hasattr(_rs, 'apply_sigmoid_override'):
                        _rs.apply_sigmoid_override(found['k'], found['x0'])
                except Exception:
                    pass
        except Exception:
            pass
    else:
        found['accepted'] = False
        found['rejected'] = True
    return True


def evaluate_auto_accept(min_samples: int = 50, min_ll_delta: float = 1.0) -> dict:
    """Evaluate whether last proposal should be auto-accepted based on simple policy.

    Policy: accept if samples >= min_samples and loglik improvement over previous >= min_ll_delta.
    Returns decision dict.
    """
    last = get_last_proposal()
    if not last:
        return {'ok': False, 'reason': 'no_proposal'}
    # find previous proposal
    prev = None
    for p in reversed(PROPOSAL_HISTORY[:-1]):
        prev = p
        break
    samples = int(last.get('samples',0))
    if samples < min_samples:
        return {'ok': False, 'reason': 'insufficient_samples', 'samples': samples}
    if prev is None:
        return {'ok': True, 'reason': 'no_previous', 'samples': samples}
    if (last.get('loglik',0) - prev.get('loglik', -1e9)) >= float(min_ll_delta):
        return {'ok': True, 'reason': 'improvement', 'delta': last.get('loglik',0)-prev.get('loglik',0)}
    return {'ok': False, 'reason': 'insufficient_improvement', 'delta': last.get('loglik',0)-prev.get('loglik',0)}


def start_background(interval: int = 3600):
    def _loop():
        while True:
            try:
                propose_and_write()
            except Exception:
                pass
            time.sleep(interval)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


__all__ = ['propose_and_write','start_background','LAST_PROPOSAL']
