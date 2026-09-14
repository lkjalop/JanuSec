from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class EvalResult:
    total: int
    true_pos: int
    false_pos: int
    false_neg: int
    true_neg: int
    precision: float
    recall: float
    coverage: float
    mttr_baseline_hours: float
    mttr_new_hours: float
    mttr_reduction_pct: float


def _safe_div(a: float, b: float) -> float:
    return (a / b) if b else 0.0


class PilotEvaluator:
    def __init__(self):
        pass

    def evaluate(self, ground_truth: List[Dict[str, Any]], detections: List[Dict[str, Any]], id_key: str = 'id') -> EvalResult:
        truth_map = {str(x[id_key]): bool(x.get('malicious', False)) for x in ground_truth if id_key in x}
        det_map = {str(x[id_key]): bool((x.get('verdict') or '').lower() in ('malicious','block','escalate')) for x in detections if id_key in x}
        ids = set(truth_map.keys()) | set(det_map.keys())
        tp=fp=fn=tn=0
        for _id in ids:
            truth = truth_map.get(_id, False)
            det = det_map.get(_id, False)
            if truth and det: tp += 1
            elif (not truth) and det: fp += 1
            elif truth and (not det): fn += 1
            else: tn += 1
        total = tp+fp+fn+tn
        precision = _safe_div(tp, tp+fp)
        recall = _safe_div(tp, tp+fn)
        coverage = _safe_div(tp+fp, total)
        # Simple MTTR calculation: baseline 24h, new = 24h - (automation_gain_hours per TP)
        mttr_baseline = 24.0
        automation_gain = 6.0  # assume automation saves 6 hours per true positive triage
        if tp:
            mttr_new = max(1.0, mttr_baseline - (automation_gain * _safe_div(tp, max(total,1))))
        else:
            mttr_new = mttr_baseline
        mttr_reduction = max(0.0, (mttr_baseline - mttr_new) / mttr_baseline * 100.0)
        return EvalResult(
            total=total, true_pos=tp, false_pos=fp, false_neg=fn, true_neg=tn,
            precision=precision, recall=recall, coverage=coverage,
            mttr_baseline_hours=mttr_baseline, mttr_new_hours=mttr_new,
            mttr_reduction_pct=mttr_reduction,
        )

    def render_html(self, res: EvalResult) -> str:
        def pct(x: float) -> str:
            return f"{round(x*100.0,1)}%"
        return f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>Pilot KPI</title>
        <style>body{{background:#0b0e14;color:#e8ebf0;font-family:Arial,sans-serif;padding:16px}} .card{{background:#151922;border:1px solid #2A3142;border-radius:8px;padding:12px;margin-bottom:12px}}
        .kpi{{display:inline-block;margin:6px 8px 0 0;padding:6px 10px;border:1px solid #2A3142;border-radius:999px;background:#1C2230}}</style></head>
        <body>
          <h2>Pilot Evaluation KPI</h2>
          <div class='card'>
            <div class='kpi'>Total: <b>{res.total}</b></div>
            <div class='kpi'>TP: <b>{res.true_pos}</b></div>
            <div class='kpi'>FP: <b>{res.false_pos}</b></div>
            <div class='kpi'>FN: <b>{res.false_neg}</b></div>
            <div class='kpi'>TN: <b>{res.true_neg}</b></div>
          </div>
          <div class='card'>
            <div class='kpi'>Precision: <b>{pct(res.precision)}</b></div>
            <div class='kpi'>Recall: <b>{pct(res.recall)}</b></div>
            <div class='kpi'>Coverage: <b>{pct(res.coverage)}</b></div>
          </div>
          <div class='card'>
            <div class='kpi'>MTTR Baseline: <b>{res.mttr_baseline_hours}h</b></div>
            <div class='kpi'>MTTR New: <b>{round(res.mttr_new_hours,1)}h</b></div>
            <div class='kpi'>MTTR Reduction: <b>{round(res.mttr_reduction_pct,1)}%</b></div>
          </div>
          <div class='card'>Target: Precision >= 75% — Status: <b>{'OK' if res.precision>=0.75 else 'Needs Improvement'}</b></div>
        </body></html>"""
