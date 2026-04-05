from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException

from src.modules.pilot_eval import PilotEvaluator

router = APIRouter(prefix='/api/v1/pilot', tags=['Pilot'])


@router.post('/eval')
async def pilot_eval(
    ground_truth: List[Dict[str, Any]] = Body(...),
    detections: List[Dict[str, Any]] = Body(...),
    id_key: str = 'id'
) -> Dict[str, Any]:
    if not isinstance(ground_truth, list) or not isinstance(detections, list):
        raise HTTPException(status_code=400, detail='lists_required')
    ev = PilotEvaluator()
    res = ev.evaluate(ground_truth, detections, id_key=id_key)
    return {
        'total': res.total, 'true_pos': res.true_pos, 'false_pos': res.false_pos, 'false_neg': res.false_neg, 'true_neg': res.true_neg,
        'precision': res.precision, 'recall': res.recall, 'coverage': res.coverage,
        'mttr_baseline_hours': res.mttr_baseline_hours, 'mttr_new_hours': res.mttr_new_hours, 'mttr_reduction_pct': res.mttr_reduction_pct,
    }


@router.post('/report/html')
async def pilot_report_html(
    ground_truth: List[Dict[str, Any]] = Body(...),
    detections: List[Dict[str, Any]] = Body(...),
    id_key: str = 'id'
):
    ev = PilotEvaluator()
    res = ev.evaluate(ground_truth, detections, id_key=id_key)
    html = ev.render_html(res)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)

__all__ = ['router']
