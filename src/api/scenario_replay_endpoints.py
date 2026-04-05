"""Scenario replay harness endpoints.

Existing GET /scenario computes naive precision/recall for a stored scenario file.
Extended with:
    - POST /upload to create/append scenario lines (JSON list or single object)
    - PATCH /label to update ground-truth flag for a specific line index
Line format: {"event": {...}, "gt": bool, "factors": [...], "tags": [...]} (tags optional)
Detection positive if any factors present (initial metric). Future: factor weighting.
"""
from __future__ import annotations

import os, json, time
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix='/api/v1/replay', tags=['Replay'])

SCENARIO_DIR = os.getenv('SCENARIO_REPLAY_DIR', 'data/replay_scenarios')

class ScenarioRecord(BaseModel):  # type: ignore[misc]
    event: Dict[str, Any] | None = None
    gt: bool | None = None
    factors: List[str] | None = None
    tags: List[str] | None = None

class ScenarioUploadPayload(BaseModel):  # type: ignore[misc]
    name: str
    records: List[ScenarioRecord] | ScenarioRecord
    append: bool = True  # if False, overwrite existing file

class ScenarioLabelPayload(BaseModel):  # type: ignore[misc]
    name: str
    index: int  # zero-based line index in file
    gt: bool
    factors: List[str] | None = None  # optional update of factors
    tags: List[str] | None = None

try:
    from prometheus_client import Counter  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

_SCENARIO_REPLAY_COUNTER = None
try:
    if Counter is not None:
        _SCENARIO_REPLAY_COUNTER = Counter('scenario_replay_runs_total','Scenario replay runs', ['scenario'])  # type: ignore
except Exception:
    _SCENARIO_REPLAY_COUNTER = None

@router.get('/scenario')
async def replay_scenario(name: str = Query(..., description='Scenario name without extension')) -> Dict[str, Any]:  # type: ignore[misc]
    path = os.path.join(SCENARIO_DIR, f'{name}.log')
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail='scenario_not_found')
    tp = fp = fn = tn = 0
    total = 0
    start = time.time()
    try:
        with open(path,'r',encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                gt = bool(rec.get('gt'))
                factors = rec.get('factors') if isinstance(rec.get('factors'), list) else []
                detected = bool(factors)
                if detected and gt:
                    tp += 1
                elif detected and not gt:
                    fp += 1
                elif (not detected) and gt:
                    fn += 1
                else:
                    tn += 1
                total += 1
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'replay_failed:{e}')
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    try:
        if _SCENARIO_REPLAY_COUNTER is not None:
            _SCENARIO_REPLAY_COUNTER.labels(scenario=name).inc()
    except Exception:
        pass
    return {
        'scenario': name,
        'counts': {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'total': total},
        'precision': precision,
        'recall': recall,
        'duration_seconds': time.time() - start
    }

@router.post('/upload', summary='Upload (create/append) scenario records')  # type: ignore[misc]
async def upload_scenario(payload: ScenarioUploadPayload) -> Dict[str, Any]:  # type: ignore[misc]
    name = (payload.name or '').strip()
    if not name:
        raise HTTPException(status_code=400, detail='missing_name')
    os.makedirs(SCENARIO_DIR, exist_ok=True)
    path = os.path.join(SCENARIO_DIR, f'{name}.log')
    mode = 'a' if (payload.append and os.path.exists(path)) else 'w'
    written = 0
    records: List[ScenarioRecord]
    if isinstance(payload.records, list):
        records = payload.records
    else:
        records = [payload.records]
    try:
        with open(path, mode, encoding='utf-8') as fh:
            for rec in records:
                obj = {
                    'event': rec.event or {},
                    'gt': bool(rec.gt),
                    'factors': rec.factors or [],
                    'tags': rec.tags or []
                }
                fh.write(json.dumps(obj) + '\n')
                written += 1
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'upload_failed:{e}')
    return {'status': 'ok', 'scenario': name, 'written': written, 'mode': mode}

@router.patch('/label', summary='Update ground-truth for a scenario line')  # type: ignore[misc]
async def label_scenario(payload: ScenarioLabelPayload) -> Dict[str, Any]:  # type: ignore[misc]
    name = (payload.name or '').strip()
    if not name:
        raise HTTPException(status_code=400, detail='missing_name')
    path = os.path.join(SCENARIO_DIR, f'{name}.log')
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail='scenario_not_found')
    try:
        with open(path,'r',encoding='utf-8') as fh:
            lines = fh.readlines()
        if payload.index < 0 or payload.index >= len(lines):
            raise HTTPException(status_code=400, detail='invalid_index')
        # Parse, modify, rewrite
        try:
            rec = json.loads(lines[payload.index].strip())
        except Exception:
            rec = {}
        rec['gt'] = bool(payload.gt)
        if isinstance(payload.factors, list):
            rec['factors'] = [str(f) for f in payload.factors if isinstance(f, str)]
        if isinstance(payload.tags, list):
            rec['tags'] = [str(t) for t in payload.tags if isinstance(t, str)]
        lines[payload.index] = json.dumps(rec) + '\n'
        with open(path,'w',encoding='utf-8') as fh:
            fh.writelines(lines)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'label_failed:{e}')
    return {'status': 'ok', 'scenario': name, 'index': payload.index, 'gt': bool(payload.gt)}

__all__ = ['router']