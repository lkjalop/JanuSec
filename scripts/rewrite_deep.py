content = '''from __future__ import annotations
import time
import uuid
import asyncio
import json
import os
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from src.api.metrics_init import ensure_metrics, _safe_hist, _safe_counter, _safe_gauge
from . import llm_prompts

# Minimal deep_analyze endpoints (single-copy file)
router = APIRouter(prefix='/api/v1/assessments')
REPORT_STORE: dict[str, dict] = {}

ensure_metrics()
csv_stage_latency = _safe_hist('csv_stage_latency_seconds', 'Latency per csv deep analyze stage', ['stage'])
csv_deep_analyze_total = _safe_counter('csv_deep_analyze_total', 'Total deep analyze pipeline runs', ['auto_llm'])
csv_deep_analyze_inflight = _safe_gauge('csv_deep_analyze_inflight', 'In-flight deep analyze tasks')


class StageBase:
    name = 'base'
    async def run(self, context: dict) -> dict:
        return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}


class LLMSummaryStage(StageBase):
    name = 'LLMSummary'
    async def run(self, context: dict) -> dict:
        start = time.time()
        auto = context.get('options', {}).get('auto_llm', False)
        if not auto:
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        prompt = llm_prompts.compose_prompt(context)
        if os.getenv('LLM_MOCK','1') in {'1','true','yes'}:
            await asyncio.sleep(0)
            summary = {'text': 'Auto-LLM Mock Summary: top factors include geoip_anomaly, threat_intel_hit.'}
        else:
            summary = {'text': 'LLM not configured'}
        elapsed = (time.time() - start) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'llm_summary': summary}}


STAGE_REGISTRY = [LLMSummaryStage()]


async def _run_stage(stage: StageBase, ctx: dict) -> dict:
    t0 = time.time()
    try:
        res = await stage.run(ctx)
    except Exception as e:
        res = {'stage': stage.name, 'status': 'error', 'error': str(e), 'elapsed_ms': (time.time()-t0)*1000.0}
    try:
        csv_stage_latency.labels(stage=stage.name).observe(res.get('elapsed_ms', 0.0))
    except Exception:
        pass
    return res


@router.post('/deep_analyze')
async def deep_analyze(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    rows = payload.get('rows') or []
    options = payload.get('options') or {}
    try:
        csv_deep_analyze_inflight.labels().set(1)
    except Exception:
        try: csv_deep_analyze_inflight.set(1)
        except Exception: pass
    auto = bool(options.get('auto_llm') or payload.get('auto_llm') or False)
    try:
        csv_deep_analyze_total.labels(auto_llm=str(bool(auto))).inc()
    except Exception:
        try: csv_deep_analyze_total.inc(1, labels={'auto_llm': str(bool(auto))})
        except Exception: pass

    ctx = {'rows': rows, 'options': {**options, 'auto_llm': auto}}
    results = []
    for stage in STAGE_REGISTRY:
        res = await _run_stage(stage, ctx)
        results.append(res)

    report_id = f"report-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    report = {'report_id': report_id, 'results': results, 'rows': len(rows)}
    REPORT_STORE[report_id] = report

    try:
        csv_deep_analyze_inflight.labels().set(0)
    except Exception:
        pass

    return JSONResponse({'report_id': report_id, 'results': results})


@router.get('/report/{report_id}')
async def get_report(report_id: str):
    r = REPORT_STORE.get(report_id)
    if not r:
        return JSONResponse({'detail': 'Not found'}, status_code=404)
    return JSONResponse(r)


@router.get('/csv/deep_analyze/stream')
async def deep_analyze_stream(request: Request):
    async def gen():
        stages = [s.name for s in STAGE_REGISTRY]
        for s in stages:
            if await request.is_disconnected():
                break
            yield f"event: stage\\ndata: {json.dumps({'stage': s, 'status': 'done'})}\\n\\n"
            await asyncio.sleep(0.01)
        yield f"event: done\\ndata: {json.dumps({'status':'done'})}\\n\\n"

    return Response(gen(), media_type='text/event-stream')
'''
open('d:/AI/Threat_thy_sniffer/src/api/deep_analyze_endpoints.py','w',encoding='utf-8').write(content)
print('WROTE')