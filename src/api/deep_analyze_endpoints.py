from __future__ import annotations
import time
import uuid
import asyncio
import json
import os
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from src.api.metrics_init import ensure_metrics, _safe_hist, _safe_counter, _safe_gauge
from . import llm_prompts

# Lightweight, deterministic stage implementations for lite-mode tests
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


class GeoIPStage(StageBase):
    name = 'GeoIP'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        # deterministic mock: tag any IP containing '10.' as internal
        rows = context.get('rows', [])
        count_internal = sum(1 for r in rows if isinstance(r, dict) and r.get('ip','').startswith('10.'))
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'internal_count': count_internal}}


class ThreatIntelStage(StageBase):
    name = 'ThreatIntel'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        rows = context.get('rows', [])
        # deterministic mock: file_hash 'deadbeef' is malicious
        hits = [r for r in rows if isinstance(r, dict) and r.get('file_hash') == 'deadbeef']
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'threat_hits': len(hits)}}


class GraphStage(StageBase):
    name = 'GraphTraversal'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        # deterministic mock: if any row has user='admin' return expansion 1
        rows = context.get('rows', [])
        expansions = 1 if any(isinstance(r, dict) and r.get('user') == 'admin' for r in rows) else 0
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'expansions': expansions}}


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


STAGE_REGISTRY = [GeoIPStage(), ThreatIntelStage(), GraphStage(), LLMSummaryStage()]


class EBPFStage(StageBase):
    name = 'eBPF'
    async def run(self, context: dict) -> dict:
        if context.get('analyze_mode') != 'advanced':
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        t0 = time.time()
        # lightweight simulated eBPF summary
        await asyncio.sleep(0)
        elapsed = (time.time()-t0)*1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'ebpf_suspicious_calls': 0}}


class PCAPStage(StageBase):
    name = 'PCAP'
    async def run(self, context: dict) -> dict:
        if context.get('analyze_mode') != 'advanced':
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        t0 = time.time()
        await asyncio.sleep(0)
        elapsed = (time.time()-t0)*1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'pcap_sessions': 0}}


ADVANCED_STAGES = [EBPFStage(), PCAPStage()]


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

    ctx = {'rows': rows, 'options': {**options, 'auto_llm': auto}, 'analyze_mode': payload.get('analyze_mode') or options.get('analyze_mode') or 'basic'}
    results = []
    # Assemble stage list; include advanced stages if requested
    active_stages = list(STAGE_REGISTRY)
    if ctx.get('analyze_mode') == 'advanced':
        active_stages = active_stages + ADVANCED_STAGES
    for stage in active_stages:
        res = await _run_stage(stage, ctx)
        results.append(res)

    report_id = f"report-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    report = {'report_id': report_id, 'results': results, 'rows': len(rows)}
    REPORT_STORE[report_id] = report

    try:
        csv_deep_analyze_inflight.labels().set(0)
    except Exception:
        pass

    # Cross-map stage results into canonical signals for Auto-LLM and frameworks
    canonical = _build_canonical_signals(results, ctx)
    # If auto LLM requested, run the LLMSummary logic to produce a summary from canonical
    if ctx.get('options', {}).get('auto_llm'):
        prompt = llm_prompts.compose_prompt(canonical)
        # LLMSummaryStage already mocked when LLM_MOCK=1; run it asynchronously
        llm_stage = LLMSummaryStage()
        llm_res = await llm_stage.run(ctx)
        if llm_res.get('result') and llm_res['result'].get('llm_summary'):
            canonical['llm_summary'] = llm_res['result']['llm_summary']

    mappings = {
        'mitre': _map_to_mitre(canonical),
        'stride': _map_to_stride(canonical),
        'controls': _map_to_controls(canonical),
        'dread': _map_to_dread(canonical),
        'pasa': _map_to_pasa(canonical),
        'maestro': _map_to_maestro(canonical),
        'diamond': _map_to_diamond(canonical),
    }

    report['canonical'] = canonical
    report['mappings'] = mappings
    REPORT_STORE[report_id] = report

    return JSONResponse({'report_id': report_id, 'results': results, 'canonical': canonical, 'mappings': mappings})


def _build_canonical_signals(stage_results, ctx):
    # Aggregate simple canonical fields from stage results and rows
    canon = {}
    rows = ctx.get('rows', [])
    if rows:
        first = rows[0]
        if isinstance(first, dict):
            for k in ('ip','ip_src','ip_dst','user','host','file_hash','process','file_name'):
                if k in first:
                    canon[k] = first[k]
    # stage-derived signals
    for s in stage_results:
        name = s.get('stage')
        result = s.get('result', {})
        if name == 'ThreatIntel' and result.get('threat_hits'):
            canon['threat_hits'] = result.get('threat_hits')
        if name == 'GeoIP' and result.get('internal_count') is not None:
            canon['internal_count'] = result.get('internal_count')
        if name == 'GraphTraversal' and result.get('expansions') is not None:
            canon['graph_expansions'] = result.get('expansions')
        if name == 'LLMSummary' and result.get('llm_summary'):
            canon['llm_summary'] = result.get('llm_summary')
    return canon


def _map_to_mitre(canonical):
    tags = []
    if canonical.get('threat_hits', 0) > 0:
        tags.append('T1027')
    if canonical.get('graph_expansions', 0) > 0:
        tags.append('T1087')
    return tags


def _map_to_stride(canonical):
    tags = []
    if canonical.get('threat_hits', 0) > 0:
        tags.append('Tampering')
    if canonical.get('internal_count', 0) > 0:
        tags.append('Repudiation')
    return tags


def _map_to_controls(canonical):
    # map to example control IDs
    ctr = []
    if canonical.get('threat_hits', 0) > 0:
        ctr.append('AC-7')
    return ctr


def _map_to_dread(canonical):
    score = 0
    if canonical.get('threat_hits', 0) > 0:
        score += 6
    if canonical.get('graph_expansions', 0) > 0:
        score += 2
    return {'score': score}


def _map_to_pasa(canonical):
    # placeholder PASA mapping
    return {'pasa_level': 'medium' if canonical.get('threat_hits') else 'low'}


def _map_to_maestro(canonical):
    return {'maestro_tags': ['initial_access'] if canonical.get('threat_hits') else []}


def _map_to_diamond(canonical):
    # return simple diamond model mapping
    return {'adversary': 'unknown' if canonical.get('threat_hits') else None, 'capability': []}


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
            yield f"event: stage\ndata: {json.dumps({'stage': s, 'status': 'done'})}\n\n"
            await asyncio.sleep(0.01)
        yield f"event: done\ndata: {json.dumps({'status':'done'})}\n\n"

    return Response(gen(), media_type='text/event-stream')
