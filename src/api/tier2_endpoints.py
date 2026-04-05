from __future__ import annotations
import os
import time
import json
import asyncio
from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from src.core.platform_scope import is_azure_cloud_funnel
from src.analysis.offline_workbook_assessment import build_grounded_tier2_json

router = APIRouter(prefix='/api/v1/csv', tags=['Tier2'])


def _env_mode() -> str:
    raw = (os.getenv('ENV') or os.getenv('APP_ENV') or 'dev').strip().lower()
    if raw in {'prod', 'production'}:
        return 'prod'
    if raw in {'stage', 'staging'}:
        return 'staging'
    return 'dev'


def _is_live_mode() -> bool:
    return _env_mode() in {'staging', 'prod'}


def _allow_tier2_placeholder() -> bool:
    if is_azure_cloud_funnel():
        return False
    if not _is_live_mode():
        return True
    return os.getenv('TIER2_ALLOW_PLACEHOLDER', '0').lower() in {'1', 'true', 'yes'}

def _finops_guard(cost_estimate: float, tenant: str | None = None) -> None:
    try:
        budget_left = float(os.getenv('T2_BUDGET_LEFT', '9999'))
        # Per-tenant override budget if available
        if tenant:
            try:
                from src.core.config.tenant_overrides import get_overrides  # type: ignore
                ov = get_overrides(tenant) or {}
                t_budget = ov.get('tier2_budget_left') or ov.get('t2_budget_left')
                if isinstance(t_budget, (int, float)):
                    budget_left = float(t_budget)
            except Exception:
                pass
        if cost_estimate > budget_left:
            raise HTTPException(status_code=402, detail='budget_exceeded')
    except Exception:
        pass

def _compose_prompt(payload: dict) -> str:
    # Use the centralized Tier2 prompt builder when available to enrich with graph/TI
    try:
        from src.ai.tier2_prompts import build_tier2_prompt_context  # type: ignore
        prompt_ctx = build_tier2_prompt_context(payload)
    except Exception:
        prompt_ctx = {
            'sections': ['verdict','actions','evidence','reasoning','timeline','threat_intel','graph_context','business_impact','recommendations','controls','mitre','next_steps'],
            'context': {'assessment_id': payload.get('assessment_id'), 'rows_count': len(payload.get('rows') or []), 'org': payload.get('org') or payload.get('tenant')},
            'templates': {},
            'few_shot_examples': [],
            'sample_evidence': (payload.get('rows') or [])[:5]
        }

    # Instructions to the model: return a strict JSON object, one key per section
    instructions = []
    instructions.append('You are a senior SOC analyst. Produce a JSON object whose top-level keys are: ' + ', '.join(prompt_ctx.get('sections', [])))
    instructions.append('For each section, follow the given template and include a confidence score between 0 and 1 in a field named "confidence". Use arrays for lists of items and strings for short summaries.')
    instructions.append('If information is missing, add a field "missing_info" listing the most useful logs or telemetry that would help (e.g., EDR process telemetry, full PCAP, authentication logs, proxy logs).')
    instructions.append('RETURN STRICT JSON ONLY. Do not include markdown, commentary, or analysis outside the JSON.')

    few = prompt_ctx.get('few_shot_examples') or []
    few_text = ''
    for ex in few:
        try:
            few_text += '\nEXAMPLE_INPUT:\n' + json.dumps(ex.get('input') or {}) + '\nEXAMPLE_OUTPUT:\n' + json.dumps(ex.get('output') or {}) + '\n'
        except Exception:
            continue

    payload_fragment = json.dumps({'context': prompt_ctx.get('context', {}), 'sample_evidence': prompt_ctx.get('sample_evidence', [])})
    prompt = '\n'.join(instructions) + '\n\n' + few_text + '\n\n' + 'INPUT_CONTEXT:\n' + payload_fragment + '\n\n' + 'Respond with JSON.'
    return prompt

async def _stream_chunks(text: str):
    for i in range(0, len(text), 256):
        yield {'chunk': text[i:i+256], 'ts': int(time.time())}
        await asyncio.sleep(0)


def _grounded_tier2_text(payload: Dict[str, Any]) -> str:
    return json.dumps(build_grounded_tier2_json(payload))


def _generate_tier2_response(prompt: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if os.getenv('LLM_MOCK', '0').lower() in {'1', 'true', 'yes'}:
        return {'text': _grounded_tier2_text(payload), 'meta': {'provider': 'grounded_mock'}}
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as LLM_CLIENT, get_client_status  # type: ignore
    except Exception as exc:
        if _allow_tier2_placeholder():
            return {'text': _grounded_tier2_text(payload), 'meta': {'error': str(exc), 'provider': 'grounded_fallback'}}
        raise HTTPException(status_code=503, detail='tier2_provider_unavailable')

    status = get_client_status(LLM_CLIENT)
    if not status.get('available'):
        if _allow_tier2_placeholder():
            return {'text': _grounded_tier2_text(payload), 'meta': {'provider_status': status, 'provider': 'grounded_fallback'}}
        raise HTTPException(status_code=503, detail='tier2_provider_unavailable')

    try:
        model_name = os.getenv('OLLAMA_TIER2_MODEL') or os.getenv('T2_MODEL') or None
        if model_name:
            return LLM_CLIENT.generate(prompt, max_tokens=2048, tenant_id=(payload.get('org') or None), model=model_name)
        return LLM_CLIENT.generate(prompt, max_tokens=2048, tenant_id=(payload.get('org') or None))
    except Exception as exc:
        if _allow_tier2_placeholder():
            return {'text': _grounded_tier2_text(payload), 'meta': {'error': str(exc), 'provider_status': status, 'provider': 'grounded_fallback'}}
        raise HTTPException(status_code=503, detail='tier2_generation_failed')

@router.post('/tier2_summarize')
async def tier2_summarize(request: Request):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')
    prompt = _compose_prompt(payload)
    # Estimate cost: simplistic per-row baseline
    rows = payload.get('rows') or []
    cost_estimate = 0.015 * max(1, len(rows))
    _finops_guard(cost_estimate, tenant=(payload.get('org') or None))

    resp = _generate_tier2_response(prompt, payload)

    # Telemetry counters (best-effort)
    try:
        from src.api.metrics_init import _safe_counter, _safe_hist
        _safe_counter('tier2_requests_total', 'Tier2 requests', ['result','tenant']).labels(result='ok', tenant=str(payload.get('org') or 'unknown')).inc()
        _safe_hist('tier2_summarize_latency_ms','Tier2 summarize latency (ms)', ['tenant']).labels(tenant=str(payload.get('org') or 'unknown')).observe(0.0)
    except Exception:
        pass

    # Streaming response (SSE-like payload array)
    text = resp.get('text') if isinstance(resp, dict) else str(resp)
    chunks = []
    async for c in _stream_chunks(text):
        chunks.append(c)
    return JSONResponse({'status':'ok','assessment_id':payload.get('assessment_id'),'chunks':chunks,'cost_estimate':cost_estimate})

@router.post('/tier2_sse')
async def tier2_sse(request: Request):
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')
    prompt = _compose_prompt(payload)
    rows = payload.get('rows') or []
    cost_estimate = 0.015 * max(1, len(rows))
    # Atomic budget reservation via LLM client
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as LLM_CLIENT, get_client_status  # type: ignore
    except Exception:
        LLM_CLIENT = None
        get_client_status = None  # type: ignore

    if LLM_CLIENT is not None:
        status = get_client_status(LLM_CLIENT) if get_client_status is not None else {'available': True}
        if not status.get('available'):
            if not _allow_tier2_placeholder():
                raise HTTPException(status_code=503, detail='tier2_provider_unavailable')
            LLM_CLIENT = None

    if LLM_CLIENT is not None:
        # Try to reserve tenant budget; if reservation fails return 402
        tenant = payload.get('org') or None
        start_ms = time.time() * 1000.0
        reserved = True
        if tenant:
            try:
                reserved = LLM_CLIENT.reserve_tenant_budget(tenant, cost_estimate)
            except Exception:
                reserved = True
        if not reserved:
            try:
                from src.api.metrics_init import _safe_counter
                _safe_counter('tier2_sse_budget_exceeded_total','Tier2 SSE budget exceeded total',['tenant']).labels(tenant=str(tenant or 'unknown')).inc()
            except Exception:
                pass
            raise HTTPException(status_code=402, detail='budget_exceeded')

        # Stream generation: convert token fragments to SSE frames
        async def async_emitter():
            try:
                # stream_generate may be blocking (iterator); run in thread if needed
                gen = LLM_CLIENT.stream_generate(prompt, max_tokens=2048, tenant_id=(payload.get('org') or None))
                # If generator is async, iterate directly
                if hasattr(gen, '__aiter__'):
                    async for frag in gen:  # type: ignore
                        evt = {'chunk': frag.get('text',''), 'ts': int(time.time()), 'meta': frag.get('meta', {})}
                        yield f"data: {json.dumps(evt)}\n\n"
                else:
                    for frag in gen:
                        evt = {'chunk': frag.get('text',''), 'ts': int(time.time()), 'meta': frag.get('meta', {})}
                        yield f"data: {json.dumps(evt)}\n\n"
            finally:
                try:
                    if LLM_CLIENT and tenant:
                        pass
                except Exception:
                    pass

        resp = StreamingResponse(async_emitter(), media_type='text/event-stream')
        try:
            from src.api.metrics_init import _safe_hist
            _safe_hist('tier2_sse_latency_ms','Tier2 SSE latency (ms)', ['tenant']).labels(tenant=str(tenant or 'unknown')).observe(max(0.0, (time.time()*1000.0 - start_ms)))
        except Exception:
            pass
        return resp
    if not _allow_tier2_placeholder():
        raise HTTPException(status_code=503, detail='tier2_provider_unavailable')
    _finops_guard(cost_estimate, tenant=(payload.get('org') or None))
    resp = _generate_tier2_response(prompt, payload)
    text = resp.get('text') if isinstance(resp, dict) else str(resp)

    async def emitter_fallback():
        async for c in _stream_chunks(text):
            yield f"data: {json.dumps(c)}\n\n"

    return StreamingResponse(emitter_fallback(), media_type='text/event-stream')
__all__ = ["router"]
