from __future__ import annotations

import time
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from src.integrations.llm_client import DEFAULT_CLIENT as LLM_CLIENT, get_client_status
from src.analysis.auto_llm import LLMAssessmentClient
from src.analysis.cost_tracker import EXTERNAL_TRACKER, LOCAL_TRACKER
from src.api.runtime_state import EVENT_QUEUE, get_server_runtime_state
import os, json, asyncio

router = APIRouter(prefix='/api/v1/llm', tags=['llm'])


@router.get('/cost_estimate')
async def cost_estimate(lines: int = 35):
    """Return a lightweight cost estimate for producing an N-line triage summary.
    Uses simple per-line token estimate and LLM_CLIENT cost ledger when available.
    """
    try:
        # naive tokens per line estimate
        tokens_per_line = 20
        est_tokens = max(1, int(lines) * tokens_per_line)
        est_cost_cents = None
        est_cost = None
        # Prefer LLM client ledger if available
        try:
            client = LLM_CLIENT
            # small heuristic cost per 1k tokens if configured
            per_1k = float(__import__('os').getenv('LLM_COST_PER_1K', '0.002') or 0.002)
            est_cost = (est_tokens / 1000.0) * per_1k
            est_cost_cents = int(round(est_cost * 100))
        except Exception:
            est_cost = (est_tokens / 1000.0) * 0.002
            est_cost_cents = int(round(est_cost * 100))
        return JSONResponse({'lines': int(lines), 'estimated_tokens': est_tokens, 'estimated_cost_cents': est_cost_cents, 'estimate': est_cost})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/generate_more')
async def generate_more(request: Request):
    """Trigger server-side generation to create more llm rows (test/dev helper).
    Payload: { assessment_id?:str, count?:int }
    Returns: { added: int }
    """
    try:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        count = int(payload.get('count') or payload.get('n') or 25)
        assessment_id = payload.get('assessment_id')
        # If an assessment_id is provided, try to reuse the deep analyzer to enqueue summaries
        if assessment_id:
            try:
                from src.api.deep_analyze_endpoints import generate_llm_summaries
                fake_req = type('R', (), {'json': (lambda: {'assessment_id': assessment_id, 'limit': count})})()
                # call underlying coroutine
                await generate_llm_summaries(fake_req)  # type: ignore
                return JSONResponse({'added': count, 'via': 'assessment'})
            except Exception:
                # fall through to default simulated behavior
                pass
        # Default fallback: simulate adding rows (no-op in production)
        time.sleep(0.05)
        return JSONResponse({'added': count})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/health')
async def llm_health():
    """Return a small status object describing available LLM providers and basic reachability.

    This endpoint is used by the frontend to populate provider dropdowns and show
    a helpful modal when no provider is configured or reachable.
    """
    try:
        client = LLM_CLIENT
        status = get_client_status(client)
        provider = status.get('provider') or getattr(client, 'provider', 'unknown')
        # attempt to include a lightweight failures metric if runtime collects it
        failures = 0
        try:
            from src.api.runtime_state import get_server_runtime_state
            runtime = get_server_runtime_state(None)
            telemetry = getattr(runtime, 'telemetry', {}) or {}
            failures = int(telemetry.get('llm_provider_failures', 0) or 0)
        except Exception:
            try:
                failures = int(getattr(client, '_metrics_state', {}).get('llm_provider_failures', 0) or 0)
            except Exception:
                failures = 0

        resp = {
            'provider': provider,
            'requested_provider': status.get('requested_provider'),
            'environment': status.get('environment'),
            'available': bool(status.get('available')),
            'strict_provider': bool(status.get('strict_provider')),
            'fallback_active': bool(status.get('fallback_active')),
            'fallback_reason': status.get('fallback_reason'),
            'local_deterministic_active': bool(status.get('local_deterministic_active')),
            'client_class': status.get('client_class'),
            'mock': bool(getattr(client, 'mock', False)),
            'ollama': {
                'enabled': bool(status.get('ollama_enabled', getattr(client, 'ollama_enabled', False))),
                'host': status.get('ollama_host', getattr(client, 'ollama_host', None)),
                'model': status.get('ollama_model', getattr(client, 'ollama_model', None)),
                'reachable': bool(status.get('ollama_reachable', False)),
                'provider_failures_total': failures,
            },
            'openai': {
                'configured': bool(status.get('openai_configured', getattr(client, 'openai_key', None)))
            },
            'anthropic': {
                'configured': bool(status.get('anthropic_configured', getattr(client, 'anthropic_key', None)))
            },
            'breaker': status.get('breaker') or {},
            'budget': status.get('budget') or {},
        }
        return JSONResponse(resp)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/feedback/metrics')
async def llm_feedback_metrics(request: Request):
    """Expose lightweight LLM feedback/training metrics collected by the background job.

    Returns whatever the scheduler last populated into runtime.llm_feedback_metrics
    or an empty object if unavailable. This is used by the LIVE console to render
    provider telemetry and recent feedback counts.
    """
    try:
        app = request.app
        runtime = get_server_runtime_state(app)
        metrics = getattr(runtime, 'llm_feedback_metrics', {})
        if not isinstance(metrics, dict):
            try:
                metrics = dict(metrics)
            except Exception:
                metrics = {}
        return JSONResponse(metrics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/triage')
async def llm_triage(request: Request):
    """Tier 1 triage summary: concise, structured JSON for UI.
    Expects a payload with optional keys: decision, factors, hopgraph_context.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    decision = payload.get('decision') or {}
    factors = payload.get('factors') or []
    hop = payload.get('hopgraph_context') or {}
    def _top_factors(fs):
        out = []
        for f in fs:
            if isinstance(f, str):
                out.append(f)
            elif isinstance(f, dict):
                out.append(f.get('factor') or f.get('name') or 'factor')
            if len(out) >= 4:
                break
        return out
    summary = {
        'summary': {
            'what': decision.get('title') or 'Event triage',
            'impact': list(set([e for e in (decision.get('entities') or [])]))[:5],
            'confidence': float(decision.get('confidence') or 0.0),
            'top_factors': _top_factors(factors)
        },
        'actions': [
            'Contain affected endpoint',
            'Block domains/processes indicated',
            'Escalate if confidence > 0.7',
            'Capture forensic snapshot'
        ],
        'context': {
            'ttl_seconds': decision.get('ttl_seconds'),
            'hopgraph_summary': hop.get('summary'),
        }
    }
    return JSONResponse(summary)


@router.post('/explain')
async def llm_explain(request: Request):
    """Tier 2 deep explain: structured JSON with factor synthesis and path context."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    synthesis = payload.get('factor_synthesis') or {}
    mapping = payload.get('mapping_semantics') or {}
    diversity = payload.get('domain_diversity') or {}
    hop = payload.get('hopgraph_context') or {}
    chains = hop.get('chains') or []

    # If a full row is provided, attempt a Tier-2 LLM explain using the centralized auto_llm client.
    row = payload.get('row') or payload.get('artifact')
    llm_block = None
    try:
        if isinstance(row, dict):
            client = LLMAssessmentClient()
            ctx = payload.get('context') or {}
            # enforce tier2
            try:
                ctx = dict(ctx or {})
                ctx['tier'] = 'tier2'
            except Exception:
                ctx = {'tier': 'tier2'}
            try:
                llm_out = client.summarize_row(row, ctx)
            except Exception:
                llm_out = None
            if isinstance(llm_out, dict):
                llm_block = {
                    'text': llm_out.get('text') or '',
                    'model': llm_out.get('model') or (llm_out.get('meta') or {}).get('model') or 'unknown',
                    'meta': llm_out.get('meta') or {},
                    'payload': llm_out.get('payload') or {},
                }
                # Record cost/tokens best-effort
                try:
                    meta = llm_block.get('meta') or {}
                    it = int(meta.get('input_tokens') or meta.get('prompt_tokens') or 0)
                    ot = int(meta.get('output_tokens') or meta.get('completion_tokens') or 0)
                    est_cost = float(meta.get('estimated_cost') or meta.get('cost') or 0.0)
                    model_name = llm_block.get('model') or 'unknown'
                    row_index = int(payload.get('row_index') or row.get('row_index') or -1)
                    if est_cost and EXTERNAL_TRACKER:
                        EXTERNAL_TRACKER.track_call(row_index, model_name, it, ot, float(est_cost))
                    else:
                        # fallback to local tracker if GPU time present
                        gpu_ms = int(meta.get('gpu_time_ms') or 0)
                        if LOCAL_TRACKER:
                            LOCAL_TRACKER.track_call(row_index, model_name, it, ot, gpu_ms)
                except Exception:
                    pass

    except Exception:
        llm_block = None

    explanation = {
        'explain': {
            'final_score': float(synthesis.get('final_score') or 0.0),
            'decay': synthesis.get('decay_applied'),
            'context_multiplier': synthesis.get('context_multiplier'),
            'contributors': synthesis.get('contributing_factors') or [],
            'uncertainties': synthesis.get('uncertainties') or [],
        },
        'path_context': {
            'mapping_semantics': mapping,
            'domain_diversity': diversity,
            'hopgraph_preview': chains[0] if chains else {},
        },
        'recommendations': [
            'Validate anomalies across identity/network/process domains',
            'Run playbook: isolate, scan, and patch',
            'Correlate with AB-test variant outcomes for precision'
        ]
    }

    if llm_block:
        explanation['llm'] = llm_block

        # Best-effort persistence: attach llm_block to an assessment or write
        # an append-only log for later consumption. If caller provided
        # `assessment_id` in payload, prefer writing to that assessment's file.
        try:
            assessment_id = payload.get('assessment_id') or payload.get('assessment')
            def _persist():
                try:
                    out_dir = Path(os.getenv('ASSESSMENT_PERSIST_DIR', 'data/assessments'))
                    out_dir.mkdir(parents=True, exist_ok=True)
                    if assessment_id:
                        path = out_dir / f'{assessment_id}.llm.jsonl'
                    else:
                        path = out_dir / 'unattached.llm.jsonl'
                    record = {
                        'ts': int(time.time()),
                        'assessment_id': assessment_id,
                        'row_index': payload.get('row_index'),
                        'row_id': (row or {}).get('id') if isinstance(row, dict) else None,
                        'llm': llm_block,
                        'context': payload.get('context') or {}
                    }
                    with open(path, 'a', encoding='utf8') as fh:
                        fh.write(json.dumps(record) + "\n")
                except Exception:
                    pass

            try:
                # Fire-and-forget to avoid blocking request handling
                loop = asyncio.get_running_loop()
                loop.create_task(asyncio.to_thread(_persist))
            except Exception:
                # Fallback synchronous write if no running loop
                try:
                    _persist()
                except Exception:
                    pass

            # Optionally create an incident when LLM confidence is high
            try:
                meta = llm_block.get('meta') or {}
                conf = float(meta.get('confidence') or meta.get('score') or 0.0)
                thresh = float(os.getenv('LLM_INCIDENT_CONFIDENCE_THRESHOLD', '0.85') or 0.85)
                if conf and conf >= thresh:
                    # Best-effort: enqueue an incident creation event onto EVENT_QUEUE
                    inc = {
                        'type': 'auto_incident_from_llm',
                        'assessment_id': assessment_id,
                        'confidence': conf,
                        'llm': llm_block,
                        'ts': int(time.time())
                    }
                    try:
                        # If EVENT_QUEUE supports enqueue or enqueue_event, try common names
                        if hasattr(EVENT_QUEUE, 'enqueue'):
                            EVENT_QUEUE.enqueue(inc)
                        elif hasattr(EVENT_QUEUE, 'enqueue_event'):
                            EVENT_QUEUE.enqueue_event(inc)
                        elif hasattr(EVENT_QUEUE, 'publish'):
                            EVENT_QUEUE.publish(inc)
                    except Exception:
                        # last resort: write to incidents fallback file
                        try:
                            out_dir = Path(os.getenv('INCIDENT_PERSIST_DIR', 'data/incidents'))
                            out_dir.mkdir(parents=True, exist_ok=True)
                            path = out_dir / f'auto_llm_incidents.jsonl'
                            with open(path, 'a', encoding='utf8') as fh:
                                fh.write(json.dumps(inc) + "\n")
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            pass

    return JSONResponse(explanation)
