"""FastAPI Ingestion & Control Service

Endpoints:
- GET /health
- GET /ready
- GET /metrics
- POST /api/v1/events
- POST /api/v1/events/eclipse-xdr
- GET /api/v1/decisions/{event_id}

Integrates with SecurityOrchestrator via an EventQueue and a background worker.
"""
import asyncio
import logging
import os
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
from fastapi import Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
except Exception:
    generate_latest = lambda : b''  # type: ignore
    CONTENT_TYPE_LATEST = 'text/plain'

from core.event_queue import EventQueue
from core.event_pipeline import PipelineResult
from main import SecurityOrchestrator  # assuming relative import works

logger = logging.getLogger(__name__)

# Pydantic models
class IngestEvent(BaseModel):
    id: str = Field(..., description="Unique event id")
    source: Optional[str] = "api"
    event_type: Optional[str] = None
    severity: Optional[str] = "low"
    timestamp: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class IngestResponse(BaseModel):
    accepted: bool
    event_id: str
    queued_depth: int

class DecisionRecord(BaseModel):
    event_id: str
    verdict: str
    confidence: float
    processing_time_ms: float
    factors: list[str]
    timestamp: float

# Globals (could be injected via dependency override in tests)
app = FastAPI(title="JanuSec API", version="0.1.0-pre")

EVENT_QUEUE: EventQueue = EventQueue(max_size=int(os.getenv('EVENT_QUEUE_MAX', '1000')))
ORCHESTRATOR: Optional[SecurityOrchestrator] = None
DECISION_CACHE: Dict[str, DecisionRecord] = {}
CACHE_MAX = 5000
ECLIPSE_SHARED_SECRET = os.getenv('ECLIPSE_XDR_SHARED_SECRET', '')
WORKER_TASK: Optional[asyncio.Task] = None
STOP_EVENT = asyncio.Event()

# Utility functions
async def orchestrator_provider() -> SecurityOrchestrator:
    global ORCHESTRATOR
    if ORCHESTRATOR is None:
        ORCHESTRATOR = SecurityOrchestrator()
        await ORCHESTRATOR.initialize()
        # Inject registry references into pipeline if needed
        ORCHESTRATOR.event_pipeline.config.module_registry = ORCHESTRATOR.module_registry
    return ORCHESTRATOR

async def background_worker():
    orchestrator = await orchestrator_provider()
    while not STOP_EVENT.is_set():
        event = await EVENT_QUEUE.dequeue(timeout=1.0)
        if not event:
            continue
        try:
            result = await orchestrator.process_event(event)
            record = DecisionRecord(
                event_id=result.event_id,
                verdict=result.verdict,
                confidence=result.confidence,
                processing_time_ms=result.processing_time_ms,
                factors=result.factors,
                timestamp=time.time()
            )
            DECISION_CACHE[result.event_id] = record
            if len(DECISION_CACHE) > CACHE_MAX:
                # Drop oldest (simple heuristic)
                for k in list(DECISION_CACHE.keys())[:1000]:
                    DECISION_CACHE.pop(k, None)
        except Exception as e:
            logger.error(f"Worker processing error: {e}")

@app.on_event("startup")
async def startup_event():
    global WORKER_TASK
    logger.info("API startup: launching orchestrator & worker")
    await orchestrator_provider()
    WORKER_TASK = asyncio.create_task(background_worker())

@app.on_event("shutdown")
async def shutdown_event():
    STOP_EVENT.set()
    if WORKER_TASK:
        await WORKER_TASK
    if ORCHESTRATOR:
        await ORCHESTRATOR.shutdown()

from repositories import decisions_repo, alerts_repo, audit_repo
from repositories import factors_repo
from repositories import feedback_repo
from repositories import access_log_repo
from repositories import factor_weights_repo
import math
from nlp_query import parse_nl
from security.auth import require_scopes, AuthContext

# Mount static console (will create folder later)
try:
    app.mount('/console_static', StaticFiles(directory='frontend'), name='console_static')
    app.mount('/docs_static', StaticFiles(directory='docs'), name='docs_static')
except Exception:
    pass

# Endpoints
@app.middleware("http")
async def access_logging_middleware(request: Request, call_next):
    # Only log for API paths (basic filter)
    path = request.url.path
    method = request.method
    subject = 'anonymous'
    scopes: list[str] = []
    # Attempt to extract auth context from request.state if set by dependencies
    # We'll inject inside protected endpoints manually after response if needed
    try:
        response = await call_next(request)
    except Exception as e:
        from fastapi.responses import PlainTextResponse
        response = PlainTextResponse("internal error", status_code=500)
    try:
        # Protected endpoints use require_scopes; we adapt by patching them to attach context
        auth_ctx = getattr(request.state, 'auth_ctx', None)
        if auth_ctx:
            subject = getattr(auth_ctx, 'subject', subject)
            scopes = getattr(auth_ctx, 'scopes', scopes)
        if path.startswith('/api/') or path.startswith('/stream'):
            # Sampling
            import random
            sample_rate = float(os.getenv('ACCESS_LOG_SAMPLE_RATE','1'))
            if sample_rate >= 1 or random.random() < sample_rate:
                ip = request.client.host if request.client else None
                ua = request.headers.get('user-agent')
                try:
                    await access_log_repo.record(subject, method, path, response.status_code, scopes, ip, ua)
                except Exception:
                    pass
    except Exception:
        pass
    return response
@app.get('/health')
async def health():
    orch = await orchestrator_provider()
    queue_stats = EVENT_QUEUE.stats()
    return {
        'status': orch.health_status,
        'uptime_seconds': time.time() - orch.start_time,
        'events_processed': orch.events_processed,
        'queue': queue_stats
    }

@app.get('/ready')
async def ready():
    orch = await orchestrator_provider()
    healthy = orch.health_status == 'healthy'
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            'ready': healthy,
            'module_health': await orch.module_registry.health_check(),
        }
    )

@app.get('/metrics')
async def metrics():
    data = generate_latest()
    return PlainTextResponse(content=data.decode('utf-8'), media_type=CONTENT_TYPE_LATEST)

@app.post('/api/v1/events', response_model=IngestResponse)
async def ingest_event(payload: IngestEvent):
    accepted = await EVENT_QUEUE.enqueue(payload.model_dump())
    stats = EVENT_QUEUE.stats()
    return IngestResponse(accepted=accepted, event_id=payload.id, queued_depth=stats['depth'])

@app.post('/api/v1/events/eclipse-xdr', response_model=IngestResponse)
async def ingest_eclipse_event(request: Request, x_eclipse_secret: Optional[str] = Header(None)):
    if ECLIPSE_SHARED_SECRET and x_eclipse_secret != ECLIPSE_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid shared secret")
    body = await request.json()
    # Normalize if needed
    event_id = body.get('id') or body.get('event_id') or body.get('uuid')
    if not event_id:
        raise HTTPException(status_code=400, detail="Missing event id")
    event = {
        'id': event_id,
        'source': 'eclipse_xdr',
        'event_type': body.get('type') or body.get('event_type'),
        'severity': body.get('severity', 'medium'),
        'timestamp': body.get('timestamp'),
        'details': body
    }
    accepted = await EVENT_QUEUE.enqueue(event)
    stats = EVENT_QUEUE.stats()
    return IngestResponse(accepted=accepted, event_id=event_id, queued_depth=stats['depth'])

@app.get('/api/v1/decisions/{event_id}', response_model=DecisionRecord)
async def get_decision(event_id: str):
    rec = DECISION_CACHE.get(event_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Decision not found")
    return rec

@app.get('/api/v1/decisions/recent')
async def recent_decisions(limit: int = 50):
    # Prefer in-memory for very recent; always include DB fallback for history
    try:
        db_rows = await decisions_repo.list_recent(limit)
    except Exception:
        db_rows = []
    return {'decisions': db_rows[:limit]}

@app.get('/api/v1/alerts/recent')
async def recent_alerts(limit: int = 50):
    try:
        rows = await alerts_repo.list_recent(limit)
    except Exception:
        rows = []
    return {'alerts': rows[:limit]}

@app.get('/api/v1/chain/{event_id}')
async def chain(event_id: str):
    try:
        chain = await audit_repo.get_chain(event_id)
    except Exception:
        chain = []
    return {'event_id': event_id, 'chain': chain}

@app.get('/console')
async def console_landing():
    html = """<html><head><title>JanuSec Analyst Console</title>
        <style>body{font-family:Arial;margin:20px;} .card{border:1px solid #ccc;padding:12px;margin-bottom:12px;border-radius:6px;} pre{background:#f7f7f7;padding:8px;} .row{display:flex;gap:12px;flex-wrap:wrap;} .small{font-size:12px;color:#555}</style>
        </head><body>
    <h1>JanuSec Analyst Console (Preview)</h1>
        <div class='small'>See <a href='/risk_register' target='_blank'>Risk Register</a></div>
        <div class='card'>
            <h3>Recent Decisions</h3>
            <div id='decisions'>Loading...</div>
        </div>
        <div class='card'>
            <h3>Recent Alerts</h3>
            <div id='alerts'>Loading...</div>
        </div>
        <div class='card'>
            <h3>Custody Chain Lookup</h3>
            <input id='chainId' placeholder='Event ID' /> <button onclick='loadChain()'>Load</button>
            <pre id='chainBox'></pre>
        </div>
        <div class='card'>
            <h3>Factor Similarity Search</h3>
            <input id='factorQuery' placeholder='e.g. privilege escalation' size='40' /> <button onclick='searchFactor()'>Search</button>
            <pre id='factorResults'>Enter a phrase and search.</pre>
        </div>
        <script>
        async function loadDecisions(){
            const r = await fetch('/api/v1/decisions/recent');
            const j = await r.json();
            document.getElementById('decisions').innerHTML = '<pre>'+JSON.stringify(j.decisions, null,2)+'</pre>';
        }
        async function loadAlerts(){
            const r = await fetch('/api/v1/alerts/recent');
            const j = await r.json();
            document.getElementById('alerts').innerHTML = '<pre>'+JSON.stringify(j.alerts, null,2)+'</pre>';
        }
        async function loadChain(){
            const id=document.getElementById('chainId').value; if(!id) return;
            const r=await fetch('/api/v1/chain/'+id); const j=await r.json();
            document.getElementById('chainBox').textContent = JSON.stringify(j.chain, null, 2);
        }
        async function searchFactor(){
            const q = document.getElementById('factorQuery').value; if(!q) return;
            const r = await fetch('/api/v1/query/factors?similar='+encodeURIComponent(q));
            const j = await r.json();
            document.getElementById('factorResults').textContent = JSON.stringify(j.results, null, 2);
        }
        loadDecisions(); loadAlerts();
        setInterval(loadDecisions, 10000); setInterval(loadAlerts, 15000);
        </script>
        </body></html>"""
    return HTMLResponse(html)

@app.post('/api/v1/query/nlp')
async def nlp_query(body: Dict[str, Any], request: Request, auth: AuthContext = Depends(require_scopes('nlp.query'))):
    """Accepts JSON: {"query": "show high confidence malicious events last 2h"} returns DSL + SQL."""
    q = body.get('query', '')
    parsed = parse_nl(q)
    page = int(body.get('page', 1) or 1)
    size = int(body.get('size', 50) or 50)
    size = min(max(size, 1), 200)
    # Optional API key (simple gate). Key expected in env API_QUERY_KEY
    api_key_req = os.getenv('API_QUERY_KEY')
    provided = request.headers.get('x-api-key')
    if api_key_req and api_key_req != provided:
        return JSONResponse(status_code=401, content={'error': 'unauthorized'})
    # Attach auth context for middleware logging
    try:
        request.state.auth_ctx = auth
    except Exception:
        pass
    sql, params = parsed.build(page=page, size=size)
    rows = []
    try:
        from db.database import get_pool
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows_raw = await conn.fetch(sql, *params)
            rows = [dict(r) for r in rows_raw]
    except Exception:
        pass
    return { 'dsl': parsed.dsl, 'page': page, 'size': size, 'results': rows }

def _cosine(a, b):
        if not a or not b: return 0.0
        n = min(len(a), len(b))
        num = sum(a[i]*b[i] for i in range(n))
        da = math.sqrt(sum(a[i]*a[i] for i in range(n)))
        db = math.sqrt(sum(b[i]*b[i] for i in range(n)))
        if da == 0 or db == 0: return 0.0
        return num/(da*db)

@app.get('/api/v1/query/factors')
async def factor_similarity(similar: str, limit: int = 10, auth: AuthContext = Depends(require_scopes('factors.search'))):
        """Similarity search over factor embeddings.

        Tries to generate an embedding for the query using optional transformer model
        (MiniLM) if available; else uses deterministic hash fallback. Then delegates to
        repository similarity_search which uses pgvector if available, else Python cosine.
        """
        limit = max(1, min(limit, 50))
        # Build query embedding
        query_emb: list[float]
        try:
            from transformers import AutoTokenizer, AutoModel  # type: ignore
            if not hasattr(app.state, 'embed_tokenizer'):
                app.state.embed_tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
                app.state.embed_model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
            toks = app.state.embed_tokenizer(similar, return_tensors='pt', truncation=True)
            with __import__('torch').no_grad():
                out = app.state.embed_model(**toks)
                vec = out.last_hidden_state.mean(dim=1).squeeze().tolist()
                if isinstance(vec, float):
                    vec = [vec]
                query_emb = vec[:384]
        except Exception:
            import hashlib
            h = hashlib.sha256(similar.encode()).digest()
            query_emb = [b/255.0 for b in h][:32]
        try:
            results = await factors_repo.similarity_search(query_emb, limit=limit)
        except Exception:
            results = []
        return { 'query': similar, 'results': results }

@app.get('/risk_register')
async def risk_register():
    try:
        with open('docs/risk_register.md','r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        raise HTTPException(status_code=404, detail='Risk register not found')
    return PlainTextResponse(content, media_type='text/markdown')

@app.get('/stream/decisions')
async def stream_decisions():
    async def event_gen():
        last_sent = 0
        while True:
            await asyncio.sleep(2)
            items = [d for d in DECISION_CACHE.values() if d.timestamp > last_sent]
            if items:
                max_ts = max(d.timestamp for d in items)
                last_sent = max(last_sent, max_ts)
                payload = [d.model_dump() for d in items]
                import json
                yield f"data: {json.dumps(payload)}\n\n"
    return StreamingResponse(event_gen(), media_type='text/event-stream')

@app.get('/api/v1/stats/factors/top')
async def factors_top(window: str = '1h', limit: int = 20):
    # window parsing limited to Nh / Nm
    import re
    m = re.match(r'^(\d+)([hm])$', window)
    if not m:
        window = '1h'
        m = ('1','h')
    qty, unit = int(m[0] if isinstance(m, tuple) else m.group(1)), (m[1] if isinstance(m, tuple) else m.group(2))
    seconds = qty * (3600 if unit == 'h' else 60)
    try:
        from db.database import get_pool
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT jsonb_array_elements_text(factors) AS factor, count(*) AS c
                FROM decisions
                WHERE created_at >= (NOW() - $1::interval)
                GROUP BY factor
                ORDER BY c DESC
                LIMIT $2
                """, f"{qty} { 'hour' if unit=='h' else 'minute' }", limit)
            data = [dict(r) for r in rows]
    except Exception:
        data = []
    return {'window': window, 'limit': limit, 'top': data}

@app.get('/api/v1/weights/factors')
async def factor_weights():
    try:
        weights = await factor_weights_repo.load_weights()
    except Exception:
        weights = {}
    return {'weights': weights}

@app.get('/api/v1/metrics/embedding')
async def embedding_metrics():
    # Expose embedding avg norm & drift gauges (best-effort)
    try:
        from main import ORCHESTRATOR  # global orchestrator instance
        orch = ORCHESTRATOR
        if orch and orch.metrics:
            avg_norm = orch.metrics.gauges.get('embedding_avg_norm', 0.0)
            drift = orch.metrics.gauges.get('factor_freq_js_divergence', 0.0)
            return {'embedding_avg_norm': avg_norm, 'factor_freq_js_divergence': drift}
    except Exception:
        pass
    return {'embedding_avg_norm': 0.0, 'factor_freq_js_divergence': 0.0}

class FactorFeedbackPayload(BaseModel):
    event_id: str
    factor: str
    vote: int  # +1 or -1
    comment: Optional[str] = None

@app.post('/api/v1/feedback/factor')
async def factor_feedback(payload: FactorFeedbackPayload, auth: AuthContext = Depends(require_scopes('feedback.write'))):
    # Attach auth context for middleware logging
    try:
        from fastapi import Request as _Req  # type: ignore
    except Exception:
        pass
    if payload.vote not in (1,-1):
        raise HTTPException(status_code=400, detail='invalid_vote')
    try:
        await feedback_repo.insert_feedback(payload.event_id, payload.factor, payload.vote, payload.comment)
    except Exception as e:
        raise HTTPException(status_code=500, detail='persist_failed')
    return {'status':'ok'}

# Convenience run helper
def run():
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('PORT', '8080')))

if __name__ == '__main__':
    run()
