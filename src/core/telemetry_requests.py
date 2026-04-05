"""Telemetry Requests: DB schema, queue manager, and worker registration.

Provides a small async worker that consumes telemetry requests and records
results. Works with the platform DB if configured; otherwise falls back to
an in-memory queue and store.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

try:
    from fastapi import FastAPI
except Exception:
    FastAPI = Any  # type: ignore

try:
    from src.db import database as _db
except Exception:
    _db = None  # type: ignore

from src.connectors.registry import ensure_connector, is_enabled, get, get_config
from src.connectors.purview_stub import PurviewConnector
from src.connectors.sdk import ConnectorContext
from src.api.metrics_init import ensure_metrics


ensure_metrics()  # initialize metrics registry early

try:
    from src.api.metrics_init import _safe_counter, _safe_hist  # type: ignore
except Exception:
    # Fallback tiny stubs if internal helpers aren't importable
    class _C:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): return None
        def observe(self, *a, **k): return None
    def _safe_counter(*a, **k): return _C()
    def _safe_hist(*a, **k): return _C()

telemetry_pull_requests_total = _safe_counter(
    "telemetry_pull_requests_total",
    "Telemetry pull requests processed",
    ["connector", "status", "tenant"],
)
telemetry_pull_latency_seconds = _safe_hist(
    "telemetry_pull_latency_seconds",
    "Latency per telemetry pull",
    ["connector", "tenant"],
)

# ARC-specific metrics
arc_verify_queue_depth = _safe_counter(
    "arc_verify_queue_depth",
    "ARC verification queue depth (approx)",
    [],
)
arc_verify_latency_seconds = _safe_hist(
    "arc_verify_latency_seconds",
    "ARC verification latency seconds",
    [],
)
arc_dns_cache_hits = _safe_counter("arc_dns_cache_hits", "ARC DNS cache hits", [])
arc_dns_cache_misses = _safe_counter("arc_dns_cache_misses", "ARC DNS cache misses", [])
arc_sample_rate_gauge = _safe_counter("arc_sample_rate", "ARC sample rate (observed)", [])


@dataclass
class TelemetryRequest:
    id: str
    domain: str
    entity: str
    window: Optional[str] = None
    connector: str = "purview"
    status: str = "pending"  # pending|processing|done|error
    result_json: Optional[str] = None
    error: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    latency_ms: Optional[int] = None
    include_body: bool = False


class TelemetryStore:
    """Simple store abstraction backed by DB when available, else memory."""

    def __init__(self):
        self._mem: Dict[str, TelemetryRequest] = {}

    async def upsert(self, r: TelemetryRequest) -> None:
        self._mem[r.id] = r
        if _db is None:
            return
        try:
            pool = await _db.get_pool()
        except Exception:
            return
        sql = (
            "INSERT INTO telemetry_requests(id, domain, entity, window, connector, status, result_json, error, created_at, updated_at, latency_ms)"
            " VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"
            " ON CONFLICT (id) DO UPDATE SET domain=EXCLUDED.domain, entity=EXCLUDED.entity, window=EXCLUDED.window,"
            " connector=EXCLUDED.connector, status=EXCLUDED.status, result_json=EXCLUDED.result_json, error=EXCLUDED.error,"
            " created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at, latency_ms=EXCLUDED.latency_ms"
        )
        try:
            await _db.execute(sql, r.id, r.domain, r.entity, r.window, r.connector, r.status, r.result_json, r.error, r.created_at, r.updated_at, r.latency_ms)
        except Exception:
            # Best-effort: SQLite fallback uses ? placeholders; try alternate path
            try:
                alt = sql.replace("$", "?")
                await _db.execute(alt, r.id, r.domain, r.entity, r.window, r.connector, r.status, r.result_json, r.error, r.created_at, r.updated_at, r.latency_ms)
            except Exception:
                pass

    async def list_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        if _db is None:
            return [asdict(v) for v in sorted(self._mem.values(), key=lambda x: x.created_at, reverse=True)[:limit]]
        try:
            rows = await _db.fetch("SELECT * FROM telemetry_requests ORDER BY created_at DESC LIMIT $1", limit)
            return [dict(r) for r in rows]
        except Exception:
            return [asdict(v) for v in sorted(self._mem.values(), key=lambda x: x.created_at, reverse=True)[:limit]]


class TelemetryCache:
    def __init__(self, ttl_seconds: int = 600):
        self._ttl = ttl_seconds
        self._store: Dict[Tuple[str, str, Optional[str]], Tuple[float, Dict[str, Any]]] = {}

    def get(self, domain: str, entity: str, window: Optional[str]) -> Optional[Dict[str, Any]]:
        key = (domain, entity, window)
        item = self._store.get(key)
        if not item:
            return None
        ts, val = item
        if (time.time() - ts) > self._ttl:
            try:
                del self._store[key]
            except Exception:
                pass
            return None
        return val

    def set(self, domain: str, entity: str, window: Optional[str], value: Dict[str, Any]) -> None:
        self._store[(domain, entity, window)] = (time.time(), value)


async def _execute_connector(connector: str, domain: str, entity: str, window: Optional[str], include_body: bool = False) -> Dict[str, Any]:
    # Resolve via registry and enforce enablement
    if not is_enabled(connector):
        return {"enrichment": {"note": "connector disabled"}, "latency_ms": 0, "cost_usd": 0.0}

    # Try to resolve an existing connector instance
    c = get(connector)
    if c is None:
        # Fallback to known built-ins
        if connector == "purview":
            c = ensure_connector('purview', lambda **kw: PurviewConnector(**kw))
        else:
            return {"enrichment": {"note": "unsupported connector"}, "latency_ms": 0, "cost_usd": 0.0}

    ctx = ConnectorContext(tenant_id=os.getenv('TENANT_ID') or None, request_id=None, rate_key=f"{connector}:{os.getenv('TENANT_ID') or 'global'}")

    # Enforce per-connector / per-tenant policy for body inclusion
    try:
        policy = get_config(connector) or {}
    except Exception:
        policy = {}
    allow_bodies = bool(policy.get('allow_bodies', False))
    tenant_policies = policy.get('tenant_policies') or {}
    if ctx and ctx.tenant_id and isinstance(tenant_policies, dict):
        tpol = tenant_policies.get(ctx.tenant_id)
        if isinstance(tpol, dict) and 'allow_bodies' in tpol:
            allow_bodies = bool(tpol.get('allow_bodies'))

    effective_include_body = bool(include_body) and allow_bodies

    # Call connector execute; connectors may accept include_body kwarg
    try:
        return await c.execute(domain=domain, entity=entity, window=window, context=ctx, include_body=effective_include_body)
    except TypeError:
        try:
            return await c.execute(domain=domain, entity=entity, window=window, context=ctx)
        except Exception:
            raise


def register_telemetry_worker(app: FastAPI) -> None:
    """Attach queue, store, cache, and start async worker when not in test mode."""
    # Initialize state objects
    app.state.telemetry_store = getattr(app.state, "telemetry_store", TelemetryStore())
    app.state.telemetry_cache = getattr(app.state, "telemetry_cache", TelemetryCache())
    app.state.telemetry_queue = getattr(app.state, "telemetry_queue", asyncio.Queue(maxsize=100))
    # Queue for deferred ARC verification
    app.state.arc_verify_queue = getattr(app.state, 'arc_verify_queue', asyncio.Queue(maxsize=500))

    # Optionally use Redis-backed ARC queue when REDIS_URL present
    try:
        from src.core.arc_redis_queue import get_redis_client
        app.state._arc_redis = get_redis_client()
    except Exception:
        app.state._arc_redis = None

    # Skip background loop in explicit test mode
    try:
        if os.getenv("FAST_TEST_MODE", "0").lower() in {"1","true","yes"} or os.getenv("PYTEST_CURRENT_TEST"):
            return
    except Exception:
        pass

    async def _worker():
        while True:
            try:
                req: TelemetryRequest = await app.state.telemetry_queue.get()
                start = time.perf_counter()
                req.status = "processing"
                req.updated_at = time.time()
                await app.state.telemetry_store.upsert(req)
                # Cache check
                cached = app.state.telemetry_cache.get(req.domain, req.entity, req.window)
                if cached:
                    req.result_json = json.dumps(cached)
                    req.status = "done"
                    req.latency_ms = int((time.perf_counter() - start) * 1000)
                    req.updated_at = time.time()
                    await app.state.telemetry_store.upsert(req)
                    try:
                        tenant_label = getattr(req, 'tenant_id', os.getenv('TENANT_ID') or 'default')
                    except Exception:
                        tenant_label = os.getenv('TENANT_ID') or 'default'
                    telemetry_pull_requests_total.labels(connector=req.connector, status="cache", tenant=tenant_label).inc()
                    telemetry_pull_latency_seconds.labels(connector=req.connector, tenant=tenant_label).observe((time.perf_counter()-start))
                    continue
                # Execute connector
                try:
                    res = await _execute_connector(req.connector, req.domain, req.entity, req.window, include_body=req.include_body)
                    # If connector returned raw message or body, attempt DKIM/DMARC/ARC checks
                    try:
                        from src.core.email_auth import verify_dkim, check_dmarc, parse_arc_headers
                        # expected locations: res.get('message') or res.get('body') or res.get('raw')
                        raw = None
                        if isinstance(res, dict):
                            raw = res.get('message') or res.get('body') or res.get('raw')
                        if isinstance(raw, str):
                            raw_bytes = raw.encode('utf-8', errors='ignore')
                        elif isinstance(raw, (bytes, bytearray)):
                            raw_bytes = bytes(raw)
                        else:
                            raw_bytes = None
                        if raw_bytes:
                            try:
                                dkim_info = verify_dkim(raw_bytes)
                                arc_info = parse_arc_headers(raw_bytes)
                                # Attempt SPF verification: simple heuristic via email headers
                                spf_result = None
                                try:
                                    from src.core.email_auth import _spf_lib
                                    if _spf_lib is not None:
                                        env_from = None
                                        origin_ip = None
                                        # prefer connector-provided envelope_from/origin_ip
                                        if isinstance(res, dict):
                                            env_from = res.get('envelope_from')
                                            origin_ip = res.get('origin_ip')
                                        # fallback heuristics
                                        if not env_from:
                                            env_from = (dkim_info.get('signatures') or [{}])[0].get('domain') or req.domain
                                        spf_res = _spf_lib.check(i=origin_ip, s=env_from, h=req.domain)
                                        if isinstance(spf_res, (list, tuple)) and spf_res:
                                            spf_result = (spf_res[0] or '').lower()
                                except Exception:
                                    spf_result = None
                                # best-effort: check dmarc using from header if present
                                from_header = None
                                try:
                                    import email
                                    m = email.message_from_bytes(raw_bytes)
                                    from_header = m.get('From')
                                except Exception:
                                    from_header = None
                                # pass dkim_verified flag and leave spf_result optional for future
                                # For each AMS in arc_info, attempt strict verification and gather selector TXT
                                # Decide whether to do strict ARC verification now or defer
                                ARC_MODE = os.getenv('ARC_VERIFY_MODE', 'sample').lower()
                                ARC_SAMPLE_RATE = float(os.getenv('ARC_SAMPLE_RATE', '0.01'))
                                do_strict = False
                                if ARC_MODE == 'on':
                                    do_strict = True
                                elif ARC_MODE == 'sample':
                                    import random
                                    do_strict = random.random() < ARC_SAMPLE_RATE
                                # Defer heavy verification to background verifier if not done inline
                                arc_validated = arc_info
                                if do_strict:
                                    try:
                                        from src.core.email_auth import validate_arc_chain, dns_resolve_txt
                                        arc_validated = validate_arc_chain(raw_bytes)
                                    except Exception:
                                        arc_validated = arc_info
                                else:
                                    # enqueue for background verification if worker available
                                    try:
                                        # use base64 for raw payloads for cross-language safety
                                        import base64 as _b64
                                        b64 = _b64.b64encode(raw_bytes).decode('ascii')
                                        payload = {'req_id': req.id, 'raw': b64, 'meta': {'connector': req.connector, 'domain': req.domain}, 'raw_b64': True}
                                        if getattr(app.state, '_arc_redis', None):
                                            try:
                                                from src.core.arc_redis_queue import enqueue_job
                                                enqueue_job(payload)
                                                try:
                                                    arc_verify_queue_depth.inc()
                                                except Exception:
                                                    pass
                                            except Exception:
                                                # fallback to in-memory queue
                                                try:
                                                    await app.state.arc_verify_queue.put(payload)
                                                    try:
                                                        arc_verify_queue_depth.inc()
                                                    except Exception:
                                                        pass
                                                except Exception:
                                                    pass
                                        else:
                                            try:
                                                await app.state.arc_verify_queue.put(payload)
                                                try:
                                                    arc_verify_queue_depth.inc()
                                                except Exception:
                                                    pass
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                                    except Exception:
                                        pass

                                # Fetch selector TXT and _dmarc for auditability
                                selector_txts = []
                                try:
                                    sigs = dkim_info.get('signatures') or []
                                    first_sig = sigs[0] if sigs else {}
                                    sel_dom = first_sig.get('domain') or req.domain
                                    sel = first_sig.get('selector')
                                    if sel and sel_dom:
                                        sel_q = f"{sel}._domainkey.{sel_dom}"
                                        selector_txts = dns_resolve_txt(sel_q)
                                        try:
                                            if selector_txts:
                                                arc_dns_cache_hits.inc()
                                            else:
                                                arc_dns_cache_misses.inc()
                                        except Exception:
                                            pass
                                except Exception:
                                    selector_txts = []

                                dmarc_txts = []
                                try:
                                    dmarc_q = f"_dmarc.{req.domain}"
                                    dmarc_txts = dns_resolve_txt(dmarc_q)
                                    try:
                                        if dmarc_txts:
                                            arc_dns_cache_hits.inc()
                                        else:
                                            arc_dns_cache_misses.inc()
                                    except Exception:
                                        pass
                                except Exception:
                                    dmarc_txts = []

                                dmarc_info = check_dmarc((dkim_info.get('signatures') or [{}])[0].get('domain') or req.domain, from_header or '', dkim_verified=(dkim_info.get('dkim_status') == 'valid'), spf_result=spf_result)
                                res.setdefault('auth_checks', {})
                                res['auth_checks']['dkim'] = dkim_info
                                res['auth_checks']['dmarc'] = dmarc_info
                                res['auth_checks']['arc'] = arc_validated
                                res['auth_checks']['selector_txt'] = selector_txts
                                res['auth_checks']['dmarc_txt'] = dmarc_txts
                                res['auth_checks']['canonicalization'] = {'used_header': arc_validated.get('sets') if isinstance(arc_validated, dict) else None}
                            except Exception:
                                pass
                    except Exception:
                        pass
                    req.result_json = json.dumps(res)
                    req.status = "done"
                    req.latency_ms = int((time.perf_counter() - start) * 1000)
                    app.state.telemetry_cache.set(req.domain, req.entity, req.window, res)
                    try:
                        tenant_label = getattr(req, 'tenant_id', os.getenv('TENANT_ID') or 'default')
                    except Exception:
                        tenant_label = os.getenv('TENANT_ID') or 'default'
                    telemetry_pull_requests_total.labels(connector=req.connector, status="ok", tenant=tenant_label).inc()
                    telemetry_pull_latency_seconds.labels(connector=req.connector, tenant=tenant_label).observe((time.perf_counter()-start))
                except Exception as exc:
                    req.error = str(exc).split("\n", 1)[0]
                    req.status = "error"
                    try:
                        tenant_label = getattr(req, 'tenant_id', os.getenv('TENANT_ID') or 'default')
                    except Exception:
                        tenant_label = os.getenv('TENANT_ID') or 'default'
                    telemetry_pull_requests_total.labels(connector=req.connector, status="error", tenant=tenant_label).inc()
                finally:
                    req.updated_at = time.time()
                    await app.state.telemetry_store.upsert(req)
            except Exception:
                await asyncio.sleep(0.05)

    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_worker())
        # background ARC verification worker
        async def _arc_verifier():
            from src.core.email_auth import validate_arc_chain
            from time import perf_counter
            redis_client = getattr(app.state, '_arc_redis', None)
            # schedule stalled mover periodically
            try:
                from src.core.arc_redis_queue import move_stalled_back
            except Exception:
                move_stalled_back = None
            while True:
                try:
                    item = None
                    if redis_client:
                        try:
                            from src.core.arc_redis_queue import pop_job, ack_job, enqueue_job
                            popped = pop_job(timeout=5)
                            if popped is None:
                                await asyncio.sleep(0.1)
                                continue
                            job, payload_str = popped
                            item = job
                        except Exception:
                            await asyncio.sleep(0.1)
                            continue
                    else:
                        item = await app.state.arc_verify_queue.get()

                    raw = item.get('raw')
                    if isinstance(raw, str):
                        # assume base64-encoded
                        try:
                            import base64 as _b64
                            raw_bytes = _b64.b64decode(raw)
                        except Exception:
                            raw_bytes = raw.encode('latin1')
                    else:
                        raw_bytes = raw
                    req_id = item.get('req_id')
                    try:
                        t0 = perf_counter()
                        arc_res = validate_arc_chain(raw_bytes)
                        arc_verify_latency_seconds.labels().observe((perf_counter() - t0))
                        # Update telemetry store entry auth_checks if present
                        try:
                            store = app.state.telemetry_store
                            tr = store._mem.get(req_id)
                            if tr and tr.result_json:
                                try:
                                    data = json.loads(tr.result_json)
                                except Exception:
                                    data = {}
                                data.setdefault('auth_checks', {})
                                data['auth_checks'].setdefault('arc_deferred', {})
                                data['auth_checks']['arc_deferred'] = arc_res
                                tr.result_json = json.dumps(data)
                                await store.upsert(tr)
                            # Acknowledge redis payload when present
                            try:
                                if redis_client and 'payload_str' in locals():
                                    ack_job(payload_str)
                            except Exception:
                                pass
                        except Exception:
                            # If updating store failed, fall through to retry below
                            raise
                    except Exception:
                        # processing failed — if redis, increment attempts and schedule requeue with backoff or DLQ
                        try:
                            if redis_client and 'payload_str' in locals():
                                # recover job object from payload
                                import json as _json
                                try:
                                    p = _json.loads(payload_str)
                                    job_obj = p.get('job', {}) if isinstance(p, dict) else {}
                                    attempts = int(job_obj.get('attempts', 0)) + 1
                                    job_obj['attempts'] = attempts
                                    max_attempts = int(job_obj.get('max_attempts', 5))
                                    if attempts >= max_attempts:
                                        # push to DLQ by enqueuing raw payload into DLQ key
                                        from src.core.arc_redis_queue import get_redis_client
                                        rc = get_redis_client()
                                        if rc is not None:
                                            rc.lpush(os.getenv('ARC_VERIFY_DLQ_KEY', 'arc:verify:dlq'), _json.dumps({'job': job_obj, 'ts': time.time()}))
                                    else:
                                        # schedule delayed requeue via zset using move_stalled_back logic
                                        from src.core.arc_redis_queue import enqueue_job
                                        enqueue_job(job_obj)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    pass
                # periodically attempt to move stalled items back (best-effort)
                try:
                    if move_stalled_back:
                        move_stalled_back()
                except Exception:
                    pass
                await asyncio.sleep(0.05)
        loop.create_task(_arc_verifier())
    except Exception:
        # Best-effort
        asyncio.create_task(_worker())


__all__ = [
    "TelemetryRequest",
    "TelemetryStore",
    "TelemetryCache",
    "register_telemetry_worker",
]
