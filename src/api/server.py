from __future__ import annotations

import logging
import os
import time
from collections import deque
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, MutableMapping, Optional, Tuple, Union

from fastapi import HTTPException
from starlette.requests import Request
from pydantic import BaseModel, Field

from .app import app
from .dependencies import get_platform_state
from .alerts_endpoints import (
    router as _alerts_router,
    ALERT_RING as _ALERT_RING,
    ALERT_RING_LOCK as _ALERT_RING_LOCK,
    append_alert,
)
from .artifact_endpoints import router as _artifact_router
from .custody import router as _custody_router
from .finops_endpoints import router as _finops_router, finops_overview as _finops_overview_impl
from .runtime_state import (
    ServerRuntime,
    get_file_batch_analysis,
    get_file_hash_factors,
    get_server_runtime_state,
)
from .schemas import DecisionRecord
from repositories import decisions_repo
from core.quality.factor_quality import get_quality_manager
from src.live import rules_engine, dns_agg, asn_stats

LOGGER = logging.getLogger(__name__)

__all__ = [
    'app',
    'DECISION_CACHE',
    '_ALERT_RING',
    '_ALERT_RING_LOCK',
    '_guardrail_single_pass',
    'DecisionRecord',
    'FILE_HASH_FACTORS',
    'EVENT_QUEUE',

]





class _EventQueueStub:
    def stats(self) -> Dict[str, int]:
        return {'depth': 0, 'max_size': 1}


EVENT_QUEUE: Any = _EventQueueStub()

_state = get_platform_state()
_RUNTIME = get_server_runtime_state(app)
FILE_HASH_FACTORS = get_file_hash_factors(_RUNTIME)
_FILE_BATCH_ANALYSIS = get_file_batch_analysis(_RUNTIME)
DECISION_CACHE: MutableMapping[str, DecisionRecord] = getattr(_state, '_decisions', {})  # type: ignore[attr-defined]

RECENT_DECISION_WINDOW = int(os.getenv('GUARDRAIL_DECISION_WINDOW', '100'))
GUARDRAIL_HISTORY_SIZE = int(os.getenv('GUARDRAIL_HISTORY_SIZE', '50'))
GUARDRAIL_MIN_SAMPLE = int(os.getenv('GUARDRAIL_MIN_SAMPLE', '50'))
_recent_guardrail_select: List[int] = []
_recent_guardrail_fallback: List[int] = []

if not getattr(app.state, '_alerts_router_registered', False):
    app.include_router(_alerts_router)
    app.state._alerts_router_registered = True

if not getattr(app.state, '_artifact_router_registered', False):
    app.include_router(_artifact_router)
    app.state._artifact_router_registered = True

if not getattr(app.state, '_custody_router_registered', False):
    app.include_router(_custody_router)
    app.state._custody_router_registered = True

if not getattr(app.state, '_finops_router_registered', False):
    app.include_router(_finops_router)
    app.state._finops_router_registered = True




def _sanitize_event(raw: Dict[str, Any], rules: List[str], classification: Dict[str, Any]) -> Dict[str, Any]:
    """Create a sanitized snapshot for SSE/debug consumers (legacy compatibility)."""
    process = raw.get('process') or {}
    parent = raw.get('parent_process') or {}
    return {
        'id': raw.get('id'),
        'host': raw.get('host') or raw.get('details', {}).get('host'),
        'proc_name': raw.get('proc_name') or process.get('name'),
        'parent_proc': raw.get('parent_proc') or parent.get('name'),
        'dest_ip': raw.get('dest_ip') or raw.get('dst_ip'),
        'dest_port': raw.get('dest_port') or raw.get('dst_port'),
        'asn': raw.get('asn'),
        'dns_rcode': raw.get('dns_rcode'),
        'rules': list(rules),
        'verdict': classification.get('verdict'),
        'score': classification.get('score'),
        'timestamp': time.time(),
    }


def _record_decision(event_id: str, verdict: str, confidence: float, factors: List[str]) -> None:
    """Maintain in-memory decision cache for backward compatibility."""
    decision = DecisionRecord(event_id=event_id, verdict=verdict, confidence=float(confidence), factors=list(factors))
    try:
        object.__setattr__(decision, 'processing_time_ms', 0.0)
    except Exception:
        try:
            setattr(decision, 'processing_time_ms', 0.0)
        except Exception:
            pass
    try:
        DECISION_CACHE.pop(event_id, None)
    except Exception:
        try:
            DECISION_CACHE.pop(event_id)
        except Exception:
            pass
    DECISION_CACHE[event_id] = decision
    cache_limit = getattr(_state, 'cache_size', 5000)
    try:
        while len(DECISION_CACHE) > cache_limit:
            try:
                DECISION_CACHE.popitem(last=False)
            except Exception:
                try:
                    first_key = next(iter(DECISION_CACHE))
                    DECISION_CACHE.pop(first_key)
                except Exception:
                    break
    except Exception:
        pass


async def detections_governance_report(limit_trends: int = 50, min_sessions: int = 2, top_n: int = 15) -> Dict[str, Any]:
    """Compatibility shim providing governance report structure for legacy imports."""
    from core.hunt.sidecar_session import get_sidecar_manager

    manager = get_sidecar_manager()
    try:
        trends = manager.coverage_trends(limit=limit_trends)
    except Exception:
        trends = []
    try:
        promotion = manager.promotion_candidates(min_sessions=min_sessions, top_n=top_n)
    except Exception:
        promotion = []

    active_sessions = 0
    try:
        active_sessions = len(getattr(manager, '_sessions', {}))
    except Exception:
        active_sessions = 0

    summary = {
        'active_sessions': active_sessions,
        'promotion_candidates': len(promotion),
        'coverage_trend_points': len(trends),
    }

    overrides = {}
    try:
        overrides = getattr(manager, 'severity_weight_overrides', {}) or {}
    except Exception:
        overrides = {}

    meta = {
        'generated_at': time.time(),
        'limit_trends': limit_trends,
        'min_sessions': min_sessions,
        'top_n': top_n,
    }

    return {
        'summary': summary,
        'trends': trends,
        'promotion_candidates': promotion,
        'effective_severity_weight_overrides': overrides,
        'meta': meta,
    }


@app.get('/api/v1/factors/promotion/status')
async def factor_promotion_status(request: Request, limit: int = 500) -> Dict[str, Any]:
    tenant_id = request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id')
    if not tenant_id:
        raise HTTPException(status_code=400, detail='tenant_required')
    try:
        decisions = await decisions_repo.list_recent(limit, tenant_id)
    except Exception:
        decisions = []
    counts: Dict[str, int] = {}
    for dec in decisions or []:
        factors = dec.get('factors') if isinstance(dec, dict) else getattr(dec, 'factors', None)
        if not factors:
            continue
        for factor in factors:
            if isinstance(factor, str):
                counts[factor] = counts.get(factor, 0) + 1
    qm = get_quality_manager()
    suppressed = getattr(qm, 'suppressed', set())
    promotion_min_sessions = int(os.getenv('PROMOTION_MIN_SESSIONS', '3') or 3)
    entries = []
    for factor, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        is_suppressed = factor in suppressed
        if is_suppressed:
            status = 'observe'
        elif count >= promotion_min_sessions:
            status = 'candidate'
        else:
            status = 'insufficient_data'
        entries.append({
            'factor': factor,
            'observations': count,
            'suppressed': is_suppressed,
            'status': status,
        })
    note = 'No recent factor observations' if not entries else 'Sorted by observation count (desc)'
    return {
        'tenant_id': tenant_id,
        'factors': entries,
        'note': note,
    }


async def finops_overview(tenant_id: str | None = None, alpha: float = 0.3, k: float = 3.0) -> Dict[str, Any]:
    """Compatibility wrapper delegating to finops endpoints while preserving legacy import path."""
    scope = {
        'type': 'http',
        'asgi': {'version': '3.0', 'spec_version': '2.1'},
        'method': 'GET',
        'headers': [],
        'path': '/api/v1/finops/overview',
        'query_string': b'',
        'client': ('internal', 0),
        'server': ('internal', 0),
        'scheme': 'http',
        'app': app,
        'state': {},
    }
    request = Request(scope)
    return await _finops_overview_impl(request, tenant_id=tenant_id, alpha=alpha, k=k)


class LogEvent(BaseModel):
    """Normalized event representation for batch ingestion."""

    id: Optional[str] = Field(default=None, min_length=1, max_length=128, description='Event identifier supplied by the caller')
    host: Optional[str] = Field(default=None, max_length=255, description='Hostname or agent identifier associated with the event')
    dns_rcode: Optional[Union[int, str]] = Field(default=None, description='DNS response code, numeric or textual')
    process: Optional[Dict[str, Any]] = Field(default=None, description='Process-level metadata for the event')
    parent_process: Optional[Dict[str, Any]] = Field(default=None, description='Parent process metadata if available')
    details: Dict[str, Any] = Field(default_factory=dict, description='Additional structured context for the event')

    class Config:
        extra = 'allow'


class LogBatchRequest(BaseModel):
    """Request schema for the /api/v1/endpoints/log_batch endpoint."""

    events: List[LogEvent] = Field(default_factory=list, min_length=1, description='Events to ingest and evaluate')
    classify: bool = Field(default=False, description='Run scoring/classification pipeline for the events')
    send_alerts: bool = Field(default=False, description='Emit alerts for qualifying events')
    include_rules: bool = Field(default=False, description='Evaluate detection rules against the events')
    tenant_id: Optional[str] = Field(default=None, max_length=64, description='Tenant context for the ingestion batch')



@dataclass
class LogBatchContext:
    """Runtime options shared while processing a log batch."""

    runtime: ServerRuntime
    include_rules: bool
    classify: bool
    send_alerts: bool
    tenant_id: Optional[str]
    nx_enabled: bool
    dedup_ttl: float


async def _guardrail_single_pass(
    orchestrator: Any,
    alerts_repo: Any,
    queue_util_threshold: float = 0.85,
    drift_threshold: float = 0.4,
    latency_thresh: float = 2500.0,
    fallback_ratio_threshold: float = 0.25,
    recent_fallback: Optional[List[int]] = None,
    recent_select: Optional[List[int]] = None,
) -> None:
    """Evaluate guardrail conditions and emit alerts for degraded states."""
    if alerts_repo is None:
        return

    fallback_buffer = recent_fallback if recent_fallback is not None else _recent_guardrail_fallback
    select_buffer = recent_select if recent_select is not None else _recent_guardrail_select
    alerts: List[Tuple[str, Dict[str, Any]]] = []

    try:
        stats = EVENT_QUEUE.stats() if EVENT_QUEUE else {}
    except Exception as exc:
        LOGGER.debug('Unable to collect event queue stats: %s', exc, exc_info=exc)
        stats = {}
    depth = stats.get('depth')
    max_size = stats.get('max_size') or 0
    if depth is not None and max_size:
        util = depth / max_size if max_size else 0.0
        if util >= queue_util_threshold:
            alerts.append(('queue', {'utilization': round(util, 3), 'depth': depth, 'max_size': max_size}))

    drift_value: Optional[float]
    try:
        gauges = getattr(getattr(orchestrator, 'metrics', None), 'gauges', {})
        drift_value = gauges.get('factor_freq_js_divergence')
    except Exception as exc:
        LOGGER.debug('Guardrail metric lookup failed: %s', exc, exc_info=exc)
        drift_value = None
    if drift_value is not None and drift_value >= drift_threshold:
        alerts.append(('drift', {'drift': drift_value}))

    window = list(DECISION_CACHE.values())[-RECENT_DECISION_WINDOW:]
    latencies = [float(getattr(rec, 'processing_time_ms', 0) or 0) for rec in window if getattr(rec, 'processing_time_ms', None) is not None]
    if latencies:
        latencies.sort()
        idx = max(int(len(latencies) * 0.95) - 1, 0)
        p95 = latencies[idx]
        avg = sum(latencies) / len(latencies)
        if p95 >= latency_thresh:
            alerts.append(('latency', {'p95': p95, 'avg': avg, 'samples': len(latencies)}))

    fallback_count = 0
    for rec in window:
        factors = getattr(rec, 'factors', []) or []
        if any('hash_provider' in str(f) for f in factors):
            fallback_count += 1
    total = len(window)

    buffer = deque(select_buffer, maxlen=GUARDRAIL_HISTORY_SIZE)
    buffer.append(total)
    select_buffer.clear()
    select_buffer.extend(buffer)

    buffer = deque(fallback_buffer, maxlen=GUARDRAIL_HISTORY_SIZE)
    buffer.append(fallback_count)
    fallback_buffer.clear()
    fallback_buffer.extend(buffer)

    if total >= GUARDRAIL_MIN_SAMPLE:
        ratio = fallback_count / total if total else 0.0
        if ratio >= fallback_ratio_threshold:
            alerts.append(('embedding', {'fallback_ratio': round(ratio, 3), 'window': total}))

    for category, details in alerts:
        try:
            message = f'{category}_guardrail_triggered'
            await alerts_repo.insert_alert('system', category, 'warning', message, details, f'guardrail-{category}')
        except Exception as exc:
            LOGGER.warning('Failed to emit guardrail alert for %s: %s', category, exc, exc_info=exc)

def _configure_nx_tracking(runtime: ServerRuntime) -> Tuple[bool, float]:
    """Prepare NX tracking state for the current batch."""
    threshold_raw = os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', '0.35')
    try:
        current_threshold = float(threshold_raw)
    except ValueError:
        current_threshold = runtime.nx_threshold_cache
    nx_enabled = os.getenv('NX_RATE_TRACKER_ENABLED', '1').lower() not in {'0', 'false', 'no'}
    runtime.nx_tracker_enabled = nx_enabled
    if not nx_enabled:
        runtime.reset_nx_tracker(current_threshold)
    elif abs(current_threshold - runtime.nx_threshold_cache) > 1e-9:
        runtime.reset_nx_tracker(current_threshold)
    return nx_enabled, current_threshold


async def _process_endpoint_event(event_model: LogEvent, ctx: LogBatchContext) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """Normalize, classify, and optionally escalate a single endpoint event."""
    event = event_model.model_dump()
    event_id = event.get('id') or f"evt-{int(time.time()*1000)}"
    event['id'] = event_id

    if ctx.nx_enabled:
        host = event.get('host')
        if host:
            tracker = ctx.runtime.nx_rate_tracker[host]
            rcode = event.get('dns_rcode')
            if rcode is not None:
                is_nx = False
                if isinstance(rcode, str) and 'NXDOMAIN' in rcode.upper():
                    is_nx = True
                elif isinstance(rcode, int) and rcode == 3:
                    is_nx = True
                tracker.append(is_nx)
            event['zeek_dns_nxdomain'] = sum(tracker)
            event['zeek_dns_total'] = len(tracker)

    dns_agg.record(event.get('host'), event.get('dns_rcode'))
    asn_stats.record(event.get('asn'))

    hits = rules_engine.evaluate_event(event) if ctx.include_rules else []
    rules = [hit.rule for hit in hits]
    classification = rules_engine.score_and_classify(hits) if ctx.classify else {'verdict': 'OBSERVE', 'score': 0.0}

    sanitized = _sanitize_event(event, rules, classification)
    async with ctx.runtime.get_sanitized_lock():
        ctx.runtime.sanitized_events.appendleft(sanitized)

    processed_event = {
        'id': event_id,
        'rules': rules,
        'verdict': sanitized['verdict'],
        'score': sanitized['score'],
    }

    _record_decision(event_id, sanitized['verdict'] or 'OBSERVE', sanitized['score'] or 0.0, rules)

    alert: Optional[Dict[str, Any]] = None
    if ctx.send_alerts:
        now = time.time()
        dedup_key = event_id
        dedup_hit = False
        async with ctx.runtime.get_dedup_lock():
            for key, ts in list(ctx.runtime.dedup_cache.items()):
                if now - ts >= ctx.dedup_ttl:
                    ctx.runtime.dedup_cache.pop(key, None)
            if dedup_key in ctx.runtime.dedup_cache:
                dedup_hit = True
            else:
                ctx.runtime.dedup_cache[dedup_key] = now
        if not dedup_hit:
            alert = {
                'id': event_id,
                'host': event.get('host'),
                'verdict': sanitized['verdict'],
                'score': sanitized['score'],
                'rules': rules,
                'ts': now,
                'tenant_id': ctx.tenant_id or 'public',
            }
    return processed_event, alert


@app.post('/api/v1/endpoints/log_batch', summary='Ingest endpoint telemetry events')
async def log_batch(payload: LogBatchRequest) -> Dict[str, Any]:
    """Process endpoint events, optionally emit alerts, and feed decision caches."""
    runtime = _RUNTIME
    nx_enabled, _ = _configure_nx_tracking(runtime)
    dedup_ttl = float(os.getenv('ALERT_DEDUP_TTL_SECONDS', '30'))
    ctx = LogBatchContext(
        runtime=runtime,
        include_rules=payload.include_rules,
        classify=payload.classify,
        send_alerts=payload.send_alerts,
        tenant_id=payload.tenant_id,
        nx_enabled=nx_enabled,
        dedup_ttl=dedup_ttl,
    )

    accepted = 0
    alerts_emitted = 0
    processed_events: List[Dict[str, Any]] = []
    errors: List[str] = []

    for event_model in payload.events:
        processed, alert = await _process_endpoint_event(event_model, ctx)
        processed_events.append(processed)
        accepted += 1
        if alert:
            append_alert(alert)
            alerts_emitted += 1

    return {
        'accepted': accepted,
        'errors': errors,
        'alerts_emitted': alerts_emitted,
        'buffer_size': len(runtime.sanitized_events),
        'events': processed_events,
    }

@app.get('/api/v1/decisions/{event_id}/explain')
def explain_decision(event_id: str) -> Dict[str, Any]:
    decision = DECISION_CACHE.get(event_id)
    if not decision:
        raise HTTPException(status_code=404, detail='decision_not_found')
    factors = list(getattr(decision, 'factors', []) or [])
    try:
        from src.core.mappings import mitre_stride
        stride_tags = mitre_stride.map_factors(factors)
    except Exception as exc:
        LOGGER.debug('Failed to map MITRE stride factors: %s', exc, exc_info=exc)
        stride_tags = []
    factor_payload = [{'name': f, 'weight': None, 'weight_decayed': None} for f in factors]
    return {
        'event_id': event_id,
        'verdict': getattr(decision, 'verdict', 'UNKNOWN'),
        'confidence': getattr(decision, 'confidence', 0.0),
        'factors': factor_payload,
        'mitre_stride_tags': stride_tags,
    }


@app.get('/api/v1/events/sanitized', summary='Retrieve recently sanitized events')
async def events_sanitized(limit: int = 50) -> Dict[str, Any]:
    """Return the most recent sanitized events for debugging clients."""
    runtime = _RUNTIME
    limit = max(0, min(limit, len(runtime.sanitized_events)))
    async with runtime.get_sanitized_lock():
        items = list(runtime.sanitized_events)[:limit]
    return {'events': items, 'count': len(items)}

def track_alert_event(timestamp: float | None) -> None:
    return None
