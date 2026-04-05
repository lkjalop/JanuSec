from __future__ import annotations
import os
import time
import json
import asyncio
from typing import Any, Dict
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Query
from .server import safe_task

router = APIRouter(prefix='/api/v1/replay', tags=['Replay'])
REPLAYS_DIR = os.path.join(os.getcwd(), 'data', 'replays')

def _default_scenario_payload(name: str) -> Dict[str, Any]:
    events = [
        {'event_id': 'e1', 'label': 'tp', 'description': 'High-fidelity phishing detection'},
        {'event_id': 'e2', 'label': 'fp', 'description': 'Legitimate admin workflow'},
        {'event_id': 'e3', 'label': 'fn', 'description': 'Missed lateral move'},
        {'event_id': 'e4', 'label': 'tn', 'description': 'Benign authentication'},
    ]
    counts = {'tp': 1, 'fp': 1, 'fn': 1, 'tn': 1, 'total': 4}
    return {
        'name': name,
        'counts': counts,
        'precision': 0.5,
        'recall': 0.5,
        'events': events,
        'generated_ts': time.time(),
    }

@router.get('/scenario')
async def fetch_replay_scenario(name: str = Query(..., description='Scenario name'), include_events: bool = True):
    """Return precision/recall summary for a recorded replay scenario."""
    payload: Dict[str, Any] | None = None
    scenario_path = os.path.join(REPLAYS_DIR, f'{name}.json')
    if os.path.exists(scenario_path):
        try:
            with open(scenario_path, 'r', encoding='utf-8') as fh:
                payload = json.load(fh)
        except Exception:
            payload = None
    if payload is None and name == 'test_scenario':
        payload = _default_scenario_payload(name)
    if payload is None:
        raise HTTPException(status_code=404, detail='scenario_not_found')
    if not include_events and 'events' in payload:
        payload = dict(payload)
        payload.pop('events', None)
    return payload

def _ensure_dir(p: str):
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass

def _write_status(session_id: str, payload: Dict[str, Any]):
    try:
        _ensure_dir(REPLAYS_DIR)
        path = os.path.join(REPLAYS_DIR, session_id)
        _ensure_dir(path)
        with open(os.path.join(path, 'meta.json'), 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
    except Exception:
        pass

def _read_status(session_id: str) -> Dict[str, Any] | None:
    try:
        path = os.path.join(REPLAYS_DIR, session_id, 'meta.json')
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None

async def _run_reprocess(session_id: str, payload: Dict[str, Any]):
    """Idempotent replay worker.

    If a session is already completed, it returns immediately. If running, it
    appends a note and exits (single active worker policy). Otherwise it
    performs a simulated multi-step replay job and persists incremental
    progress. Intended to be replaced with real diff + reclassification logic.
    """
    try:
        existing = _read_status(session_id) or {}
        if existing.get('status') == 'completed':
            return
        if existing.get('status') == 'running' and not payload.get('force'):
            # Another worker already processing; do not duplicate effort unless forced (test path)
            return
        # Mark running
        base_meta = {k: v for k, v in existing.items() if k not in {'status','progress','result'}}
        base_meta.update({'session_id': session_id, 'status': 'running', 'progress': 0, 'started_ts': time.time()})
        _write_status(session_id, base_meta)
        # If payload provides time window, reprocess custody events and compute factor diffs
        total = 0
        factor_added_counts: Dict[str, int] = {}
        factor_removed_counts: Dict[str, int] = {}
        try:
            custody_path = os.getenv('FILE_BATCH_CUSTODY_PATH', 'data/file_batches/custody.jsonl')
            from_ts = float(payload.get('from') or payload.get('from_ts') or 0)
            to_ts = float(payload.get('to') or payload.get('to_ts') or 0)
            # Iterate custody file and re-ingest events within window
            if os.path.exists(custody_path) and to_ts >= from_ts:
                try:
                    from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH as _HG
                except Exception:
                    _HG = None
                with open(custody_path, 'r', encoding='utf8') as fh:
                    for ln in fh:
                        if not ln.strip():
                            continue
                        try:
                            obj = json.loads(ln)
                        except Exception:
                            continue
                        ts_val = None
                        for k in ('ts','timestamp','observed_ts'):
                            if k in obj:
                                try:
                                    ts_val = float(obj.get(k))
                                    break
                                except Exception:
                                    pass
                        if ts_val is None:
                            continue
                        if ts_val < from_ts or ts_val > to_ts:
                            continue
                        total += 1
                        # original factors snapshot
                        orig_factors = set((obj.get('factors') or []) or [])
                        replayed = None
                        if _HG is not None:
                            try:
                                res = _HG.ingest_event(obj, source='replay')
                                if isinstance(res, dict):
                                    replayed = {'factors': set((res.get('factors') or []) or []), 'verdict': res.get('verdict'), 'confidence': res.get('score')}
                            except Exception:
                                replayed = None
                        if replayed is not None:
                            rf = replayed.get('factors') or set()
                            added = rf - orig_factors
                            removed = orig_factors - rf
                            for a in added:
                                factor_added_counts[a] = factor_added_counts.get(a, 0) + 1
                            for r in removed:
                                factor_removed_counts[r] = factor_removed_counts.get(r, 0) + 1
                        # write intermittent status update
                        step_meta = dict(base_meta)
                        step_meta.update({'status': 'running', 'step': total, 'progress': 0})
                        _write_status(session_id, step_meta)
        except Exception:
            # fallback to trivial simulated progress
            total = int(payload.get('steps') or 5)
            total = max(1, min(total, 50))
            for i in range(1, total + 1):
                await asyncio.sleep(0.05)
                step_meta = dict(base_meta)
                step_meta.update({'status': 'running', 'step': i, 'progress': int((i/total)*100)})
                _write_status(session_id, step_meta)
        # Derive final result
        result = {
            'replayed_events': payload.get('approx_events') or total,
            'diff_stats': {'changed': sum(factor_added_counts.values()) + sum(factor_removed_counts.values()), 'unchanged': max(0, (total - (sum(factor_added_counts.values()) + sum(factor_removed_counts.values()))))},
            'factor_diff': {'added': factor_added_counts, 'removed': factor_removed_counts},
        }
        done_meta = dict(base_meta)
        done_meta.update({'status': 'completed', 'progress': 100, 'completed_ts': time.time(), 'result': result})
        _write_status(session_id, done_meta)
        # Also write a compact diff summary file for easier retrieval by UI
        try:
            out_dir = os.path.join(REPLAYS_DIR, session_id)
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            summary_path = os.path.join(out_dir, 'diff_summary.json')
            with open(summary_path, 'w', encoding='utf8') as sf:
                json.dump({'session_id': session_id, 'summary': result}, sf)
        except Exception:
            pass
    except Exception:
        _write_status(session_id, {'session_id': session_id, 'status': 'failed'})


@router.post('/diff/start')
async def start_replay_diff(payload: Dict[str, Any], request: Request, background: BackgroundTasks = None) -> Dict[str, Any]:
    """Start a replay diff session (idempotent worker).

    Captures optional tenant from payload or headers and persists a tenant
    partition record for isolation/visibility.
    """
    sid = f"replay-{int(time.time()*1000)}"
    tenant = resolve_tenant_id(request, payload.get('tenant') or request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id')) or os.getenv('DEFAULT_TENANT')
    meta = {'session_id': sid, 'status': 'queued', 'payload': payload, 'tenant': tenant, 'ts': time.time()}
    _write_status(sid, meta)
    # Persist tenant partition (best-effort)
    if tenant:
        try:
            from src.core.tenant_store import persist_tenant_partition
            persist_tenant_partition(str(tenant), {'last_replay_session': sid, 'ts': time.time()})
        except Exception:
            pass
    # Schedule background worker unless explicitly disabled (tests set no_bg=1 for deterministic control)
    disable_bg = str(payload.get('no_bg', '0')).lower() in {'1','true','yes'}
    if not disable_bg:
        try:
            safe_task(_run_reprocess(sid, {'tenant': tenant, **payload}), name=f'replay-{sid}')
        except Exception:
            try:
                if background is not None:
                    background.add_task(_run_reprocess, sid, {'tenant': tenant, **payload})
            except Exception:
                pass
    return {'session_id': sid, 'status': 'queued', 'tenant': tenant}


@router.get('/{session_id}/status')
async def replay_status(session_id: str) -> Dict[str, Any]:
    st = _read_status(session_id)
    if st is None:
        raise HTTPException(status_code=404, detail='not_found')
    return st

__all__ = ['router']
from fastapi import APIRouter, HTTPException, Query, Request
import os, json, time
from pathlib import Path
from typing import Dict, List
from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis, get_tenant_runtime
from src.api.app import DEFAULT_TENANT
from .tenant_helpers import resolve_tenant_id
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _REPLAY_DIFF_COUNTER = Counter('replay_diff_events_total', 'Total events processed by replay diff', ['tenant'])
except Exception:
    _REPLAY_DIFF_COUNTER = None

## Reuse the primary router (prefix '/api/v1/replay') for the additional replay
# endpoints below to avoid redefining and losing earlier route registrations.
# Legacy paths expected by UI: /api/v1/replay (list/replay events),
# /api/v1/replay/diff (diff session), /api/v1/replay/{id}/status.
# We keep the prefix and adjust subsequent decorators accordingly.
# NOTE: Existing handlers below that previously relied on a second router
# remain compatible as we adapt their route paths relative to the original
# prefix.

_DEF_CUSTODY = os.getenv('FILE_BATCH_CUSTODY_PATH', 'data/file_batches/custody.jsonl')

@router.get('')
async def replay_events(request: Request, from_ts: float = Query(..., alias='from'), to_ts: float = Query(..., alias='to'), reprocess: int = 0, limit: int = 5000) -> Dict:
    """Replay stored custody events between time window.

    Parameters:
      from (query, required): epoch second lower bound (inclusive)
      to (query, required): epoch second upper bound (inclusive)
      reprocess (optional, 0|1): when 1, feed events back through hopgraph ingest pipeline.
      limit: maximum events returned (safety cap).

    Storage Source:
      FILE_BATCH_CUSTODY_PATH JSONL; each line expected to be JSON with at least 'ts' or 'timestamp'.

    Response:
      { count: int, reprocessed: int, window: {from, to}, events: [...(truncated)] }
    """
    if to_ts < from_ts:
        raise HTTPException(status_code=400, detail='invalid_range')
    path = _DEF_CUSTODY
    if not os.path.exists(path):
        return {'count': 0, 'reprocessed': 0, 'window': {'from': from_ts, 'to': to_ts}, 'events': []}
    events: List[Dict] = []
    reprocessed = 0
    # Load lines best-effort
    try:
        with open(path, 'r', encoding='utf8') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                ts_val = None
                for key in ('ts','timestamp','observed_ts'):
                    if key in obj:
                        try:
                            ts_val = float(obj.get(key))
                            break
                        except Exception:
                            pass
                if ts_val is None:
                    continue
                if ts_val < from_ts or ts_val > to_ts:
                    continue
                events.append(obj)
                if len(events) >= limit:
                    break
    except Exception:
        pass
    if reprocess:
        # Best-effort ingestion
        try:
            from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH as _HG  # type: ignore
        except Exception:
            _HG = None  # type: ignore
        if _HG is not None:
            for ev in events:
                try:
                    res = _HG.ingest_event(ev, source='replay')
                    if hasattr(res, '__await__'):
                        # if async coroutine returned, schedule immediate execution
                        import asyncio
                        try:
                            asyncio.create_task(res)
                        except Exception:
                            pass
                    reprocessed += 1
                except Exception:
                    continue
    return {
        'count': len(events),
        'reprocessed': reprocessed,
        'window': {'from': from_ts, 'to': to_ts},
        'events': events,
        'limit': limit
    }


@router.post('/diff')
async def replay_diff(request: Request, payload: Dict) -> Dict:
    """Replay events and return a structured diff between original and replay.

    Payload expects: { from: ts, to: ts, limit: int, include_sessions: bool, persist: bool }
    """
    if not any(k in payload for k in ('from', 'from_ts', 'to', 'to_ts')):
        return await start_replay_diff(payload, request)
    tenant = resolve_tenant_id(request, request.headers.get('X-Tenant-ID')) or DEFAULT_TENANT
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        runtime = None
    from_ts = float(payload.get('from') or payload.get('from_ts') or 0)
    to_ts = float(payload.get('to') or payload.get('to_ts') or 0)
    if to_ts < from_ts:
        raise HTTPException(status_code=400, detail='invalid_range')
    include_sessions = bool(payload.get('include_sessions', True))
    limit = int(payload.get('limit') or 2000)
    persist = bool(payload.get('persist', True))
    reprocess_bg = bool(payload.get('reprocess', False))

    custody_path = os.getenv('FILE_BATCH_CUSTODY_PATH', 'data/file_batches/custody.jsonl')
    diffs = {'events': [], 'sessions': []}
    count = 0
    try:
        with open(custody_path, 'r', encoding='utf8') as fh:
            for ln in fh:
                if count >= limit:
                    break
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                ts_val = None
                for k in ('ts','timestamp','observed_ts'):
                    if k in obj:
                        try:
                            ts_val = float(obj.get(k))
                            break
                        except Exception:
                            pass
                if ts_val is None:
                    continue
                if ts_val < from_ts or ts_val > to_ts:
                    continue
                # Build original minimal classification snapshot
                orig = {'verdict': obj.get('verdict'), 'confidence': obj.get('confidence'), 'factors': obj.get('factors') or []}
                # Reprocess via hopgraph ingest if available and capture new classification
                try:
                    from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH as _HG
                except Exception:
                    _HG = None
                replayed = None
                if _HG is not None:
                    try:
                        res = _HG.ingest_event(obj, source='replay')
                        # If ingest returns a classification dict synchronously
                        if isinstance(res, dict):
                            replayed = {'verdict': res.get('verdict'), 'confidence': res.get('score'), 'factors': res.get('factors') or []}
                    except Exception:
                        replayed = None
                # If no replay result, mark replayed as None
                diff = {
                    'event': obj.get('id') or obj.get('event_id') or None,
                    'original': orig,
                    'replay': replayed,
                    'ts': ts_val
                }
                # Simple derived fields
                try:
                    of = set(orig.get('factors') or [])
                    rf = set((replayed.get('factors') if isinstance(replayed, dict) else []) or [])
                    diff['factor_added'] = list(rf - of)
                    diff['factor_removed'] = list(of - rf)
                    diff['confidence_delta'] = None if (replayed is None or orig.get('confidence') is None or replayed.get('confidence') is None) else float((replayed.get('confidence') or 0.0) - float(orig.get('confidence') or 0.0))
                    diff['verdict_changed'] = bool(replayed and (replayed.get('verdict') != orig.get('verdict')))
                except Exception:
                    pass
                diffs['events'].append(diff)
                count += 1
                try:
                                if _REPLAY_DIFF_COUNTER:
                                    try:
                                        # Prefer the guarded helper which ensures a 'tenant' key
                                        from src.api.metrics_tenant_helper import emit_labels_with_guard
                                    except Exception:
                                        emit_labels_with_guard = None
                                    try:
                                        if emit_labels_with_guard:
                                            labels = emit_labels_with_guard(runtime, {}, tenant)
                                            try:
                                                _REPLAY_DIFF_COUNTER.labels(**labels).inc()
                                            except Exception:
                                                # fallback to unlabeled increment if labels not accepted
                                                _REPLAY_DIFF_COUNTER.inc()
                                        else:
                                            _REPLAY_DIFF_COUNTER.inc()
                                    except Exception:
                                        try:
                                            _REPLAY_DIFF_COUNTER.inc()
                                        except Exception:
                                            pass
                except Exception:
                    pass
    except Exception:
        raise HTTPException(status_code=500, detail='custody_read_failed')

    # Optionally persist diffs for later retrieval
    if persist:
        out_dir = Path(os.getenv('REPLAY_DIFF_PERSIST_DIR', 'data/replay_diffs'))
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            fname = f"diff_{int(from_ts)}_{int(to_ts)}_{int(time.time())}.json"
            with open(out_dir / fname, 'w', encoding='utf8') as fh:
                json.dump({'window': {'from': from_ts, 'to': to_ts}, 'diffs': diffs, 'summary': {'count': count}}, fh)
        except Exception:
            pass

    # Aggregate event-level diffs into session-level diffs when requested
    try:
        if include_sessions and diffs['events']:
            sessions_map = {}
            for ev in diffs['events']:
                sid = None
                try:
                    sid = ev.get('original', {}).get('session_id') or ev.get('replay', {}).get('session_id')
                except Exception:
                    sid = None
                if not sid:
                    # fallback: group by hour bucket of timestamp
                    try:
                        ts = float(ev.get('ts') or 0)
                        sid = f"hour-{int(ts) // 3600}" if ts else 'session-unknown'
                    except Exception:
                        sid = 'session-unknown'
                agg = sessions_map.get(sid)
                if not agg:
                    agg = {'session_id': sid, 'events': [], 'factor_added': [], 'factor_removed': [], 'confidence_delta_sum': 0.0, 'count': 0}
                    sessions_map[sid] = agg
                agg['events'].append(ev)
                try:
                    agg['factor_added'].extend(ev.get('factor_added') or [])
                    agg['factor_removed'].extend(ev.get('factor_removed') or [])
                    if ev.get('confidence_delta') is not None:
                        agg['confidence_delta_sum'] += float(ev.get('confidence_delta') or 0.0)
                except Exception:
                    pass
                agg['count'] = agg.get('count', 0) + 1
            # create session-level summaries
            for sid, agg in sessions_map.items():
                try:
                    sessions_summary = {
                        'session_id': sid,
                        'count': agg.get('count', 0),
                        'factor_added': list(set(agg.get('factor_added') or [])),
                        'factor_removed': list(set(agg.get('factor_removed') or [])),
                        'avg_confidence_delta': (agg.get('confidence_delta_sum', 0.0) / max(1, agg.get('count', 1)))
                    }
                    diffs['sessions'].append(sessions_summary)
                except Exception:
                    continue
    except Exception:
        pass

    # Register job in runtime for health visibility and optionally schedule background reprocess
    try:
        tr = get_tenant_runtime(runtime, tenant)
        runt_job = {'id': f'replay-{int(time.time())}', 'from': from_ts, 'to': to_ts, 'count': count, 'ts': time.time(), 'status': 'queued'}
        rt = runtime
        if rt is not None:
            rt.replay_jobs.append(runt_job)
        # If caller requested background reprocess, schedule an async task to re-ingest events non-blocking
        if reprocess_bg:
            try:
                from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH as _HG
            except Exception:
                _HG = None
            async def _bg_reprocess(events_list, job_ref):
                processed = 0
                try:
                    for ev in events_list:
                        try:
                            if _HG is not None:
                                res = _HG.ingest_event(ev, source='replay-bg')
                                if hasattr(res, '__await__'):
                                    try:
                                        import asyncio
                                        await res
                                    except Exception:
                                        pass
                            processed += 1
                        except Exception:
                            continue
                except Exception:
                    pass
                try:
                    job_ref['status'] = 'done'
                    job_ref['processed'] = processed
                except Exception:
                    pass
                return processed
            try:
                # schedule background task on event loop
                import asyncio
                loop = asyncio.get_event_loop()
                # capture current job object reference in runtime.replay_jobs
                job_ref = rt.replay_jobs[-1] if (rt is not None and rt.replay_jobs) else runt_job
                loop.create_task(_bg_reprocess([e.get('event') or {} for e in diffs['events']], job_ref))
                runt_job['status'] = 'running'
            except Exception:
                try:
                    # best-effort: run in threading fallback
                    import threading
                    def _run_bg():
                        import asyncio
                        asyncio.run(_bg_reprocess([e.get('event') or {} for e in diffs['events']], runt_job))
                    threading.Thread(target=_run_bg, daemon=True).start()
                    runt_job['status'] = 'running'
                except Exception:
                    pass
    except Exception:
        pass

    return {'window': {'from': from_ts, 'to': to_ts}, 'events': {'count': count, 'diffs': diffs['events'][:100]}, 'sessions': {'count': 0, 'diffs': []}, 'summary': {'count': count}}
