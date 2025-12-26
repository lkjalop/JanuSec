"""Dashboard status & curated metrics endpoints (consolidated)."""
from __future__ import annotations

import time
from typing import Any
from pathlib import Path
import json
import os

from fastapi import APIRouter, Depends, Header, Query

from .dependencies import get_platform_state
from .state import PlatformState
from src.analysis.cost_tracker import EXTERNAL_TRACKER, LOCAL_TRACKER

try:
    from .finops_endpoints import finops_overview as _finops_overview_impl  # type: ignore
    from core.finops.finops_manager import get_finops_manager  # type: ignore
except Exception:  # fallback stubs
    def _finops_overview_impl():  # type: ignore
        return {
            'detection_cost_today': 0.0,
            'prevented_damage_today': 0.0,
            'ewma_30d': 0.0,
        }

    def get_finops_manager():  # type: ignore
        return None

router = APIRouter(tags=["Metrics"])

# In-memory ring for EWMA/Latest to complement file-based history
_HISTORY_RING: list[dict[str, Any]] = []
_HISTORY_CAP = 600


@router.get('/api/v1/metrics/llm_costs')
async def llm_costs_overview() -> dict[str, Any]:
    """Return aggregated LLM cost tracking for external and local calls."""
    try:
        external = EXTERNAL_TRACKER.get_summary()
    except Exception:
        external = {'total_calls': 0, 'total_cost': 0.0, 'models': {}, 'recent': []}
    try:
        local = LOCAL_TRACKER.get_summary()
    except Exception:
        local = {'total_calls': 0, 'total_gpu_time_ms': 0, 'models': {}, 'recent': []}
    return {'external': external, 'local': local}


@router.get('/api/v1/status/metrics')
async def status_metrics(request=None) -> dict[str, Any]:
    """Lightweight status metrics used by the frontend metrics page.

    Returns SSE client count and ingest queue stats when available.
    """
    sse_clients = 0
    try:
        # Import telemetry ws connection set if available
        from .telemetry_endpoints import _WS_CONNECTIONS  # type: ignore
        sse_clients = len(list(_WS_CONNECTIONS))
    except Exception:
        sse_clients = 0
    queue_stats = {}
    try:
        from .runtime_state import get_server_runtime_state, EVENT_QUEUE  # type: ignore
        # Prefer the bound EVENT_QUEUE; use its stats() when present
        q = EVENT_QUEUE
        if hasattr(q, 'stats') and callable(getattr(q, 'stats')):
            try:
                queue_stats = q.stats() or {}
            except Exception:
                queue_stats = {}
        else:
            queue_stats = {'depth': None, 'accepted': None, 'rejected': None}
    except Exception:
        queue_stats = {'depth': None, 'accepted': None, 'rejected': None}
    return {
        'sse': {
            'clients': sse_clients,
            'queue_depth': None,  # reserved for future SSE backpressure
        },
        'queue': queue_stats,
        'ts': time.time(),
    }


@router.get('/api/v1/status/dashboard')
async def status_dashboard(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    state: PlatformState = Depends(get_platform_state),
) -> dict[str, Any]:
    alerts = state.recent_alerts(limit=200, tenant_id=tenant_id)

    def sever(rec) -> str:
        sc = getattr(rec, 'score', 0) or 0
        ver = (getattr(rec, 'verdict', '') or '').lower()
        if ver in ('malicious', 'block', 'escalate') and sc >= 0.9:
            return 'critical'
        if sc >= 0.75:
            return 'high'
        if sc >= 0.55:
            return 'medium'
        return 'low'

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0}
    for a in alerts:
        s = sever(a)
        if s in sev_counts:
            sev_counts[s] += 1
    return {
        'alerts': sev_counts,
        'last_update': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'xdr_connected': True,
        'tenant_id': tenant_id,
    }


@router.get('/api/v1/health/extended')
async def extended_health(request=None) -> dict[str, Any]:
    """Extended health & runtime state snapshot.

    Returns counts for hash history, NX producers, EWMA entries, FP label totals,
    false-positive ratios per factor, and cleanup loop activation based on env.
    """
    stats = {}
    try:
        from .runtime_state import get_server_runtime_state
        from .app import app as _app  # type: ignore
        runtime = get_server_runtime_state(_app if request is None else request.app)
    except Exception:
        runtime = None
    try:
        stats['hash_keys'] = len(getattr(runtime, 'file_hash_factors', {}) or {})
    except Exception:
        stats['hash_keys'] = None
    try:
        stats['nx_producers'] = len(getattr(runtime, 'nx_rate_tracker', {}) or {})
    except Exception:
        stats['nx_producers'] = None
    try:
        stats['ewma_entries'] = len(getattr(runtime, 'ewma_history', {}) or {})
    except Exception:
        stats['ewma_entries'] = None
    try:
        stats['fp_labels_total'] = len(getattr(runtime, 'fp_labels', {}) or {})
    except Exception:
        stats['fp_labels_total'] = None
    try:
        stats['replay_jobs_pending'] = len(getattr(runtime, 'replay_jobs', []) or [])
    except Exception:
        stats['replay_jobs_pending'] = None
    # Compute per-factor FP ratio if counters available
    fp_ratio = {}
    try:
        counts = getattr(runtime, 'fp_factor_counts', {}) or {}
        fp_counts = getattr(runtime, 'fp_factor_fp_labels_counts', {}) or {}
        for fac, tot in counts.items():
            try:
                fp_c = fp_counts.get(fac, 0)
                fp_ratio[fac] = round(fp_c / max(1, tot), 4)
            except Exception:
                continue
    except Exception:
        fp_ratio = {}
    stats['fp_ratio_by_factor'] = fp_ratio
    try:
        stats['cleanup_loop_active'] = bool(int(os.getenv('SESSION_CLEAN_INTERVAL_SECONDS','0') or 0) > 0)
    except Exception:
        stats['cleanup_loop_active'] = False
    stats['timestamp'] = time.time()
    return stats


@router.get('/api/v1/finops/overview')
async def finops_overview():
    res = (
        await _finops_overview_impl()
        if callable(getattr(_finops_overview_impl, '__call__', None))
        else _finops_overview_impl()
    )
    try:
        point = {
            'ts': time.time(),
            'latest': res.get('latest_cost') if isinstance(res, dict) else None,
            'ewma': res.get('ewma') if isinstance(res, dict) else None,
            'threshold': res.get('ewma_threshold') if isinstance(res, dict) else None,
            'anomaly': bool(res.get('anomaly_flag')) if isinstance(res, dict) else False,
        }
        _HISTORY_RING.append(point)
        if len(_HISTORY_RING) > _HISTORY_CAP:
            del _HISTORY_RING[: len(_HISTORY_RING) - _HISTORY_CAP]
    except Exception:
        pass
    return res


@router.get('/api/v1/finops/ledger', summary='Cost ledger inference summary')
async def finops_ledger() -> dict[str, Any]:
    try:
        from core.metrics.cost_ledger import get_cost_ledger  # type: ignore
        return get_cost_ledger().summary()
    except Exception:
        return {'inference_summary': []}


@router.get('/api/v1/finops/daily', summary='Daily estimated cost summary')
async def finops_daily() -> dict[str, Any]:
    try:
        from artifact import cost_tracker  # type: ignore
        return cost_tracker.summary()
    except Exception:
        return {
            'day': None,
            'embedding_calls': 0,
            'reputation_queries': 0,
            'artifacts_processed': 0,
            'llm_tokens': 0,
            'estimated_usd_day': 0.0,
            'estimated_usd_month_to_date': 0.0,
            'unit_prices': {},
        }


@router.get('/api/v1/finops/estimate', summary='Estimate hunt cost over a window')
async def finops_estimate(
    window_hours: int = Query(24, ge=1, le=24 * 14),
    tenant: str | None = Query(None),
    model_enabled: bool = Query(False),
) -> dict[str, Any]:
    try:
        from core.finops.cost_estimator import estimate_hunt_cost  # type: ignore
        est = estimate_hunt_cost(window_hours, tenant or 'all', model_enabled=model_enabled)
        avg_events = 8000
        fusion_density = 0.002
        model_ratio = 0.1 if model_enabled else 0.0
        events_est = avg_events * window_hours
        fusion_candidates = int(events_est * fusion_density)
        model_calls = int(fusion_candidates * model_ratio)
        C_f = 0.05
        C_m = 0.5
        base_units = (events_est / 1000)
        fusion_units = fusion_candidates * C_f
        model_units = model_calls * C_m
        total_units = base_units + fusion_units + model_units
        est['breakdown'] = {
            'base': round(base_units, 2),
            'fusion': round(fusion_units, 2),
            'model': round(model_units, 2),
        } if total_units > 0 else {'base': 0.0, 'fusion': 0.0, 'model': 0.0}
        return est
    except Exception:
        return {
            'window_hours': window_hours,
            'tenant': tenant or 'all',
            'total_units': 0.0,
            'confidence': 'low',
            'margin_units': 0.0,
        }


@router.get('/api/v1/finops/forecast', summary='Monthly forecast from daily rollups')
async def finops_forecast(tenant: str | None = Query(None)) -> dict[str, Any]:
    try:
        fm = get_finops_manager()  # type: ignore[name-defined]
        res = fm.forecast_month(tenant or 'all') if fm else None
        if not isinstance(res, dict):
            res = {'tenant': tenant or 'all', 'forecast_units': 0.0, 'basis_days': 0}
        res.setdefault('avg_daily', 0.0)
        return res
    except Exception:
        return {'tenant': tenant or 'all', 'forecast_units': 0.0, 'basis_days': 0, 'avg_daily': 0.0}


@router.get('/api/v1/finops/accuracy', summary='Recent estimation accuracy history')
async def finops_accuracy(limit: int = Query(30, ge=1, le=200)) -> dict[str, Any]:
    try:
        from core.finops.finops_manager import get_finops_manager  # type: ignore
        fm = get_finops_manager()
        return fm.accuracy_history(limit=limit)
    except Exception:
        return {'history': []}


@router.get('/api/v1/finops/history', summary='EWMA/Latest history from anomaly log')
async def finops_history(limit: int = Query(60, ge=1, le=1000)) -> dict[str, Any]:
    try:
        from .runtime_state import get_server_runtime_state
        from .app import app as _app  # type: ignore
        runtime = get_server_runtime_state(_app)
        p = Path(runtime.finops_anomaly_log)
        if not p.exists():
            return {'points': _HISTORY_RING[-limit:]}
        lines = p.read_text(encoding='utf-8').splitlines()
        rows = []
        for line in lines[-limit:]:
            try:
                j = json.loads(line)
                rows.append({
                    'ts': j.get('ts'),
                    'latest': j.get('latest'),
                    'ewma': j.get('ewma'),
                    'threshold': j.get('threshold'),
                    'anomaly': bool(j.get('anomaly')),
                })
            except Exception:
                continue
        rows.sort(key=lambda r: (r.get('ts') or 0))
        merged = rows
        try:
            if _HISTORY_RING:
                last_ts = rows[-1]['ts'] if rows else 0
                extra = [r for r in _HISTORY_RING if (r.get('ts') or 0) > last_ts]
                merged = rows + extra
        except Exception:
            merged = rows
        return {'points': merged[-limit:]}
    except Exception:
        return {'points': _HISTORY_RING[-limit:]}


@router.get('/api/v1/dashboard/metrics')
async def dashboard_metrics(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    state: PlatformState = Depends(get_platform_state),
):
    alerts = state.recent_alerts(limit=500, tenant_id=tenant_id)
    critical = len(
        [a for a in alerts if (getattr(a, 'verdict', '').lower() in ('malicious', 'block') and getattr(a, 'score', 0) >= 0.8)]
    )
    artifacts_analyzed = len(alerts)
    detected = len([a for a in alerts if getattr(a, 'verdict', '').lower() in ('malicious', 'suspicious', 'block', 'escalate')])
    detection_rate = (detected / artifacts_analyzed * 100) if artifacts_analyzed else 0.0
    avg_response_time = 1.2
    # Add simple consolidation metric (pre vs. post dedupe by id)
    pre_count = artifacts_analyzed
    uniq_ids: set[str] = set(getattr(a, 'id', None) for a in alerts if getattr(a, 'id', None))
    post_count = len(uniq_ids) if uniq_ids else pre_count
    consolidation = {
        'pre': pre_count,
        'post': post_count,
        'factor': round((pre_count / post_count), 2) if post_count else 1.0,
    }
    # Best-effort LM observability from hopgraph path matches (coarse)
    lm_hits = 0
    try:
        from core.graph.hopgraph_lite import get_graph  # type: ignore
        g = get_graph()
        # count hits in last 5 minutes by draining none; just check if any
        lm_hits = 1 if g.path_hit_recent(300) else 0
    except Exception:
        lm_hits = 0

    # LM metrics from recent alerts/factors
    lm_candidates = 0
    lm_composites = 0
    try:
        for a in alerts:
            facs = set(getattr(a, 'factors', []) or [])
            if any(str(f).startswith(('lane_host_pivot:', 'lane_privilege_misuse:')) for f in facs):
                lm_candidates += 1
            if 'lateral_movement_composite' in facs:
                lm_composites += 1
    except Exception:
        pass
    lm_metrics = {
        'candidates': lm_candidates,
        'composites': lm_composites,
        'precision_proxy': round((lm_composites / lm_candidates), 3) if lm_candidates else 0.0,
    }

    # Predictive LM risk (offline TFT-lite scaffold): average risk across entities
    predictive_avg = 0.0
    predictive_count = 0
    try:
        pred_path = os.getenv('PREDICTIVE_OUTPUT', 'artifacts/predictive/lm_daily.jsonl')
        if pred_path and os.path.exists(pred_path):
            total = 0.0
            n = 0
            with open(pred_path, encoding='utf-8') as f:
                for line in f:
                    try:
                        j = json.loads(line)
                        total += float(j.get('risk') or 0.0)
                        n += 1
                    except Exception:
                        continue
            predictive_avg = round((total / n), 3) if n else 0.0
            predictive_count = n
    except Exception:
        predictive_avg = 0.0

    # Cloud posture aggregation (best-effort, tenant-aware, cached)
    cloud_posture = {'total': 0, 'by_type': {}, 'severity': {'critical':0,'high':0,'medium':0,'low':0}}
    try:
        from src.common.jsonl_cache import get_jsonl  # type: ignore
        posture_path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
        ttl = float(os.getenv('JSONL_CACHE_TTL','30') or 30)
        rows = get_jsonl(posture_path, ttl) if posture_path else []
        for j in rows:
            if tenant_id and (j.get('tenant_id') not in {tenant_id}):
                continue
            t = str(j.get('type') or '')
            sev = str(j.get('severity') or '').lower()
            cloud_posture['total'] += 1
            cloud_posture['by_type'][t] = cloud_posture['by_type'].get(t, 0) + 1
            if sev in cloud_posture['severity']:
                cloud_posture['severity'][sev] += 1
    except Exception:
        pass

    return {
        'critical_threats': critical,
        'artifacts_analyzed': artifacts_analyzed,
        'detection_rate': round(detection_rate, 1),
        'avg_response_time': avg_response_time,
        'dedupe_consolidation': consolidation,
        'lm_path_hits_recent': lm_hits,
        'lm_metrics': lm_metrics,
        'predictive_lm_risk_avg': predictive_avg,
        'predictive_entities': predictive_count,
        'cloud_posture': cloud_posture,
        'timestamp': time.time(),
        'tenant_id': tenant_id,
    }


@router.get('/api/v1/finops/cost_summary', summary='Combined cost summary (overview, daily, forecast)')
async def finops_cost_summary(tenant: str | None = Query(None)) -> dict[str, Any]:
    try:
        overview = await finops_overview()
        daily = await finops_daily()
        forecast = await finops_forecast(tenant)
        return {
            'overview': overview,
            'daily': daily,
            'forecast': forecast,
        }
    except Exception as e:
        return {'overview': {}, 'daily': {}, 'forecast': {}, 'error': str(e)}


__all__ = ['router']
