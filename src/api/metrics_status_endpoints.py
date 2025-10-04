@router.get('/api/v1/finops/cost_summary', summary='Combined cost summary (overview, daily, forecast)')
async def finops_cost_summary(tenant: str | None = Query(None)) -> dict[str, Any]:
    """Return a short cost summary object combining overview, daily, and forecast."""
    try:
        # Overview
        overview = await finops_overview()
        # Daily
        daily = await finops_daily()
        # Forecast
        forecast = await finops_forecast(tenant)
        return {
            'overview': overview,
            'daily': daily,
            'forecast': forecast
        }
    except Exception as e:
        return {'overview': {}, 'daily': {}, 'forecast': {}, 'error': str(e)}
"""Dashboard status & executive metrics endpoints (P1 placeholders)."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, Query
from pathlib import Path
import json

from .dependencies import get_platform_state
from .state import PlatformState

try:
    from .finops_endpoints import finops_overview as _finops_overview_impl  # type: ignore
    # Re-export get_finops_manager for tests/monkeypatch convenience
    from core.finops.finops_manager import get_finops_manager  # type: ignore
except Exception:  # fallback stub
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

@router.get('/api/v1/status/dashboard')
async def status_dashboard(tenant_id: str | None = Header(None, alias='X-Tenant-ID'), state: PlatformState = Depends(get_platform_state)) -> dict[str, Any]:
    alerts = state.recent_alerts(limit=200, tenant_id=tenant_id)
    def sever(rec) -> str:
        sc = getattr(rec, 'score', 0) or 0
        ver = (getattr(rec, 'verdict', '') or '').lower()
        if ver in ('malicious','block','escalate') and sc >= 0.9: return 'critical'
        if sc >= 0.75: return 'high'
        if sc >= 0.55: return 'medium'
        return 'low'
    sev_counts = {'critical':0,'high':0,'medium':0}
    for a in alerts:
        s = sever(a)
        if s in sev_counts: sev_counts[s]+=1
    return {
        'alerts': sev_counts,
        'last_update': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'xdr_connected': True,
        'tenant_id': tenant_id,
    }

@router.get('/api/v1/finops/overview')
async def finops_overview():
    res = await _finops_overview_impl() if callable(getattr(_finops_overview_impl, '__call__', None)) else _finops_overview_impl()
    # Append to ring best-effort
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

# ---------- FinOps & Cost Ledger Extensions ----------
@router.get('/api/v1/finops/ledger', summary='Cost ledger inference summary')
async def finops_ledger() -> dict[str, Any]:
    """Expose the in-memory cost ledger inference summary for UI consumption."""
    try:
        from core.metrics.cost_ledger import get_cost_ledger  # type: ignore
        return get_cost_ledger().summary()
    except Exception:
        return { 'inference_summary': [] }

@router.get('/api/v1/finops/daily', summary='Daily estimated cost summary')
async def finops_daily() -> dict[str, Any]:
    """Expose daily/month-to-date estimated dollars and unit prices.

    Backed by artifact.cost_tracker if present; otherwise returns zeros.
    """
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
            'unit_prices': {}
        }

@router.get('/api/v1/finops/estimate', summary='Estimate hunt cost over a window')
async def finops_estimate(
    window_hours: int = Query(24, ge=1, le=24*14),
    tenant: str | None = Query(None),
    model_enabled: bool = Query(False)
) -> dict[str, Any]:
    try:
        from core.finops.cost_estimator import estimate_hunt_cost  # type: ignore
        # Get primary estimate
        est = estimate_hunt_cost(window_hours, tenant or 'all', model_enabled=model_enabled)
        # Recompute a simple breakdown using the same assumptions
        # This mirrors cost_estimator logic; kept lightweight to avoid import loops.
        avg_events = 8000
        fusion_density = 0.002
        model_ratio = 0.1 if model_enabled else 0.0
        events_est = avg_events * window_hours
        fusion_candidates = int(events_est * fusion_density)
        model_calls = int(fusion_candidates * model_ratio)
        # Approximate derived costs with same constants used in estimator
        # We don't have dynamic cost_per_1k here; present relative breakdown using units
        C_f = 0.05
        C_m = 0.5
        base_units = (events_est/1000)
        fusion_units = fusion_candidates * C_f
        model_units = model_calls * C_m
        total_units = base_units + fusion_units + model_units
        if total_units > 0:
            est['breakdown'] = {
                'base': round(base_units, 2),
                'fusion': round(fusion_units, 2),
                'model': round(model_units, 2),
            }
        else:
            est['breakdown'] = {'base':0.0,'fusion':0.0,'model':0.0}
        return est
    except Exception:
        return { 'window_hours': window_hours, 'tenant': tenant or 'all', 'total_units': 0.0, 'confidence': 'low', 'margin_units': 0.0 }

@router.get('/api/v1/finops/forecast', summary='Monthly forecast from daily rollups')
async def finops_forecast(tenant: str | None = Query(None)) -> dict[str, Any]:
    try:
        # Use module-level get_finops_manager to allow monkeypatch in tests
        fm = get_finops_manager()  # type: ignore[name-defined]
        res = fm.forecast_month(tenant or 'all') if fm else None
        if not isinstance(res, dict):
            res = { 'tenant': tenant or 'all', 'forecast_units': 0.0, 'basis_days': 0 }
        # Normalize shape to include avg_daily
        res.setdefault('avg_daily', 0.0)
        return res
    except Exception:
        return { 'tenant': tenant or 'all', 'forecast_units': 0.0, 'basis_days': 0, 'avg_daily': 0.0 }

@router.get('/api/v1/finops/accuracy', summary='Recent estimation accuracy history')
async def finops_accuracy(limit: int = Query(30, ge=1, le=200)) -> dict[str, Any]:
    try:
        from core.finops.finops_manager import get_finops_manager  # type: ignore
        fm = get_finops_manager()
        return fm.accuracy_history(limit=limit)
    except Exception:
        return { 'history': [] }

@router.get('/api/v1/finops/history', summary='EWMA/Latest history from anomaly log')
async def finops_history(limit: int = Query(60, ge=1, le=1000)) -> dict[str, Any]:
    """Return recent points from the JSONL anomaly log produced by finops_overview calls.

    Response: { points: [ { ts, latest, ewma, threshold, anomaly } ... ] }
    """
    try:
        # Determine log path from runtime state
        from .runtime_state import get_server_runtime_state
        # Create a dummy request-like app? We don't have a Request here; use FastAPI app via import
        from .app import app as _app  # type: ignore
        runtime = get_server_runtime_state(_app)
        p = Path(runtime.finops_anomaly_log)
        if not p.exists():
            # Fallback to in-memory ring if file absent
            return { 'points': _HISTORY_RING[-limit:] }
        # Read all lines and slice last N (file expected to be small for now)
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
        # sort by ts ascending
        rows.sort(key=lambda r: (r.get('ts') or 0))
        # merge with ring (dedup by ts tolerance)
        merged = rows
        try:
            if _HISTORY_RING:
                # include ring items newer than last file ts
                last_ts = rows[-1]['ts'] if rows else 0
                extra = [r for r in _HISTORY_RING if (r.get('ts') or 0) > last_ts]
                merged = rows + extra
        except Exception:
            merged = rows
        return { 'points': merged[-limit:] }
    except Exception:
        # Full fallback to ring only
        return { 'points': _HISTORY_RING[-limit:] }

@router.get('/api/v1/dashboard/metrics')
async def dashboard_metrics(tenant_id: str | None = Header(None, alias='X-Tenant-ID'), state: PlatformState = Depends(get_platform_state)):
    # Lightweight aggregate; if a richer version already exists in dashboard_endpoints, that one can supersede this.
    alerts = state.recent_alerts(limit=500, tenant_id=tenant_id)
    critical = len([a for a in alerts if (getattr(a,'verdict','').lower() in ('malicious','block') and getattr(a,'score',0)>=0.8)])
    artifacts_analyzed = len(alerts)  # placeholder until decisions count accessible
    detected = len([a for a in alerts if getattr(a,'verdict','').lower() in ('malicious','suspicious','block','escalate')])
    detection_rate = (detected / artifacts_analyzed * 100) if artifacts_analyzed else 0.0
    avg_response_time = 1.2  # placeholder constant
    return {
        'critical_threats': critical,
        'artifacts_analyzed': artifacts_analyzed,
        'detection_rate': round(detection_rate,1),
        'avg_response_time': avg_response_time,
        'timestamp': time.time(),
        'tenant_id': tenant_id,
    }

__all__ = ['router']