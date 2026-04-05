from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
import time
from pydantic import BaseModel

from ..repositories.precision_metrics_repo import PrecisionMetricsRepo
from src.security.auth import require_scopes
from src.repositories import ab_test_repo

router = APIRouter(prefix='/api/v1/metrics')


def get_repo():
    repo = PrecisionMetricsRepo()
    repo.init_db()
    return repo


@router.get('/fp_reduction_trend')
def fp_reduction_trend(start_ts: int = None, end_ts: int = None, repo: PrecisionMetricsRepo = Depends(get_repo)) -> Dict[str, Any]:
    now = int(time.time())
    start_ts = start_ts or (now - 86400 * 30)
    end_ts = end_ts or now
    try:
        data = repo.fp_reduction_trend(start_ts, end_ts)
        return {'start_ts': start_ts, 'end_ts': end_ts, 'data': data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ab_test/{ab_test_id}')
def ab_test_results(ab_test_id: str, repo: PrecisionMetricsRepo = Depends(get_repo)) -> Dict[str, Any]:
    try:
        data = repo.ab_test_results(ab_test_id)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/admin/init_db')
def admin_init_db(auth: object = Depends(require_scopes('admin'))):
    """Admin helper: initialize the precision metrics DB. Secured by auth dependency."""
    try:
        repo = get_repo()
        repo.init_db()
        # init the ab_test demo table too
        try:
            ab_test_repo.init_db()
        except Exception:
            pass
        return {'status': 'ok', 'db_path': getattr(repo, 'db_path', None)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ABRecordIn(BaseModel):
    ab_test_id: str
    variant: str
    label: str
    event_id: str | None = None
    reviewer: str | None = None


@router.post('/ab_tests/record')
def record_ab_result(payload: ABRecordIn, auth: object = Depends(require_scopes('operator'))):
    try:
        ab_test_repo.record(payload.ab_test_id, payload.variant, payload.label, payload.event_id, payload.reviewer)
        return {'status': 'ok'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ab_tests/{ab_test_id}/summary')
def ab_test_repo_summary(ab_test_id: str, auth: object = Depends(require_scopes('viewer'))):
    try:
        data = ab_test_repo.summary_for(ab_test_id)
        return {'ab_test_id': ab_test_id, 'summary': data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/fp_reduction_series')
def fp_reduction_series(start_ts: int | None = None, end_ts: int | None = None, repo: PrecisionMetricsRepo = Depends(get_repo)) -> Dict[str, Any]:
    """Return a simple time-bucketed series consumable by dashboards.

    Each entry: { day_ts: int, tp: int, fp: int, total: int, precision: float | None }
    """
    now = int(time.time())
    start_ts = start_ts or (now - 86400 * 30)
    end_ts = end_ts or now
    try:
        data = repo.fp_reduction_trend(start_ts, end_ts)
        return {'start_ts': start_ts, 'end_ts': end_ts, 'series': data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
from fastapi import APIRouter, Depends, HTTPException
import asyncio

def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Running inside event loop: create task and wait
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            return fut.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop in thread
        return asyncio.get_event_loop().run_until_complete(coro)
from typing import List
from datetime import date, datetime
from pydantic import BaseModel
import os
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
from .dependencies import get_platform_state
from .state import PlatformState
from .tenant_helpers import resolve_tenant_id
from fastapi import Request
import json as _json

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])
@router.get('/health')
def metrics_health():
    """Lightweight health snapshot: registry presence + dependency status."""
    try:
        try:
            from .metrics_init import ensure_metrics
            ensure_metrics()
        except Exception:
            pass
        # Best-effort dependency status hook when available
        dep = {}
        try:
            from .graph_sessions import _check_dependency_status  # type: ignore
            dep = _check_dependency_status()
        except Exception:
            try:
                from .graph_session_endpoints import _check_dependency_status  # type: ignore
                dep = _check_dependency_status()
            except Exception:
                dep = {}
        # Minimal registry check using metrics_init REGISTRY name list
        reg_ok = False
        names = []
        try:
            from .metrics_init import REGISTRY
            if REGISTRY is not None:
                reg_ok = True
                try:
                    names = list(getattr(REGISTRY, '_names_to_collectors', {}).keys())[:10]
                except Exception:
                    names = []
        except Exception:
            reg_ok = False
        return {
            'registry_initialized': reg_ok,
            'metrics_sample_present': names,
            'dependency_status': dep,
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))



class DailyMetricsIn(BaseModel):
    day: date
    tenant_id: str
    tp: int
    fp: int
    fn: int


class ABTestQuery(BaseModel):
    tenant_id: str
    test_id: str


_DB_PATH = os.getenv('JANUSEC_SQLITE_PATH', 'data/janusec.db')
_repo = PrecisionMetricsRepo(_DB_PATH)
_CONFIG_PATH = os.getenv('METRICS_CONFIG_PATH', 'data/metrics_config.json')
_ALERTS_CONFIG_PATH = os.getenv('METRICS_ALERTS_CONFIG_PATH', 'data/metrics_alerts.json')
_metrics_config = {
    'window_days': int(os.getenv('METRICS_WINDOW_DAYS', '28')),
    'min_sample_size': int(os.getenv('METRICS_MIN_SAMPLE', '200')),
    'mde': float(os.getenv('METRICS_MDE', '0.03')),
    'alpha': float(os.getenv('METRICS_ALPHA', '0.05'))
}
_alerts_config: dict[str, dict] = {}

def _load_persisted_config():
    try:
        if os.path.exists(_CONFIG_PATH):
            with open(_CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = _json.load(f)
                if isinstance(data, dict):
                    _metrics_config.update({
                        k: data.get(k, _metrics_config.get(k))
                        for k in ['window_days','min_sample_size','mde','alpha']
                    })
    except Exception:
        pass

def _load_alerts_config():
    try:
        if os.path.exists(_ALERTS_CONFIG_PATH):
            with open(_ALERTS_CONFIG_PATH, 'r', encoding='utf-8') as f:
                data = _json.load(f)
                if isinstance(data, dict):
                    # Expect shape: { tenant: { route: { fp_rate_max, detection_rate_min, alert_enabled } } }
                    global _alerts_config
                    _alerts_config = data
    except Exception:
        pass

def _save_persisted_config():
    try:
        os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
        with open(_CONFIG_PATH, 'w', encoding='utf-8') as f:
            _json.dump(_metrics_config, f)
    except Exception:
        pass

def _save_alerts_config():
    try:
        os.makedirs(os.path.dirname(_ALERTS_CONFIG_PATH), exist_ok=True)
        with open(_ALERTS_CONFIG_PATH, 'w', encoding='utf-8') as f:
            _json.dump(_alerts_config, f)
    except Exception:
        pass

_load_persisted_config()
_load_alerts_config()


@router.post('/ingest_daily')
def ingest_daily_metrics(payload: DailyMetricsIn):
    try:
        _repo.insert_daily_metrics(payload.day, payload.tenant_id, payload.tp, payload.fp, payload.fn)
        return {'status': 'ok'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/fp_reduction_trend')
def fp_reduction_trend(tenant_id: str, start: date, end: date, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id)
    try:
        data = _repo.get_daily_metrics(tenant_id, start, end)
        return {'tenant_id': tenant_id, 'start': start.isoformat(), 'end': end.isoformat(), 'data': data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/precision_recall_trend')
def precision_recall_trend(tenant_id: str, start: date, end: date, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id)
    """Alias for fp_reduction_trend returning precision/recall timeseries.

    Useful for UI charts expecting a dedicated precision/recall endpoint.
    """
    try:
        data = _repo.get_daily_metrics(tenant_id, start, end)
        # Ensure only required fields for trend charts
        series = [
            {
                'day': row.get('day'),
                'precision': row.get('precision'),
                'recall': row.get('recall'),
                'tp': row.get('tp'),
                'fp': row.get('fp'),
                'fn': row.get('fn'),
            }
            for row in data
        ]
        return {'tenant_id': tenant_id, 'start': start.isoformat(), 'end': end.isoformat(), 'series': series}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ab_test_summary', operation_id='metrics_ab_test_summary')
def ab_test_summary(tenant_id: str, test_id: str, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id)
    try:
        try:
            from src.repositories import decision_labels_repo
            # prefer DB-backed aggregation
            try:
                variants = asyncio_run(decision_labels_repo.ab_test_summary(tenant_id, test_id))
            except Exception as dexc:
                # If the repository raises an sqlite OperationalError for missing
                # tables or columns (common in fresh dev DBs or schema drift),
                # attempt a best-effort fallback: read the simple `ab_test_results`
                # demo table (if present) to synthesize per-variant counts.
                try:
                    import sqlite3
                    msg = str(dexc).lower()
                    if isinstance(dexc, sqlite3.OperationalError) and ('no such table' in msg or 'no such column' in msg):
                        # try reading from a simple demo table we may have seeded
                        try:
                            conn = sqlite3.connect(_DB_PATH)
                            cur = conn.cursor()
                            cur.execute("SELECT variant, SUM(tp) as tp, SUM(fp) as fp, SUM(fn) as fn FROM ab_test_results WHERE tenant_id=? AND test_id=? GROUP BY variant", (tenant_id, test_id))
                            rows = cur.fetchall()
                            variants = []
                            for r in rows:
                                variants.append({'variant': r[0], 'tp': int(r[1] or 0), 'fp': int(r[2] or 0), 'fn': int(r[3] or 0)})
                            conn.close()
                        except Exception:
                            variants = []
                    else:
                        raise
                except Exception:
                    # Not sqlite or different error - re-raise
                    raise
            # compute precision per variant
            out = []
            for v in variants:
                tp = int(v.get('tp') or 0)
                fp = int(v.get('fp') or 0)
                fn = int(v.get('fn') or 0)
                precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
                recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
                v['precision'] = precision
                v['recall'] = recall
                out.append(v)
            return {'tenant_id': tenant_id, 'test_id': test_id, 'variants': out}
        except Exception:
            data = _repo.get_ab_test_summary(tenant_id, test_id)
            # repo returns simple variant summaries; best-effort compute precision
            out = []
            for v in data:
                tp = int(v.get('tp') or 0)
                fp = int(v.get('fp') or 0)
                fn = int(v.get('fn') or 0)
                v['precision'] = (tp / (tp + fp)) if (tp + fp) > 0 else None
                v['recall'] = (tp / (tp + fn)) if (tp + fn) > 0 else None
                out.append(v)
            return {'tenant_id': tenant_id, 'test_id': test_id, 'variants': out}
    except HTTPException:
        raise
    except Exception as e:
        # If the error is due to missing AB tables return a safe empty
        # response to avoid breaking the UI during local dev.
        try:
            import sqlite3
            if isinstance(e, sqlite3.OperationalError) and 'no such table' in str(e).lower():
                return {'tenant_id': tenant_id, 'test_id': test_id, 'variants': []}
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ab_test_daily')
def ab_test_daily(tenant_id: str, test_id: str, start: date, end: date, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id)
    try:
        from src.repositories import decision_labels_repo
        rows = asyncio_run(decision_labels_repo.ab_test_daily(tenant_id, test_id, start.isoformat()+'Z', end.isoformat()+'Z'))
        # rows: list of {day, variant, tp, fp, fn}
        # group by variant
        out = {}
        for r in rows:
            v = r.get('variant') or 'unknown'
            day = r.get('day')
            tp = int(r.get('tp') or 0)
            fp = int(r.get('fp') or 0)
            fn = int(r.get('fn') or 0)
            prec = (tp / (tp + fp)) if (tp + fp) > 0 else None
            if v not in out:
                out[v] = []
            out[v].append({'day': str(day), 'tp': tp, 'fp': fp, 'fn': fn, 'precision': prec})
        return {'tenant_id': tenant_id, 'test_id': test_id, 'daily': out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/ab_test_winner')
def ab_test_winner(tenant_id: str, test_id: str, mde: float | None = None, alpha: float | None = None, min_n: int | None = None, method: str | None = None, request: Request = None):
    tenant_id = resolve_tenant_id(request, tenant_id)
    """Compute winner between variants using precision with pooled variance.
    Flags a winner only if absolute delta >= mde and sample sizes >= min_n.
    """
    try:
        from src.repositories import decision_labels_repo
        try:
            variants = asyncio_run(decision_labels_repo.ab_test_summary(tenant_id, test_id))
        except Exception as dexc:
            try:
                import sqlite3
                if isinstance(dexc, sqlite3.OperationalError) and 'no such table' in str(dexc).lower():
                    variants = []
                else:
                    raise
            except Exception:
                raise
        # prepare stats per variant
        stats = []
        for v in variants:
            tp = int(v.get('tp') or 0)
            fp = int(v.get('fp') or 0)
            n = tp + fp
            p = (tp / n) if n > 0 else None
            stats.append({'variant': v.get('variant') or 'base', 'tp': tp, 'fp': fp, 'n': n, 'precision': p})
        # need at least 2 variants with samples
        active = [s for s in stats if s['n'] > 0 and s['precision'] is not None]
        if len(active) < 2:
            return {'test_id': test_id, 'tenant_id': tenant_id, 'winner': None, 'reason': 'insufficient_variants', 'stats': stats}
        # sort by precision desc
        active.sort(key=lambda x: (x['precision'] or 0.0), reverse=True)
        best, second = active[0], active[1]
        # parameters
        _mde = float(mde if mde is not None else _metrics_config['mde'])
        _alpha = float(alpha if alpha is not None else _metrics_config['alpha'])
        _min_n = int(min_n if min_n is not None else _metrics_config['min_sample_size'])
        # pooled variance for proportions (Wald approx)
        # sp^2 = p*(1-p) where p is pooled (tp1+tp2)/(n1+n2)
        n1, n2 = best['n'], second['n']
        p1, p2 = best['precision'] or 0.0, second['precision'] or 0.0
        pooled_p = (best['tp'] + second['tp']) / float(n1 + n2) if (n1 + n2) > 0 else 0.0
        sp = (pooled_p * (1.0 - pooled_p)) ** 0.5
        # standard error of difference
        se = sp * ((1.0 / n1) + (1.0 / n2)) ** 0.5 if n1 > 0 and n2 > 0 else float('inf')
        delta = abs(p1 - p2)
        # two-proportion z-test (Wald) p-value and threshold
        # z critical ~1.96 for alpha=0.05; allow method selection placeholder (wald/newcombe)
        z = 1.96
        _method = (method or 'wald').lower()
        # For "newcombe" we still report Wald z as placeholder; future improvement can implement CI calc.
        threshold = z * se
        meets_effect = delta >= _mde
        meets_sample = (n1 >= _min_n) and (n2 >= _min_n)
        significant = delta > threshold
        # p-value for z-test (two-tailed)
        try:
            import math
            # z-statistic for difference in proportions
            z_stat = (p1 - p2) / se if se and se != float('inf') else 0.0
            # two-tailed p-value using error function approximation
            # p = 2 * (1 - Phi(|z|)); Phi approx via 0.5 * (1 + erf(z/sqrt(2)))
            p_value = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z_stat) / math.sqrt(2.0))))
        except Exception:
            p_value = None
        winner = best['variant'] if (meets_effect and meets_sample and significant) else None
        return {
            'test_id': test_id,
            'tenant_id': tenant_id,
            'winner': winner,
            'delta': delta,
            'threshold': threshold,
            'p_value': p_value,
            'method': _method,
            'meets_effect': meets_effect,
            'meets_sample': meets_sample,
            'significant': significant,
            'stats': stats
        }
    except Exception as e:
        try:
            import sqlite3
            if isinstance(e, sqlite3.OperationalError) and 'no such table' in str(e).lower():
                return {
                    'test_id': test_id,
                    'tenant_id': tenant_id,
                    'winner': None,
                    'reason': 'no_ab_data',
                    'stats': []
                }
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/config')
def get_metrics_config():
    return _metrics_config


class MetricsConfigUpdate(BaseModel):
    window_days: int | None = None
    min_sample_size: int | None = None
    mde: float | None = None
    alpha: float | None = None


@router.post('/config')
def update_metrics_config(payload: MetricsConfigUpdate):
    try:
        if payload.window_days is not None:
            _metrics_config['window_days'] = int(payload.window_days)
        if payload.min_sample_size is not None:
            _metrics_config['min_sample_size'] = int(payload.min_sample_size)
        if payload.mde is not None:
            _metrics_config['mde'] = float(payload.mde)
        if payload.alpha is not None:
            _metrics_config['alpha'] = float(payload.alpha)
        _save_persisted_config()
        return {'status': 'ok', 'config': _metrics_config}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class AlertThresholdsUpdate(BaseModel):
    tenant_id: str
    route: str | None = None
    fp_rate_max: float | None = None
    detection_rate_min: float | None = None
    alert_enabled: bool | None = None


@router.get('/alerts/config')
def get_alerts_config(tenant_id: str | None = None, request: Request = None):
    tenant_id = resolve_tenant_id(request, tenant_id)
    """Return alerting threshold configuration.

    If `tenant_id` provided, return that tenant's config only.
    Shape: { tenant: { route: { fp_rate_max, detection_rate_min, alert_enabled } } }
    """
    try:
        if tenant_id:
            return {'tenant_id': tenant_id, 'config': _alerts_config.get(tenant_id, {})}
        return {'config': _alerts_config}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/alerts/config')
def update_alerts_config(payload: AlertThresholdsUpdate):
    """Update alert thresholds for a tenant/route.

    Missing fields are left unchanged; missing route keys are created.
    """
    try:
        tid = payload.tenant_id
        route = payload.route or 'global'
        cur = _alerts_config.setdefault(tid, {}).get(route)
        if not isinstance(cur, dict):
            _alerts_config[tid][route] = {}
            cur = _alerts_config[tid][route]
        if payload.fp_rate_max is not None:
            cur['fp_rate_max'] = float(payload.fp_rate_max)
        if payload.detection_rate_min is not None:
            cur['detection_rate_min'] = float(payload.detection_rate_min)
        if payload.alert_enabled is not None:
            cur['alert_enabled'] = bool(payload.alert_enabled)
        _alerts_config[tid][route] = cur
        _save_alerts_config()
        return {'status': 'ok', 'tenant_id': tid, 'route': route, 'config': cur}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/tenants', operation_id='metrics_list_tenants')
def list_tenants(state: PlatformState = Depends(get_platform_state)):
    """Return a simple list of known tenants observed in runtime state.
    This endpoint is lightweight and unauthenticated to support UI filters.
    """
    try:
        dbg = state.debug_state()
        tenants = dbg.get('tenants', []) or []
        return {'tenants': tenants}
    except Exception as e:
        # Return empty list on error to avoid breaking UI
        try:
            return {'tenants': []}
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=str(e))
